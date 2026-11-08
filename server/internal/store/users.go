package store

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Console users, their sessions and API tokens. Passwords are PBKDF2-SHA256 hashed; session and API
// tokens are stored only as SHA-256 hashes, so a database copy does not leak usable credentials.

const usersSchema = `
CREATE TABLE IF NOT EXISTS console_user (
  username   TEXT PRIMARY KEY,
  role       TEXT NOT NULL,
  pw_hash    TEXT NOT NULL,
  disabled   INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_login INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS console_session (
  token_hash TEXT PRIMARY KEY,
  username   TEXT NOT NULL,
  kind       TEXT NOT NULL,           -- 'session' (login) or 'api' (long-lived token)
  name       TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_used  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_console_session_user ON console_session(username);
`

const (
	RoleViewer   = "viewer"
	RoleOperator = "operator"
	RoleAdmin    = "admin"

	pbkdf2Iterations  = 600_000 // OWASP 2023 recommendation for PBKDF2-HMAC-SHA256
	MinPasswordLength = 12
)

var ErrConflict = errors.New("already exists")

// RoleRank orders roles; unknown roles rank 0 (no access).
func RoleRank(role string) int {
	switch role {
	case RoleViewer:
		return 1
	case RoleOperator:
		return 2
	case RoleAdmin:
		return 3
	}
	return 0
}

type User struct {
	Username  string `json:"username"`
	Role      string `json:"role"`
	Disabled  bool   `json:"disabled"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
	LastLogin int64  `json:"last_login"`
	pwHash    string
}

// HashPassword returns "pbkdf2-sha256$<iterations>$<salt>$<hash>" (base64, no padding).
func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, 32)
	if err != nil {
		return "", err
	}
	enc := base64.RawStdEncoding
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdf2Iterations, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

// CheckPassword verifies a password against a stored hash in constant time.
func CheckPassword(stored, password string) bool {
	p := strings.Split(stored, "$")
	if len(p) != 4 || p[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(p[1])
	if err != nil || iter < 1000 {
		return false
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(p[2])
	want, err2 := enc.DecodeString(p[3])
	if err1 != nil || err2 != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}

// ValidatePassword enforces the minimum password policy.
func ValidatePassword(password string) error {
	if len([]rune(password)) < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	return nil
}

func validUsername(u string) bool {
	if len(u) < 2 || len(u) > 64 {
		return false
	}
	for _, c := range u {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._-@", c)) {
			return false
		}
	}
	return true
}

func (s *Store) CreateUser(username, role, password string) error {
	if !validUsername(username) {
		return fmt.Errorf("username must be 2-64 characters of letters, digits and . _ - @")
	}
	if RoleRank(role) == 0 {
		return fmt.Errorf("role must be viewer, operator or admin")
	}
	if err := ValidatePassword(password); err != nil {
		return err
	}
	h, err := HashPassword(password)
	if err != nil {
		return err
	}
	ts := now()
	_, err = s.db.Exec(`INSERT INTO console_user(username, role, pw_hash, created_at, updated_at) VALUES(?,?,?,?,?)`, username, role, h, ts, ts)
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return ErrConflict
	}
	return err
}

const userCols = `username, role, pw_hash, disabled, created_at, updated_at, last_login`

func scanUser(r interface{ Scan(...any) error }) (*User, error) {
	u := &User{}
	var disabled int
	err := r.Scan(&u.Username, &u.Role, &u.pwHash, &disabled, &u.CreatedAt, &u.UpdatedAt, &u.LastLogin)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	u.Disabled = disabled != 0
	return u, err
}

func (s *Store) GetUser(username string) (*User, error) {
	return scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM console_user WHERE username = ?`, username))
}

func (s *Store) ListUsers() ([]*User, error) {
	rows, err := s.db.Query(`SELECT ` + userCols + ` FROM console_user ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM console_user`).Scan(&n)
	return n, err
}

// countActiveAdmins excludes one user (the one being changed) from the count.
func (s *Store) countActiveAdmins(except string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM console_user WHERE role = 'admin' AND disabled = 0 AND username <> ?`, except).Scan(&n)
	return n, err
}

var ErrLastAdmin = errors.New("at least one enabled admin must remain")

// Authenticate checks credentials; it returns ErrNotFound for unknown users and wrong passwords alike.
func (s *Store) Authenticate(username, password string) (*User, error) {
	u, err := s.GetUser(username)
	if errors.Is(err, ErrNotFound) {
		CheckPassword("pbkdf2-sha256$600000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", password) // equalise timing
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !CheckPassword(u.pwHash, password) || u.Disabled {
		return nil, ErrNotFound
	}
	_, _ = s.db.Exec(`UPDATE console_user SET last_login = ? WHERE username = ?`, now(), username)
	return u, nil
}

// UpdateUser changes role, disabled flag and/or password (nil = unchanged). Demoting or disabling the last
// enabled admin is refused. Disabling a user or changing the password revokes their login sessions.
func (s *Store) UpdateUser(username string, role *string, disabled *bool, password *string) error {
	u, err := s.GetUser(username)
	if err != nil {
		return err
	}
	if role != nil && RoleRank(*role) == 0 {
		return fmt.Errorf("role must be viewer, operator or admin")
	}
	losesAdmin := u.Role == RoleAdmin && !u.Disabled && ((role != nil && *role != RoleAdmin) || (disabled != nil && *disabled))
	if losesAdmin {
		if n, err := s.countActiveAdmins(username); err != nil {
			return err
		} else if n == 0 {
			return ErrLastAdmin
		}
	}
	sets, args := []string{"updated_at = ?"}, []any{now()}
	if role != nil {
		sets, args = append(sets, "role = ?"), append(args, *role)
	}
	if disabled != nil {
		d := 0
		if *disabled {
			d = 1
		}
		sets, args = append(sets, "disabled = ?"), append(args, d)
	}
	if password != nil {
		if err := ValidatePassword(*password); err != nil {
			return err
		}
		h, err := HashPassword(*password)
		if err != nil {
			return err
		}
		sets, args = append(sets, "pw_hash = ?"), append(args, h)
	}
	if _, err := s.db.Exec(`UPDATE console_user SET `+strings.Join(sets, ", ")+` WHERE username = ?`, append(args, username)...); err != nil {
		return err
	}
	if password != nil || (disabled != nil && *disabled) {
		_, err = s.db.Exec(`DELETE FROM console_session WHERE username = ? AND kind = 'session'`, username)
	}
	return err
}

func (s *Store) DeleteUser(username string) error {
	u, err := s.GetUser(username)
	if err != nil {
		return err
	}
	if u.Role == RoleAdmin && !u.Disabled {
		if n, err := s.countActiveAdmins(username); err != nil {
			return err
		} else if n == 0 {
			return ErrLastAdmin
		}
	}
	if _, err := s.db.Exec(`DELETE FROM console_session WHERE username = ?`, username); err != nil {
		return err
	}
	_, err = s.db.Exec(`DELETE FROM console_user WHERE username = ?`, username)
	return err
}

// ------------------------------------------------------------------ sessions & API tokens

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// TokenInfo describes a session or API token (never the token itself).
type TokenInfo struct {
	ID        string `json:"id"` // first 12 hex chars of the token hash
	Username  string `json:"username"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
	LastUsed  int64  `json:"last_used"`
}

// IssueToken creates a session ("session") or API token ("api") and returns the clear-text token once.
func (s *Store) IssueToken(username, kind, name string, ttlMillis int64) (string, error) {
	prefix := "rs_"
	if kind == "api" {
		prefix = "rat_" // recognisable in logs / secret scanners
	}
	token := prefix + RandomHex(32)
	ts := now()
	_, err := s.db.Exec(`INSERT INTO console_session(token_hash, username, kind, name, created_at, expires_at, last_used) VALUES(?,?,?,?,?,?,?)`,
		hashToken(token), username, kind, name, ts, ts+ttlMillis, ts)
	return token, err
}

// Principal is the authenticated caller of a console request.
type Principal struct {
	Username string
	Role     string
	Kind     string
}

// ResolveToken returns the principal for a token, or ErrNotFound if it is unknown, expired, or its user
// is disabled/deleted. last_used is refreshed at most once a minute.
func (s *Store) ResolveToken(token string) (*Principal, error) {
	if token == "" {
		return nil, ErrNotFound
	}
	h := hashToken(token)
	var p Principal
	var expires, lastUsed int64
	var disabled int
	err := s.db.QueryRow(`SELECT s.username, u.role, s.kind, s.expires_at, s.last_used, u.disabled
		FROM console_session s JOIN console_user u ON u.username = s.username WHERE s.token_hash = ?`, h).
		Scan(&p.Username, &p.Role, &p.Kind, &expires, &lastUsed, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	ts := now()
	if expires <= ts || disabled != 0 {
		return nil, ErrNotFound
	}
	if ts-lastUsed > 60_000 {
		_, _ = s.db.Exec(`UPDATE console_session SET last_used = ? WHERE token_hash = ?`, ts, h)
	}
	return &p, nil
}

func (s *Store) RevokeToken(token string) error {
	_, err := s.db.Exec(`DELETE FROM console_session WHERE token_hash = ?`, hashToken(token))
	return err
}

// RevokeTokenID deletes an API token by its id; owner "" means any owner (admin).
func (s *Store) RevokeTokenID(id, owner string) error {
	if len(id) != 12 {
		return ErrNotFound
	}
	q, args := `DELETE FROM console_session WHERE kind = 'api' AND substr(token_hash, 1, 12) = ?`, []any{id}
	if owner != "" {
		q, args = q+` AND username = ?`, append(args, owner)
	}
	res, err := s.db.Exec(q, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListTokens lists API tokens; owner "" lists everyone's.
func (s *Store) ListTokens(owner string) ([]*TokenInfo, error) {
	q, args := `SELECT substr(token_hash, 1, 12), username, kind, name, created_at, expires_at, last_used FROM console_session WHERE kind = 'api'`, []any{}
	if owner != "" {
		q, args = q+` AND username = ?`, append(args, owner)
	}
	rows, err := s.db.Query(q+` ORDER BY created_at DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*TokenInfo{}
	for rows.Next() {
		t := &TokenInfo{}
		if err := rows.Scan(&t.ID, &t.Username, &t.Kind, &t.Name, &t.CreatedAt, &t.ExpiresAt, &t.LastUsed); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// PurgeExpiredTokens removes expired sessions and API tokens.
func (s *Store) PurgeExpiredTokens() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM console_session WHERE expires_at <= ?`, now())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
