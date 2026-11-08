// Package store persists apps, agent instances, policies, whitelists, alarms and audit logs.
//
// The MVP uses SQLite (pure Go, no CGO) so the server is a single binary. The schema follows
// docs chapter 6.4; at scale, configuration moves to MySQL and alarms to ClickHouse.
package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("not found")

type Store struct {
	db *sql.DB
	// OnAudit, if set, receives every audit record after it is stored (e.g. SIEM forwarding).
	OnAudit func(Audit)
}

const schema = `
CREATE TABLE IF NOT EXISTS app (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT NOT NULL,
  env         TEXT NOT NULL DEFAULT 'prod',
  language    TEXT NOT NULL DEFAULT 'java',
  owner       TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  app_key     TEXT NOT NULL UNIQUE,
  app_secret  TEXT NOT NULL,
  policy      TEXT NOT NULL,
  policy_rev  INTEGER NOT NULL DEFAULT 1,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL,
  UNIQUE(name, env)
);
CREATE TABLE IF NOT EXISTS agent_instance (
  agent_id       TEXT PRIMARY KEY,
  app_id         INTEGER NOT NULL,
  hostname       TEXT, ips TEXT, pid INTEGER,
  agent_version  TEXT, language TEXT, runtime TEXT, server_type TEXT, os TEXT, start_mode TEXT,
  config_version TEXT NOT NULL DEFAULT '',
  metrics        TEXT NOT NULL DEFAULT '{}',
  registered_at  INTEGER NOT NULL,
  last_heartbeat INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_instance_app ON agent_instance(app_id);
CREATE TABLE IF NOT EXISTS whitelist (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id      INTEGER NOT NULL DEFAULT 0,
  url         TEXT NOT NULL,
  match_type  TEXT NOT NULL DEFAULT 'prefix',
  types       TEXT NOT NULL DEFAULT 'all',
  note        TEXT NOT NULL DEFAULT '',
  created_by  TEXT NOT NULL DEFAULT '',
  created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS alarm (
  event_id      TEXT PRIMARY KEY,
  app_id        INTEGER NOT NULL,
  agent_id      TEXT NOT NULL,
  hostname      TEXT NOT NULL DEFAULT '',
  event_time    INTEGER NOT NULL,
  received_at   INTEGER NOT NULL,
  attack_type   TEXT NOT NULL,
  algorithm     TEXT NOT NULL DEFAULT '',
  action        TEXT NOT NULL,
  confidence    INTEGER NOT NULL DEFAULT 0,
  url           TEXT NOT NULL DEFAULT '',
  client_ip     TEXT NOT NULL DEFAULT '',
  reason        TEXT NOT NULL DEFAULT '',
  matched_input TEXT NOT NULL DEFAULT '',
  raw           TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'new'
);
CREATE INDEX IF NOT EXISTS idx_alarm_time ON alarm(event_time);
CREATE INDEX IF NOT EXISTS idx_alarm_app ON alarm(app_id, event_time);
CREATE INDEX IF NOT EXISTS idx_alarm_type_action ON alarm(attack_type, action, event_time);
CREATE INDEX IF NOT EXISTS idx_alarm_status ON alarm(status, event_time);
CREATE INDEX IF NOT EXISTS idx_alarm_ip ON alarm(client_ip, event_time);
-- Hourly counts maintained on insert; dashboards read these instead of scanning raw alarms.
CREATE TABLE IF NOT EXISTS alarm_rollup (
  hour        INTEGER NOT NULL,           -- event_time / 3600000
  app_id      INTEGER NOT NULL,
  attack_type TEXT NOT NULL,
  action      TEXT NOT NULL,
  client_ip   TEXT NOT NULL,
  n           INTEGER NOT NULL,
  PRIMARY KEY (hour, app_id, attack_type, action, client_ip)
);
CREATE TABLE IF NOT EXISTS component (
  agent_id   TEXT NOT NULL,
  app_id     INTEGER NOT NULL,
  group_id   TEXT NOT NULL DEFAULT '',
  artifact   TEXT NOT NULL,
  version    TEXT NOT NULL DEFAULT '',
  file       TEXT NOT NULL DEFAULT '',
  path       TEXT NOT NULL,
  sha1       TEXT NOT NULL DEFAULT '',
  source     TEXT NOT NULL DEFAULT '',
  reported_at INTEGER NOT NULL,
  PRIMARY KEY (agent_id, path, artifact)
);
CREATE INDEX IF NOT EXISTS idx_component_ga ON component(artifact, version);
CREATE INDEX IF NOT EXISTS idx_component_app ON component(app_id);
CREATE TABLE IF NOT EXISTS setting (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, user TEXT NOT NULL,
  action TEXT NOT NULL, target TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT ''
);
`

// Full-text index for alarm keyword search (trigram: substring semantics like LIKE '%kw%' for 3+ chars),
// kept in sync with the alarm table by triggers.
const ftsSchema = `
CREATE VIRTUAL TABLE IF NOT EXISTS alarm_fts USING fts5(url, client_ip, hostname, matched_input,
  content='alarm', content_rowid='rowid', tokenize='trigram');
CREATE TRIGGER IF NOT EXISTS alarm_fts_ai AFTER INSERT ON alarm BEGIN
  INSERT INTO alarm_fts(rowid, url, client_ip, hostname, matched_input) VALUES (new.rowid, new.url, new.client_ip, new.hostname, new.matched_input);
END;
CREATE TRIGGER IF NOT EXISTS alarm_fts_ad AFTER DELETE ON alarm BEGIN
  INSERT INTO alarm_fts(alarm_fts, rowid, url, client_ip, hostname, matched_input) VALUES ('delete', old.rowid, old.url, old.client_ip, old.hostname, old.matched_input);
END;
CREATE TRIGGER IF NOT EXISTS alarm_fts_au AFTER UPDATE OF url, client_ip, hostname, matched_input ON alarm BEGIN
  INSERT INTO alarm_fts(alarm_fts, rowid, url, client_ip, hostname, matched_input) VALUES ('delete', old.rowid, old.url, old.client_ip, old.hostname, old.matched_input);
  INSERT INTO alarm_fts(rowid, url, client_ip, hostname, matched_input) VALUES (new.rowid, new.url, new.client_ip, new.hostname, new.matched_input);
END;
`

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite: serialise writers
	for _, ddl := range []string{schema, vulnSchema, usersSchema, ftsSchema, incidentSchema} {
		if _, err := db.Exec(ddl); err != nil {
			return nil, fmt.Errorf("init schema: %w", err)
		}
	}
	st := &Store{db: db}
	if err := st.ensureAlarmFingerprintColumn(); err != nil {
		return nil, fmt.Errorf("alarm fingerprint migration: %w", err)
	}
	if err := st.backfillRollup(); err != nil {
		return nil, fmt.Errorf("alarm rollup migration: %w", err)
	}
	if st.GetSetting("alarm_fts_v1", "") != "done" { // index alarms stored before the FTS table existed
		if _, err := db.Exec(`INSERT INTO alarm_fts(alarm_fts) VALUES('rebuild')`); err != nil {
			return nil, fmt.Errorf("alarm search index migration: %w", err)
		}
		if err := st.SetSetting("alarm_fts_v1", "done"); err != nil {
			return nil, err
		}
	}
	return st, nil
}

// backfillRollup builds alarm_rollup once for databases created before it existed.
func (s *Store) backfillRollup() error {
	if s.GetSetting("alarm_rollup_v1", "") == "done" {
		return nil
	}
	if _, err := s.db.Exec(`INSERT OR REPLACE INTO alarm_rollup(hour, app_id, attack_type, action, client_ip, n)
		SELECT event_time / 3600000, app_id, attack_type, action, client_ip, COUNT(*) FROM alarm GROUP BY 1, 2, 3, 4, 5`); err != nil {
		return err
	}
	return s.SetSetting("alarm_rollup_v1", "done")
}

func (s *Store) Close() error { return s.db.Close() }

func now() int64 { return time.Now().UnixMilli() }

func RandomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// ------------------------------------------------------------------ apps

type App struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Env         string `json:"env"`
	Language    string `json:"language"`
	Owner       string `json:"owner"`
	Description string `json:"description"`
	AppKey      string `json:"app_key"`
	AppSecret   string `json:"app_secret,omitempty"`
	Policy      string `json:"-"`
	PolicyRev   int64  `json:"policy_rev"`
	CreatedAt   int64  `json:"created_at"`
	UpdatedAt   int64  `json:"updated_at"`
	Online      int    `json:"online"`
	Total       int    `json:"total"`
}

const appCols = `id, name, env, language, owner, description, app_key, app_secret, policy, policy_rev, created_at, updated_at`

func scanApp(r interface{ Scan(...any) error }) (*App, error) {
	a := &App{}
	err := r.Scan(&a.ID, &a.Name, &a.Env, &a.Language, &a.Owner, &a.Description, &a.AppKey, &a.AppSecret,
		&a.Policy, &a.PolicyRev, &a.CreatedAt, &a.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

func (s *Store) CreateApp(a *App) error {
	a.AppKey = RandomHex(16)
	a.AppSecret = RandomHex(32)
	a.CreatedAt, a.UpdatedAt = now(), now()
	a.PolicyRev = 1
	res, err := s.db.Exec(`INSERT INTO app(name, env, language, owner, description, app_key, app_secret, policy, policy_rev, created_at, updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`, a.Name, a.Env, a.Language, a.Owner, a.Description, a.AppKey, a.AppSecret,
		a.Policy, a.PolicyRev, a.CreatedAt, a.UpdatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return fmt.Errorf("app %s/%s already exists", a.Name, a.Env)
		}
		return err
	}
	a.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) ListApps(onlineSince int64) ([]*App, error) {
	rows, err := s.db.Query(`SELECT ` + appCols + ` FROM app ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*App
	for rows.Next() {
		a, err := scanApp(rows)
		if err != nil {
			return nil, err
		}
		a.AppSecret = ""
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, a := range out {
		_ = s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(CASE WHEN last_heartbeat >= ? THEN 1 ELSE 0 END),0)
			FROM agent_instance WHERE app_id = ?`, onlineSince, a.ID).Scan(&a.Total, &a.Online)
	}
	return out, nil
}

func (s *Store) GetApp(id int64) (*App, error) {
	return scanApp(s.db.QueryRow(`SELECT `+appCols+` FROM app WHERE id = ?`, id))
}

func (s *Store) GetAppByKey(key string) (*App, error) {
	return scanApp(s.db.QueryRow(`SELECT `+appCols+` FROM app WHERE app_key = ?`, key))
}

func (s *Store) UpdateAppPolicy(id int64, policy string) error {
	res, err := s.db.Exec(`UPDATE app SET policy = ?, policy_rev = policy_rev + 1, updated_at = ? WHERE id = ?`, policy, now(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteApp(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{`DELETE FROM component WHERE app_id = ?`, `DELETE FROM agent_instance WHERE app_id = ?`,
		`DELETE FROM whitelist WHERE app_id = ?`, `DELETE FROM app WHERE id = ?`} {
		if _, err := tx.Exec(q, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ------------------------------------------------------------------ instances

type Instance struct {
	AgentID       string `json:"agent_id"`
	AppID         int64  `json:"app_id"`
	AppName       string `json:"app_name"`
	Hostname      string `json:"hostname"`
	IPs           string `json:"ips"`
	PID           int64  `json:"pid"`
	AgentVersion  string `json:"agent_version"`
	Language      string `json:"language"`
	Runtime       string `json:"runtime"`
	ServerType    string `json:"server_type"`
	OS            string `json:"os"`
	StartMode     string `json:"start_mode"`
	ConfigVersion string `json:"config_version"`
	Metrics       string `json:"metrics"`
	RegisteredAt  int64  `json:"registered_at"`
	LastHeartbeat int64  `json:"last_heartbeat"`
	Online        bool   `json:"online"`
}

func (s *Store) UpsertInstance(i *Instance) error {
	i.RegisteredAt, i.LastHeartbeat = now(), now()
	_, err := s.db.Exec(`INSERT INTO agent_instance(agent_id, app_id, hostname, ips, pid, agent_version, language, runtime,
		server_type, os, start_mode, registered_at, last_heartbeat) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(agent_id) DO UPDATE SET app_id=excluded.app_id, hostname=excluded.hostname, ips=excluded.ips,
		pid=excluded.pid, agent_version=excluded.agent_version, runtime=excluded.runtime, server_type=excluded.server_type,
		os=excluded.os, start_mode=excluded.start_mode, last_heartbeat=excluded.last_heartbeat`,
		i.AgentID, i.AppID, i.Hostname, i.IPs, i.PID, i.AgentVersion, i.Language, i.Runtime, i.ServerType, i.OS,
		i.StartMode, i.RegisteredAt, i.LastHeartbeat)
	return err
}

// Heartbeat returns ErrNotFound when the agent is unknown or belongs to another app.
func (s *Store) Heartbeat(agentID string, appID int64, configVersion, metrics string) error {
	res, err := s.db.Exec(`UPDATE agent_instance SET last_heartbeat = ?, config_version = ?, metrics = ?
		WHERE agent_id = ? AND app_id = ?`, now(), configVersion, metrics, agentID, appID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) InstanceBelongsTo(agentID string, appID int64) bool {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM agent_instance WHERE agent_id = ? AND app_id = ?`, agentID, appID).Scan(&n)
	return n > 0
}

func (s *Store) ListInstances(appID int64, onlineSince int64) ([]*Instance, error) {
	q := `SELECT i.agent_id, i.app_id, a.name, COALESCE(i.hostname,''), COALESCE(i.ips,''), COALESCE(i.pid,0),
		COALESCE(i.agent_version,''), COALESCE(i.language,''), COALESCE(i.runtime,''), COALESCE(i.server_type,''),
		COALESCE(i.os,''), COALESCE(i.start_mode,''), i.config_version, i.metrics, i.registered_at, i.last_heartbeat
		FROM agent_instance i JOIN app a ON a.id = i.app_id`
	var args []any
	if appID > 0 {
		q += ` WHERE i.app_id = ?`
		args = append(args, appID)
	}
	q += ` ORDER BY i.last_heartbeat DESC LIMIT 1000`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Instance
	for rows.Next() {
		i := &Instance{}
		if err := rows.Scan(&i.AgentID, &i.AppID, &i.AppName, &i.Hostname, &i.IPs, &i.PID, &i.AgentVersion, &i.Language,
			&i.Runtime, &i.ServerType, &i.OS, &i.StartMode, &i.ConfigVersion, &i.Metrics, &i.RegisteredAt, &i.LastHeartbeat); err != nil {
			return nil, err
		}
		i.Online = i.LastHeartbeat >= onlineSince
		out = append(out, i)
	}
	return out, rows.Err()
}

// PurgeInstances removes instances that have been offline longer than the given age.
func (s *Store) PurgeInstances(olderThan time.Duration) (int64, error) {
	limit := time.Now().Add(-olderThan).UnixMilli()
	if _, err := s.db.Exec(`DELETE FROM component WHERE agent_id IN (SELECT agent_id FROM agent_instance WHERE last_heartbeat < ?)`, limit); err != nil {
		return 0, err
	}
	res, err := s.db.Exec(`DELETE FROM agent_instance WHERE last_heartbeat < ?`, limit)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ------------------------------------------------------------------ components (SCA)

type Component struct {
	Group    string `json:"group"`
	Artifact string `json:"artifact"`
	Version  string `json:"version"`
	File     string `json:"file"`
	Path     string `json:"path"`
	SHA1     string `json:"sha1"`
	Source   string `json:"source"`
}

// ReplaceComponents stores the full inventory reported by one agent.
func (s *Store) ReplaceComponents(agentID string, appID int64, items []Component) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM component WHERE agent_id = ?`, agentID); err != nil {
		return err
	}
	st, err := tx.Prepare(`INSERT OR IGNORE INTO component(agent_id, app_id, group_id, artifact, version, file, path, sha1, source, reported_at)
		VALUES(?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer st.Close()
	ts := now()
	for _, c := range items {
		if _, err := st.Exec(agentID, appID, c.Group, c.Artifact, c.Version, c.File, c.Path, c.SHA1, c.Source, ts); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ComponentSummary is one group:artifact:version across the fleet.
type ComponentSummary struct {
	Group     string `json:"group"`
	Artifact  string `json:"artifact"`
	Version   string `json:"version"`
	Source    string `json:"source"`
	SHA1      string `json:"sha1"`
	Apps      string `json:"apps"`
	Instances int64  `json:"instances"`
	Vulns     int64  `json:"vulns"`        // advisories affecting this version
	Severity  string `json:"max_severity"` // worst of them, "" when none
}

func (s *Store) QueryComponents(appID int64, keyword string, limit int) ([]*ComponentSummary, error) {
	where := []string{"1=1"}
	var args []any
	if appID > 0 {
		where, args = append(where, "c.app_id = ?"), append(args, appID)
	}
	if keyword != "" {
		kw := "%" + keyword + "%"
		where, args = append(where, "(c.artifact LIKE ? OR c.group_id LIKE ? OR c.file LIKE ? OR c.version LIKE ?)"), append(args, kw, kw, kw, kw)
	}
	if limit <= 0 || limit > 5000 {
		limit = 2000
	}
	rows, err := s.db.Query(`SELECT c.group_id, c.artifact, c.version, MIN(c.source), MIN(c.sha1),
		GROUP_CONCAT(DISTINCT a.name || '/' || a.env), COUNT(DISTINCT c.agent_id),
		COALESCE(MAX(vs.n), 0), COALESCE(MAX(vs.worst), '')
		FROM component c JOIN app a ON a.id = c.app_id
		LEFT JOIN (SELECT cv.group_id, cv.artifact, cv.version, COUNT(*) AS n,
			CASE MAX(`+severityRank+`) WHEN 5 THEN 'critical' WHEN 4 THEN 'high' WHEN 3 THEN 'medium' WHEN 2 THEN 'low' WHEN 1 THEN 'none' ELSE 'unknown' END AS worst
			FROM component_vuln cv JOIN vuln v ON v.id = cv.vuln_id GROUP BY cv.group_id, cv.artifact, cv.version) vs
			ON vs.group_id = c.group_id AND vs.artifact = c.artifact AND vs.version = c.version
		WHERE `+strings.Join(where, " AND ")+`
		GROUP BY c.group_id, c.artifact, c.version ORDER BY c.artifact, c.version LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ComponentSummary
	for rows.Next() {
		c := &ComponentSummary{}
		if err := rows.Scan(&c.Group, &c.Artifact, &c.Version, &c.Source, &c.SHA1, &c.Apps, &c.Instances, &c.Vulns, &c.Severity); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ComponentInstances lists where one component version is loaded.
type ComponentUse struct {
	AppName  string `json:"app_name"`
	Env      string `json:"env"`
	AgentID  string `json:"agent_id"`
	Hostname string `json:"hostname"`
	Path     string `json:"path"`
}

func (s *Store) ComponentUses(group, artifact, version string) ([]*ComponentUse, error) {
	rows, err := s.db.Query(`SELECT a.name, a.env, c.agent_id, COALESCE(i.hostname,''), c.path
		FROM component c JOIN app a ON a.id = c.app_id LEFT JOIN agent_instance i ON i.agent_id = c.agent_id
		WHERE c.group_id = ? AND c.artifact = ? AND c.version = ? ORDER BY a.name LIMIT 1000`, group, artifact, version)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ComponentUse
	for rows.Next() {
		u := &ComponentUse{}
		if err := rows.Scan(&u.AppName, &u.Env, &u.AgentID, &u.Hostname, &u.Path); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// ------------------------------------------------------------------ whitelist

type Whitelist struct {
	ID        int64  `json:"id"`
	AppID     int64  `json:"app_id"`
	URL       string `json:"url"`
	Match     string `json:"match"`
	Types     string `json:"types"`
	Note      string `json:"note"`
	CreatedBy string `json:"created_by"`
	CreatedAt int64  `json:"created_at"`
}

func (s *Store) AddWhitelist(w *Whitelist) error {
	w.CreatedAt = now()
	res, err := s.db.Exec(`INSERT INTO whitelist(app_id, url, match_type, types, note, created_by, created_at) VALUES(?,?,?,?,?,?,?)`,
		w.AppID, w.URL, w.Match, w.Types, w.Note, w.CreatedBy, w.CreatedAt)
	if err != nil {
		return err
	}
	w.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) DeleteWhitelist(id int64) error {
	_, err := s.db.Exec(`DELETE FROM whitelist WHERE id = ?`, id)
	return err
}

// ListWhitelist returns entries for an app plus global entries (app_id = 0). appID < 0 lists all.
func (s *Store) ListWhitelist(appID int64) ([]*Whitelist, error) {
	q := `SELECT id, app_id, url, match_type, types, note, created_by, created_at FROM whitelist`
	var args []any
	if appID >= 0 {
		q += ` WHERE app_id = ? OR app_id = 0`
		args = append(args, appID)
	}
	rows, err := s.db.Query(q+` ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Whitelist
	for rows.Next() {
		w := &Whitelist{}
		if err := rows.Scan(&w.ID, &w.AppID, &w.URL, &w.Match, &w.Types, &w.Note, &w.CreatedBy, &w.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// ------------------------------------------------------------------ alarms

type Alarm struct {
	EventID      string `json:"event_id"`
	AppID        int64  `json:"app_id"`
	AppName      string `json:"app_name"`
	AgentID      string `json:"agent_id"`
	Hostname     string `json:"hostname"`
	EventTime    int64  `json:"event_time"`
	ReceivedAt   int64  `json:"received_at"`
	AttackType   string `json:"attack_type"`
	Algorithm    string `json:"algorithm"`
	Action       string `json:"action"`
	Confidence   int64  `json:"confidence"`
	URL          string `json:"url"`
	ClientIP     string `json:"client_ip"`
	Reason       string `json:"reason"`
	MatchedInput string `json:"matched_input"`
	Raw          string `json:"raw,omitempty"`
	Status       string `json:"status"`
	Fingerprint  string `json:"fingerprint"` // incident key, see incident.go
}

func (s *Store) InsertAlarms(as []*Alarm) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	st, err := tx.Prepare(`INSERT OR IGNORE INTO alarm(event_id, app_id, agent_id, hostname, event_time, received_at, attack_type,
		algorithm, action, confidence, url, client_ip, reason, matched_input, raw, fingerprint) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer st.Close()
	type rollKey struct {
		hour, app             int64
		typ, action, clientIP string
	}
	roll := map[rollKey]int64{}
	incidents := map[string]*incidentDelta{}
	for _, a := range as {
		a.ReceivedAt = now()
		fp, pattern := Fingerprint(a.AppID, a.AttackType, a.Algorithm, a.URL)
		a.Fingerprint = fp
		res, err := st.Exec(a.EventID, a.AppID, a.AgentID, a.Hostname, a.EventTime, a.ReceivedAt, a.AttackType, a.Algorithm,
			a.Action, a.Confidence, a.URL, a.ClientIP, a.Reason, a.MatchedInput, a.Raw, fp)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 1 { // duplicates (agent retries) are not counted twice
			roll[rollKey{a.EventTime / 3600000, a.AppID, a.AttackType, a.Action, a.ClientIP}]++
			d := incidents[fp]
			if d == nil {
				d = &incidentDelta{appID: a.AppID, typ: a.AttackType, algorithm: a.Algorithm, pattern: pattern}
				incidents[fp] = d
			}
			d.add(a)
		}
	}
	if err := upsertIncidents(tx, incidents); err != nil {
		return err
	}
	for k, n := range roll {
		if _, err := tx.Exec(`INSERT INTO alarm_rollup(hour, app_id, attack_type, action, client_ip, n) VALUES(?,?,?,?,?,?)
			ON CONFLICT(hour, app_id, attack_type, action, client_ip) DO UPDATE SET n = n + excluded.n`,
			k.hour, k.app, k.typ, k.action, k.clientIP, n); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type AlarmQuery struct {
	AppID       int64
	AttackType  string
	Action      string
	Status      string
	Keyword     string
	Since       int64
	Fingerprint string // alarms of one incident
	Page        int
	PageSize    int
}

func (s *Store) QueryAlarms(q AlarmQuery) ([]*Alarm, int, error) {
	where := []string{"1=1"}
	var args []any
	if q.AppID > 0 {
		where, args = append(where, "a.app_id = ?"), append(args, q.AppID)
	}
	if q.AttackType != "" {
		where, args = append(where, "a.attack_type = ?"), append(args, q.AttackType)
	}
	if q.Action != "" {
		where, args = append(where, "a.action = ?"), append(args, q.Action)
	}
	if q.Status != "" {
		where, args = append(where, "a.status = ?"), append(args, q.Status)
	}
	if q.Since > 0 {
		where, args = append(where, "a.event_time >= ?"), append(args, q.Since)
	}
	if q.Fingerprint != "" {
		where, args = append(where, "a.fingerprint = ?"), append(args, q.Fingerprint)
	}
	if kw := strings.TrimSpace(q.Keyword); kw != "" {
		if utf8.RuneCountInString(kw) >= 3 {
			// trigram index; the keyword is quoted as one phrase so FTS syntax in user input has no effect
			where = append(where, "a.rowid IN (SELECT rowid FROM alarm_fts WHERE alarm_fts MATCH ?)")
			args = append(args, `"`+strings.ReplaceAll(kw, `"`, `""`)+`"`)
		} else { // trigrams need 3 characters: short keywords scan
			like := "%" + kw + "%"
			where, args = append(where, "(a.url LIKE ? OR a.client_ip LIKE ? OR a.hostname LIKE ? OR a.matched_input LIKE ?)"),
				append(args, like, like, like, like)
		}
	}
	cond := strings.Join(where, " AND ")
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM alarm a WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if q.PageSize <= 0 || q.PageSize > 200 {
		q.PageSize = 20
	}
	if q.Page <= 0 {
		q.Page = 1
	}
	rows, err := s.db.Query(`SELECT a.event_id, a.app_id, COALESCE(p.name,''), a.agent_id, a.hostname, a.event_time, a.received_at,
		a.attack_type, a.algorithm, a.action, a.confidence, a.url, a.client_ip, a.reason, a.matched_input, a.status, a.fingerprint
		FROM alarm a LEFT JOIN app p ON p.id = a.app_id WHERE `+cond+` ORDER BY a.event_time DESC LIMIT ? OFFSET ?`,
		append(args, q.PageSize, (q.Page-1)*q.PageSize)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*Alarm
	for rows.Next() {
		a := &Alarm{}
		if err := rows.Scan(&a.EventID, &a.AppID, &a.AppName, &a.AgentID, &a.Hostname, &a.EventTime, &a.ReceivedAt, &a.AttackType,
			&a.Algorithm, &a.Action, &a.Confidence, &a.URL, &a.ClientIP, &a.Reason, &a.MatchedInput, &a.Status, &a.Fingerprint); err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}

func (s *Store) GetAlarm(id string) (*Alarm, error) {
	a := &Alarm{}
	err := s.db.QueryRow(`SELECT a.event_id, a.app_id, COALESCE(p.name,''), a.agent_id, a.hostname, a.event_time, a.received_at,
		a.attack_type, a.algorithm, a.action, a.confidence, a.url, a.client_ip, a.reason, a.matched_input, a.raw, a.status, a.fingerprint
		FROM alarm a LEFT JOIN app p ON p.id = a.app_id WHERE a.event_id = ?`, id).Scan(&a.EventID, &a.AppID, &a.AppName,
		&a.AgentID, &a.Hostname, &a.EventTime, &a.ReceivedAt, &a.AttackType, &a.Algorithm, &a.Action, &a.Confidence, &a.URL,
		&a.ClientIP, &a.Reason, &a.MatchedInput, &a.Raw, &a.Status, &a.Fingerprint)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

func (s *Store) SetAlarmStatus(id, status string) error {
	res, err := s.db.Exec(`UPDATE alarm SET status = ? WHERE event_id = ?`, status, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) PurgeAlarms(olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan).UnixMilli()
	res, err := s.db.Exec(`DELETE FROM alarm WHERE event_time < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	if _, err := s.db.Exec(`DELETE FROM alarm_rollup WHERE hour < ?`, cutoff/3600000); err != nil {
		return 0, err
	}
	if err := s.purgeIncidents(cutoff); err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

type Count struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// AlarmStats aggregates alarms since the given time by a whitelisted column.
func (s *Store) AlarmStats(since int64, column string, limit int) ([]Count, error) {
	// Reads the hourly rollup (hour granularity: "since" is rounded down to the hour).
	cols := map[string]string{
		"attack_type": "r.attack_type", "action": "r.action", "client_ip": "r.client_ip", "app": "COALESCE(p.name,'')",
		"day": "strftime('%Y-%m-%d', r.hour * 3600, 'unixepoch', 'localtime')",
	}
	expr, ok := cols[column]
	if !ok {
		return nil, fmt.Errorf("bad stats column %q", column)
	}
	order := "SUM(r.n) DESC"
	if column == "day" {
		order = "k"
	}
	rows, err := s.db.Query(`SELECT `+expr+` AS k, SUM(r.n) FROM alarm_rollup r LEFT JOIN app p ON p.id = r.app_id
		WHERE r.hour >= ? GROUP BY k ORDER BY `+order+` LIMIT ?`, since/3600000, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Count
	for rows.Next() {
		var c Count
		if err := rows.Scan(&c.Key, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ------------------------------------------------------------------ settings & audit

func (s *Store) GetSetting(k, def string) string {
	var v string
	if err := s.db.QueryRow(`SELECT v FROM setting WHERE k = ?`, k).Scan(&v); err != nil {
		return def
	}
	return v
}

func (s *Store) SetSetting(k, v string) error {
	_, err := s.db.Exec(`INSERT INTO setting(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`, k, v)
	return err
}

type Audit struct {
	ID     int64  `json:"id"`
	At     int64  `json:"at"`
	User   string `json:"user"`
	Action string `json:"action"`
	Target string `json:"target"`
	Detail string `json:"detail"`
}

func (s *Store) AddAudit(user, action, target, detail string) {
	at := now()
	res, err := s.db.Exec(`INSERT INTO audit(at, user, action, target, detail) VALUES(?,?,?,?,?)`, at, user, action, target, detail)
	if err == nil && s.OnAudit != nil {
		id, _ := res.LastInsertId()
		s.OnAudit(Audit{ID: id, At: at, User: user, Action: action, Target: target, Detail: detail})
	}
}

func (s *Store) ListAudit(limit int) ([]*Audit, error) {
	rows, err := s.db.Query(`SELECT id, at, user, action, target, detail FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Audit
	for rows.Next() {
		a := &Audit{}
		if err := rows.Scan(&a.ID, &a.At, &a.User, &a.Action, &a.Target, &a.Detail); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Ping checks that the database answers (readiness probe).
func (s *Store) Ping() error {
	var one int
	return s.db.QueryRow(`SELECT 1`).Scan(&one)
}

// FleetCounts returns gauges for metrics: apps, instances (total/online), alarms in the last 24 hours.
func (s *Store) FleetCounts(onlineSince int64) (map[string]float64, error) {
	out := map[string]float64{}
	var apps, total, online, alarms int64
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM app`).Scan(&apps); err != nil {
		return nil, err
	}
	if err := s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(CASE WHEN last_heartbeat >= ? THEN 1 ELSE 0 END), 0) FROM agent_instance`, onlineSince).Scan(&total, &online); err != nil {
		return nil, err
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM alarm WHERE event_time >= ?`, now()-24*3600*1000).Scan(&alarms); err != nil {
		return nil, err
	}
	out["apps"], out["instances"], out["instances_online"], out["alarms_24h"] = float64(apps), float64(total), float64(online), float64(alarms)
	return out, nil
}

// Backup writes a consistent snapshot of the live database to path (SQLite VACUUM INTO; readers and
// writers continue meanwhile) and verifies it with an integrity check. path must not exist.
func (s *Store) Backup(path string) error {
	if _, err := s.db.Exec(`VACUUM INTO ?`, path); err != nil {
		return err
	}
	check, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer check.Close()
	var result string
	if err := check.QueryRow(`PRAGMA integrity_check`).Scan(&result); err != nil {
		return err
	}
	if result != "ok" {
		return fmt.Errorf("backup integrity check failed: %s", result)
	}
	return nil
}
