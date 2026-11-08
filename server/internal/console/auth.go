package console

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"zhuwei-rasp/server/internal/httpx"
	"zhuwei-rasp/server/internal/ldapauth"
	"zhuwei-rasp/server/internal/ops"
	"zhuwei-rasp/server/internal/store"
)

const (
	sessionTTL      = 12 * time.Hour
	maxTokenDays    = 366
	lockoutWindow   = 15 * time.Minute
	lockoutFailures = 10
)

// ------------------------------------------------------------------ login throttling

// limiter counts failed logins per key (client IP, and username) inside a sliding window.
type limiter struct {
	mu    sync.Mutex
	fails map[string][]time.Time
}

func newLimiter() *limiter { return &limiter{fails: map[string][]time.Time{}} }

func (l *limiter) recent(key string, now time.Time) []time.Time {
	var keep []time.Time
	for _, t := range l.fails[key] {
		if now.Sub(t) < lockoutWindow {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(l.fails, key)
	} else {
		l.fails[key] = keep
	}
	return keep
}

func (l *limiter) blocked(keys ...string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for _, k := range keys {
		if len(l.recent(k, now)) >= lockoutFailures {
			return true
		}
	}
	return false
}

func (l *limiter) fail(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for _, k := range keys {
		l.fails[k] = append(l.recent(k, now), now)
	}
	if len(l.fails) > 100_000 { // bounded memory under a distributed brute force
		l.fails = map[string][]time.Time{}
	}
}

func (l *limiter) reset(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		delete(l.fails, k)
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ------------------------------------------------------------------ middleware

// authed handlers receive the caller's username; the role check has already passed.
type authed func(w http.ResponseWriter, r *http.Request, user string)

type principalKey struct{}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(h[len("Bearer "):])
	}
	return ""
}

// auth requires a valid session or API token. Safe by default: GET/HEAD need viewer, every other
// method needs operator. Use authAs to grant a different minimum role explicitly.
func (a *API) auth(h authed) http.HandlerFunc { return a.authAs("", h) }

func (a *API) admin(h authed) http.HandlerFunc { return a.authAs(store.RoleAdmin, h) }

func (a *API) authAs(minRole string, h authed) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := a.st.ResolveToken(bearer(r))
		if err != nil {
			httpx.Fail(w, http.StatusUnauthorized, "login required")
			return
		}
		need := minRole
		if need == "" {
			need = store.RoleOperator
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				need = store.RoleViewer
			}
		}
		if store.RoleRank(p.Role) < store.RoleRank(need) {
			httpx.Fail(w, http.StatusForbidden, "permission denied: requires role "+need)
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)), p.Username)
	}
}

// principal returns the authenticated caller of r (inside an auth-wrapped handler).
func (a *API) principal(r *http.Request) *store.Principal {
	if p, ok := r.Context().Value(principalKey{}).(*store.Principal); ok {
		return p
	}
	return &store.Principal{}
}

// ------------------------------------------------------------------ login / logout / me

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	var req struct{ Username, Password string }
	if err := httpx.ReadJSON(r, 4096, &req); err != nil {
		httpx.Fail(w, http.StatusBadRequest, "invalid request")
		return
	}
	ip := clientIP(r)
	keys := []string{"ip:" + ip, "user:" + strings.ToLower(req.Username)}
	if a.limit.blocked(keys...) {
		httpx.Fail(w, http.StatusTooManyRequests, "too many failed logins, try again in 15 minutes")
		return
	}
	u, err := a.st.Authenticate(req.Username, req.Password)
	source := "local"
	if errors.Is(err, store.ErrNotFound) && a.LDAP.Enabled() && !a.st.IsLocalUser(req.Username) {
		// Local accounts win: the directory is only asked about names that have no local password.
		source = "ldap"
		var role string
		role, err = a.LDAP.Authenticate(req.Username, req.Password)
		switch {
		case err == nil:
			u, err = a.st.UpsertExternalUser(req.Username, role, "ldap")
		case errors.Is(err, ldapauth.ErrInvalidCredentials), errors.Is(err, ldapauth.ErrNoRole):
			// counted as a failed login below
		default:
			log.Printf("ldap login for %q: %v", req.Username, err)
			httpx.Fail(w, http.StatusServiceUnavailable, "directory service unavailable, try again later")
			return
		}
	}
	if err != nil {
		a.limit.fail(keys...)
		ops.LoginFailures.Inc("")
		detail := source
		if errors.Is(err, ldapauth.ErrNoRole) {
			detail = "ldap: no mapped group"
		} else if errors.Is(err, store.ErrDisabled) || errors.Is(err, store.ErrLocalAccount) {
			detail = source + ": " + err.Error()
		}
		a.st.AddAudit(req.Username, "login_failed", ip, detail)
		time.Sleep(300 * time.Millisecond)
		httpx.Fail(w, http.StatusUnauthorized, "wrong username or password")
		return
	}
	tok, err := a.st.IssueToken(u.Username, "session", "login "+ip, sessionTTL.Milliseconds())
	if err != nil {
		storeErr(w, err)
		return
	}
	a.limit.reset(keys...)
	a.st.AddAudit(u.Username, "login", ip, source)
	httpx.OK(w, map[string]string{"token": tok, "user": u.Username, "role": u.Role})
}

func (a *API) logout(w http.ResponseWriter, r *http.Request, user string) {
	if a.principal(r).Kind == "session" {
		_ = a.st.RevokeToken(bearer(r))
	}
	httpx.OK(w, nil)
}

func (a *API) me(w http.ResponseWriter, r *http.Request, user string) {
	p := a.principal(r)
	httpx.OK(w, map[string]string{"user": p.Username, "role": p.Role, "auth": p.Kind})
}

func (a *API) changeOwnPassword(w http.ResponseWriter, r *http.Request, user string) {
	var req struct {
		Old string `json:"old_password"`
		New string `json:"new_password"`
	}
	if err := httpx.ReadJSON(r, 4096, &req); err != nil {
		httpx.Fail(w, http.StatusBadRequest, "invalid request")
		return
	}
	if _, err := a.st.Authenticate(user, req.Old); err != nil {
		httpx.Fail(w, http.StatusBadRequest, "current password is wrong")
		return
	}
	if err := a.st.UpdateUser(user, nil, nil, &req.New); err != nil {
		userErr(w, err)
		return
	}
	a.st.AddAudit(user, "change_password", user, "")
	httpx.OK(w, nil) // all login sessions of the user are revoked, including this one
}

// ------------------------------------------------------------------ users (admin)

func userErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		httpx.Fail(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrConflict):
		httpx.Fail(w, http.StatusConflict, "user already exists")
	case errors.Is(err, store.ErrLastAdmin), errors.Is(err, store.ErrExternal):
		httpx.Fail(w, http.StatusConflict, err.Error())
	default:
		httpx.Fail(w, http.StatusBadRequest, err.Error())
	}
}

func (a *API) listUsers(w http.ResponseWriter, r *http.Request, _ string) {
	list, err := a.st.ListUsers()
	if err != nil {
		storeErr(w, err)
		return
	}
	httpx.OK(w, list)
}

func (a *API) createUser(w http.ResponseWriter, r *http.Request, user string) {
	var req struct{ Username, Role, Password string }
	if err := httpx.ReadJSON(r, 4096, &req); err != nil {
		httpx.Fail(w, http.StatusBadRequest, "invalid request")
		return
	}
	if err := a.st.CreateUser(req.Username, req.Role, req.Password); err != nil {
		userErr(w, err)
		return
	}
	a.st.AddAudit(user, "create_user", req.Username, "role="+req.Role)
	httpx.OK(w, nil)
}

func (a *API) updateUser(w http.ResponseWriter, r *http.Request, user string) {
	var req struct {
		Role     *string `json:"role"`
		Disabled *bool   `json:"disabled"`
		Password *string `json:"password"`
	}
	if err := httpx.ReadJSON(r, 4096, &req); err != nil {
		httpx.Fail(w, http.StatusBadRequest, "invalid request")
		return
	}
	target := r.PathValue("name")
	if err := a.st.UpdateUser(target, req.Role, req.Disabled, req.Password); err != nil {
		userErr(w, err)
		return
	}
	var parts []string
	if req.Role != nil {
		parts = append(parts, "role="+*req.Role)
	}
	if req.Disabled != nil {
		parts = append(parts, map[bool]string{true: "disabled", false: "enabled"}[*req.Disabled])
	}
	if req.Password != nil {
		parts = append(parts, "password reset")
	}
	a.st.AddAudit(user, "update_user", target, strings.Join(parts, " "))
	httpx.OK(w, nil)
}

func (a *API) deleteUser(w http.ResponseWriter, r *http.Request, user string) {
	target := r.PathValue("name")
	if target == user {
		httpx.Fail(w, http.StatusConflict, "you cannot delete your own account")
		return
	}
	if err := a.st.DeleteUser(target); err != nil {
		userErr(w, err)
		return
	}
	a.st.AddAudit(user, "delete_user", target, "")
	httpx.OK(w, nil)
}

// ------------------------------------------------------------------ API tokens

// API tokens act with their owner's role; they are meant for CI/SIEM integrations.
func (a *API) listTokens(w http.ResponseWriter, r *http.Request, user string) {
	owner := user
	if r.URL.Query().Get("all") == "1" && a.principal(r).Role == store.RoleAdmin {
		owner = ""
	}
	list, err := a.st.ListTokens(owner)
	if err != nil {
		storeErr(w, err)
		return
	}
	httpx.OK(w, list)
}

func (a *API) createToken(w http.ResponseWriter, r *http.Request, user string) {
	if a.principal(r).Kind != "session" {
		httpx.Fail(w, http.StatusForbidden, "API tokens can only be created from a login session")
		return
	}
	var req struct {
		Name string `json:"name"`
		Days int    `json:"days"`
	}
	if err := httpx.ReadJSON(r, 4096, &req); err != nil || strings.TrimSpace(req.Name) == "" || len(req.Name) > 100 {
		httpx.Fail(w, http.StatusBadRequest, "name (1-100 characters) is required")
		return
	}
	if req.Days <= 0 || req.Days > maxTokenDays {
		httpx.Fail(w, http.StatusBadRequest, "days must be between 1 and 366")
		return
	}
	tok, err := a.st.IssueToken(user, "api", strings.TrimSpace(req.Name), int64(req.Days)*24*time.Hour.Milliseconds())
	if err != nil {
		storeErr(w, err)
		return
	}
	a.st.AddAudit(user, "create_token", req.Name, "days="+strconv.Itoa(req.Days))
	httpx.OK(w, map[string]string{"token": tok, "note": "store this token now; it cannot be shown again"})
}

func (a *API) deleteToken(w http.ResponseWriter, r *http.Request, user string) {
	owner := user
	if a.principal(r).Role == store.RoleAdmin {
		owner = "" // admins can revoke anyone's token
	}
	if err := a.st.RevokeTokenID(r.PathValue("id"), owner); err != nil {
		userErr(w, err)
		return
	}
	a.st.AddAudit(user, "revoke_token", r.PathValue("id"), "")
	httpx.OK(w, nil)
}
