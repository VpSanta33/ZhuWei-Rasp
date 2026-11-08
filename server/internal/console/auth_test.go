package console

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"zhuwei-rasp/server/internal/signing"
	"zhuwei-rasp/server/internal/store"
)

type env struct {
	t   *testing.T
	st  *store.Store
	srv *httptest.Server
}

func setup(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	signer, _, err := signing.LoadOrCreate(filepath.Join(dir, "k.pem"))
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range [][2]string{{"root", store.RoleAdmin}, {"ops", store.RoleOperator}, {"audit", store.RoleViewer}} {
		if err := st.CreateUser(u[0], u[1], u[0]+"-password-123"); err != nil {
			t.Fatal(err)
		}
	}
	mux := http.NewServeMux()
	New(st, "http://agent", signer).Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(func() { srv.Close(); st.Close() })
	return &env{t, st, srv}
}

func (e *env) do(method, path, token string, body any) (int, map[string]any) {
	e.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (e *env) login(user string) string {
	e.t.Helper()
	code, out := e.do("POST", "/api/v1/login", "", map[string]string{"username": user, "password": user + "-password-123"})
	if code != 200 {
		e.t.Fatalf("login %s: %d %v", user, code, out)
	}
	return out["data"].(map[string]any)["token"].(string)
}

func TestRoleEnforcement(t *testing.T) {
	e := setup(t)
	root, ops, viewer := e.login("root"), e.login("ops"), e.login("audit")

	if c, _ := e.do("GET", "/api/v1/apps", "", nil); c != 401 {
		t.Fatalf("anonymous = %d", c)
	}
	// viewers read; anything that writes needs operator by default
	if c, _ := e.do("GET", "/api/v1/apps", viewer, nil); c != 200 {
		t.Fatalf("viewer read = %d", c)
	}
	if c, out := e.do("POST", "/api/v1/apps", viewer, map[string]string{"name": "x"}); c != 403 || !strings.Contains(out["message"].(string), "operator") {
		t.Fatalf("viewer create app = %d %v", c, out)
	}
	c, out := e.do("POST", "/api/v1/apps", ops, map[string]string{"name": "pay"})
	if c != 200 {
		t.Fatalf("operator create app = %d %v", c, out)
	}
	id := int(out["data"].(map[string]any)["app"].(map[string]any)["id"].(float64))
	path := "/api/v1/apps/" + strings.TrimSpace(strings.Repeat(" ", 0)) + itoaTest(id)

	// secrets: hidden from viewers, visible to operators
	_, out = e.do("GET", path, viewer, nil)
	if props := out["data"].(map[string]any)["properties"].(string); !strings.Contains(props, "app.secret=<hidden") {
		t.Fatalf("viewer sees secret: %s", props)
	}
	_, out = e.do("GET", path, ops, nil)
	if props := out["data"].(map[string]any)["properties"].(string); strings.Contains(props, "<hidden") {
		t.Fatalf("operator cannot see secret: %s", props)
	}

	// admin-only operations
	for _, tc := range []struct{ method, path string }{{"DELETE", path}, {"PUT", "/api/v1/settings"}, {"GET", "/api/v1/users"}} {
		if c, _ := e.do(tc.method, tc.path, ops, map[string]string{}); c != 403 {
			t.Errorf("operator %s %s = %d, want 403", tc.method, tc.path, c)
		}
	}
	if c, _ := e.do("PUT", "/api/v1/settings", root, map[string]string{"alarm_retention_days": "90"}); c != 200 {
		t.Fatalf("admin settings = %d", c)
	}
	if c, _ := e.do("GET", "/api/v1/audit", viewer, nil); c != 403 {
		t.Fatalf("viewer audit = %d", c)
	}
	// every user may log out, read /me and change their own password
	_, out = e.do("GET", "/api/v1/me", viewer, nil)
	if out["data"].(map[string]any)["role"] != "viewer" {
		t.Fatalf("me = %v", out)
	}
	if c, _ := e.do("POST", "/api/v1/logout", viewer, nil); c != 200 {
		t.Fatalf("viewer logout = %d", c)
	}
	if c, _ := e.do("GET", "/api/v1/me", viewer, nil); c != 401 {
		t.Fatalf("token still valid after logout = %d", c)
	}
}

func itoaTest(n int) string { b, _ := json.Marshal(n); return string(b) }

func TestUserLifecycleAndLastAdmin(t *testing.T) {
	e := setup(t)
	root := e.login("root")
	if c, out := e.do("POST", "/api/v1/users", root, map[string]string{"username": "new", "role": "viewer", "password": "short"}); c != 400 || !strings.Contains(out["message"].(string), "12") {
		t.Fatalf("weak password = %d %v", c, out)
	}
	if c, _ := e.do("POST", "/api/v1/users", root, map[string]string{"username": "new", "role": "viewer", "password": "a-long-enough-pass"}); c != 200 {
		t.Fatalf("create = %d", c)
	}
	if c, _ := e.do("POST", "/api/v1/users", root, map[string]string{"username": "new", "role": "viewer", "password": "a-long-enough-pass"}); c != 409 {
		t.Fatalf("duplicate = %d", c)
	}
	// last enabled admin cannot be demoted, disabled or deleted
	if c, _ := e.do("PUT", "/api/v1/users/root", root, map[string]string{"role": "viewer"}); c != 409 {
		t.Fatalf("demote last admin = %d", c)
	}
	if c, _ := e.do("DELETE", "/api/v1/users/root", root, nil); c != 409 {
		t.Fatalf("delete self = %d", c)
	}
	// disabling a user revokes their sessions immediately
	ops := e.login("ops")
	if c, _ := e.do("PUT", "/api/v1/users/ops", root, map[string]any{"disabled": true}); c != 200 {
		t.Fatalf("disable = %d", c)
	}
	if c, _ := e.do("GET", "/api/v1/apps", ops, nil); c != 401 {
		t.Fatalf("disabled user's session = %d", c)
	}
	if c, _ := e.do("POST", "/api/v1/login", "", map[string]string{"username": "ops", "password": "ops-password-123"}); c != 401 {
		t.Fatalf("disabled login = %d", c)
	}
	// self password change: needs the old one, revokes current sessions
	viewer := e.login("audit")
	if c, _ := e.do("PUT", "/api/v1/me/password", viewer, map[string]string{"old_password": "wrong", "new_password": "another-long-pass"}); c != 400 {
		t.Fatalf("wrong old password = %d", c)
	}
	if c, _ := e.do("PUT", "/api/v1/me/password", viewer, map[string]string{"old_password": "audit-password-123", "new_password": "another-long-pass"}); c != 200 {
		t.Fatalf("change password = %d", c)
	}
	if c, _ := e.do("GET", "/api/v1/me", viewer, nil); c != 401 {
		t.Fatalf("session survives password change = %d", c)
	}
	if c, _ := e.do("POST", "/api/v1/login", "", map[string]string{"username": "audit", "password": "another-long-pass"}); c != 200 {
		t.Fatalf("login with new password = %d", c)
	}
}

func TestAPITokens(t *testing.T) {
	e := setup(t)
	ops := e.login("ops")
	c, out := e.do("POST", "/api/v1/tokens", ops, map[string]any{"name": "siem export", "days": 30})
	if c != 200 {
		t.Fatalf("create token = %d %v", c, out)
	}
	tok := out["data"].(map[string]any)["token"].(string)
	if !strings.HasPrefix(tok, "rat_") {
		t.Fatalf("token format %q", tok)
	}
	// acts with the owner's role, cannot mint further tokens
	if c, _ := e.do("GET", "/api/v1/alarms", tok, nil); c != 200 {
		t.Fatalf("token read = %d", c)
	}
	if c, _ := e.do("GET", "/api/v1/users", tok, nil); c != 403 {
		t.Fatalf("token admin route = %d", c)
	}
	if c, _ := e.do("POST", "/api/v1/tokens", tok, map[string]any{"name": "x", "days": 1}); c != 403 {
		t.Fatalf("token minting token = %d", c)
	}
	// stored hashed; listed without the secret; revocable by id
	_, out = e.do("GET", "/api/v1/tokens", ops, nil)
	list := out["data"].([]any)
	if len(list) != 1 || strings.Contains(mustJSON(list), tok) {
		t.Fatalf("token list = %v", list)
	}
	id := list[0].(map[string]any)["id"].(string)
	if c, _ := e.do("DELETE", "/api/v1/tokens/"+id, ops, nil); c != 200 {
		t.Fatalf("revoke = %d", c)
	}
	if c, _ := e.do("GET", "/api/v1/alarms", tok, nil); c != 401 {
		t.Fatalf("revoked token = %d", c)
	}
	if c, _ := e.do("POST", "/api/v1/tokens", ops, map[string]any{"name": "too long", "days": 400}); c != 400 {
		t.Fatalf("token lifetime cap = %d", c)
	}
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestLoginLockout(t *testing.T) {
	e := setup(t)
	for i := 0; i < lockoutFailures; i++ {
		if c, _ := e.do("POST", "/api/v1/login", "", map[string]string{"username": "root", "password": "nope"}); c != 401 {
			t.Fatalf("attempt %d = %d", i, c)
		}
	}
	// now locked, even with the right password, for this IP and this username
	if c, _ := e.do("POST", "/api/v1/login", "", map[string]string{"username": "root", "password": "root-password-123"}); c != 429 {
		t.Fatalf("after lockout = %d", c)
	}
	n := 0
	audit, _ := e.st.ListAudit(100)
	for _, a := range audit {
		if a.Action == "login_failed" {
			n++
		}
	}
	if n != lockoutFailures {
		t.Fatalf("failed logins audited = %d", n)
	}
}

func TestPasswordHashing(t *testing.T) {
	h, err := store.HashPassword("correct horse battery")
	if err != nil || !strings.HasPrefix(h, "pbkdf2-sha256$600000$") {
		t.Fatalf("hash = %q %v", h, err)
	}
	if !store.CheckPassword(h, "correct horse battery") || store.CheckPassword(h, "correct horse batterY") || store.CheckPassword("garbage", "x") {
		t.Fatal("password check")
	}
	h2, _ := store.HashPassword("correct horse battery")
	if h == h2 {
		t.Fatal("hashes must be salted")
	}
}
