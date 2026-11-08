// Package console implements the management console API (docs chapter 6.7), prefix /api/v1.
package console

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"zhuwei-rasp/server/internal/agentapi"
	"zhuwei-rasp/server/internal/httpx"
	"zhuwei-rasp/server/internal/ldapauth"
	"zhuwei-rasp/server/internal/policy"
	"zhuwei-rasp/server/internal/signing"
	"zhuwei-rasp/server/internal/store"
	"zhuwei-rasp/server/internal/vuln"
)

const (
	onlineWindow  = 3 * agentapi.HeartbeatSec * time.Second
	maxConsoleReq = 1 << 20
)

type API struct {
	st       *store.Store
	agentURL string
	signer   *signing.Signer
	// Vulns imports advisories and rematches components; set by main (nil disables import/rematch).
	Vulns *vuln.Service

	limit *limiter
	// LDAP, when enabled, authenticates names that are not local accounts (set by main).
	LDAP *ldapauth.Config
}

// New creates the console API. agentURL is the address agents should use (shown in install snippets).
// Users, roles and tokens live in the store; see auth.go.
func New(st *store.Store, agentURL string, signer *signing.Signer) *API {
	return &API{st: st, agentURL: agentURL, signer: signer, limit: newLimiter()}
}

func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/login", a.login)
	mux.HandleFunc("POST /api/v1/logout", a.authAs(store.RoleViewer, a.logout))
	mux.HandleFunc("GET /api/v1/me", a.auth(a.me))
	mux.HandleFunc("PUT /api/v1/me/password", a.authAs(store.RoleViewer, a.changeOwnPassword))
	mux.HandleFunc("GET /api/v1/tokens", a.auth(a.listTokens))
	mux.HandleFunc("POST /api/v1/tokens", a.authAs(store.RoleViewer, a.createToken))
	mux.HandleFunc("DELETE /api/v1/tokens/{id}", a.authAs(store.RoleViewer, a.deleteToken))
	mux.HandleFunc("GET /api/v1/users", a.admin(a.listUsers))
	mux.HandleFunc("POST /api/v1/users", a.admin(a.createUser))
	mux.HandleFunc("PUT /api/v1/users/{name}", a.admin(a.updateUser))
	mux.HandleFunc("DELETE /api/v1/users/{name}", a.admin(a.deleteUser))

	mux.HandleFunc("GET /api/v1/stats", a.auth(a.stats))
	mux.HandleFunc("GET /api/v1/signing", a.auth(func(w http.ResponseWriter, r *http.Request, user string) {
		httpx.OK(w, map[string]any{"alg": signing.Alg, "key_id": a.signer.KeyID(), "public_key": a.signer.PublicKey(), "pem": a.signer.PublicPEM()})
	}))

	mux.HandleFunc("GET /api/v1/apps", a.auth(a.listApps))
	mux.HandleFunc("POST /api/v1/apps", a.auth(a.createApp))
	mux.HandleFunc("GET /api/v1/apps/{id}", a.auth(a.getApp))
	mux.HandleFunc("DELETE /api/v1/apps/{id}", a.admin(a.deleteApp))
	mux.HandleFunc("GET /api/v1/apps/{id}/policy", a.auth(a.getPolicy))
	mux.HandleFunc("PUT /api/v1/apps/{id}/policy", a.auth(a.putPolicy))
	mux.HandleFunc("GET /api/v1/apps/{id}/effective", a.auth(a.effective))
	mux.HandleFunc("GET /api/v1/policy/default", a.auth(func(w http.ResponseWriter, r *http.Request, _ string) {
		httpx.OK(w, json.RawMessage(policy.Default()))
	}))

	mux.HandleFunc("GET /api/v1/instances", a.auth(a.listInstances))

	mux.HandleFunc("GET /api/v1/alarms", a.auth(a.listAlarms))
	mux.HandleFunc("GET /api/v1/alarms/{id}", a.auth(a.getAlarm))
	mux.HandleFunc("POST /api/v1/alarms/{id}/status", a.auth(a.setAlarmStatus))
	mux.HandleFunc("POST /api/v1/alarms/{id}/whitelist", a.auth(a.whitelistFromAlarm))

	mux.HandleFunc("GET /api/v1/whitelists", a.auth(a.listWhitelist))
	mux.HandleFunc("POST /api/v1/whitelists", a.auth(a.addWhitelist))
	mux.HandleFunc("DELETE /api/v1/whitelists/{id}", a.auth(a.deleteWhitelist))

	mux.HandleFunc("GET /api/v1/components", a.auth(a.listComponents))
	mux.HandleFunc("GET /api/v1/components/uses", a.auth(a.componentUses))
	a.registerVulns(mux)

	mux.HandleFunc("GET /api/v1/settings", a.auth(a.getSettings))
	mux.HandleFunc("PUT /api/v1/settings", a.admin(a.putSettings))
	mux.HandleFunc("GET /api/v1/audit", a.authAs(store.RoleOperator, a.listAudit))
}

func storeErr(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		httpx.Fail(w, http.StatusNotFound, "not found")
		return
	}
	log.Printf("console store error: %v", err)
	httpx.Fail(w, http.StatusInternalServerError, "store error")
}

// ------------------------------------------------------------------ stats

func (a *API) stats(w http.ResponseWriter, r *http.Request, _ string) {
	days := httpx.QueryInt(r, "days", 7)
	if days < 1 || days > 180 {
		days = 7
	}
	since := time.Now().Add(-time.Duration(days) * 24 * time.Hour).UnixMilli()
	res := map[string]any{"days": days}
	for _, col := range []string{"attack_type", "action", "client_ip", "app", "day"} {
		limit := 10
		if col == "day" {
			limit = 200
		}
		c, err := a.st.AlarmStats(since, col, limit)
		if err != nil {
			storeErr(w, err)
			return
		}
		res["by_"+col] = c
	}
	insts, err := a.st.ListInstances(0, a.onlineSince())
	if err != nil {
		storeErr(w, err)
		return
	}
	online, breaker := 0, 0
	for _, i := range insts {
		if i.Online {
			online++
		}
		if strings.Contains(i.Metrics, `"breaker_state":"open"`) || strings.Contains(i.Metrics, `"breaker_state":"manual_off"`) {
			breaker++
		}
	}
	apps, _ := a.st.ListApps(a.onlineSince())
	res["instances_total"] = len(insts)
	res["instances_online"] = online
	res["instances_breaker"] = breaker
	res["apps_total"] = len(apps)
	res["kill_switch"] = a.st.GetSetting("kill_switch", "false") == "true"
	httpx.OK(w, res)
}

func (a *API) onlineSince() int64 { return time.Now().Add(-onlineWindow).UnixMilli() }

// ------------------------------------------------------------------ apps & policy

func (a *API) listApps(w http.ResponseWriter, r *http.Request, _ string) {
	apps, err := a.st.ListApps(a.onlineSince())
	if err != nil {
		storeErr(w, err)
		return
	}
	httpx.OK(w, apps)
}

func (a *API) createApp(w http.ResponseWriter, r *http.Request, user string) {
	var req store.App
	if err := httpx.ReadJSON(r, maxConsoleReq, &req); err != nil {
		httpx.Fail(w, http.StatusBadRequest, "invalid request")
		return
	}
	req.Name, req.Env = strings.TrimSpace(req.Name), strings.TrimSpace(req.Env)
	if req.Name == "" || len(req.Name) > 128 {
		httpx.Fail(w, http.StatusBadRequest, "name required (max 128 chars)")
		return
	}
	if req.Env == "" {
		req.Env = "prod"
	}
	if req.Language == "" {
		req.Language = "java"
	}
	req.Policy = policy.Default()
	if err := a.st.CreateApp(&req); err != nil {
		httpx.Fail(w, http.StatusBadRequest, err.Error())
		return
	}
	a.st.AddAudit(user, "create_app", fmt.Sprintf("%s/%s", req.Name, req.Env), "")
	httpx.OK(w, a.withInstall(&req))
}

func (a *API) getApp(w http.ResponseWriter, r *http.Request, _ string) {
	app, err := a.st.GetApp(httpx.PathInt(r, "id"))
	if err != nil {
		storeErr(w, err)
		return
	}
	if store.RoleRank(a.principal(r).Role) < store.RoleRank(store.RoleOperator) {
		app.AppSecret = "<hidden: requires operator role>" // viewers can read setup instructions, not credentials
	}
	httpx.OK(w, a.withInstall(app))
}

func (a *API) withInstall(app *store.App) map[string]any {
	props := fmt.Sprintf("server.url=%s\napp.key=%s\napp.secret=%s\napp.name=%s\napp.env=%s\n"+
		"# policy signing public key (key id %s); configs that do not verify are rejected\npolicy.public_key=%s\n",
		a.agentURL, app.AppKey, app.AppSecret, app.Name, app.Env, a.signer.KeyID(), a.signer.PublicKey())
	return map[string]any{
		"app":        app,
		"properties": props,
		"command":    "java -javaagent:/opt/rasp/rasp-launcher.jar -jar your-app.jar",
	}
}

func (a *API) deleteApp(w http.ResponseWriter, r *http.Request, user string) {
	id := httpx.PathInt(r, "id")
	app, err := a.st.GetApp(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	if err := a.st.DeleteApp(id); err != nil {
		storeErr(w, err)
		return
	}
	a.st.AddAudit(user, "delete_app", app.Name+"/"+app.Env, "")
	httpx.OK(w, nil)
}

func (a *API) getPolicy(w http.ResponseWriter, r *http.Request, _ string) {
	app, err := a.st.GetApp(httpx.PathInt(r, "id"))
	if err != nil {
		storeErr(w, err)
		return
	}
	httpx.OK(w, map[string]any{"policy": json.RawMessage(app.Policy), "policy_rev": app.PolicyRev})
}

func (a *API) putPolicy(w http.ResponseWriter, r *http.Request, user string) {
	id := httpx.PathInt(r, "id")
	app, err := a.st.GetApp(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	var raw json.RawMessage
	if err := httpx.ReadJSON(r, maxConsoleReq, &raw); err != nil {
		httpx.Fail(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	norm, err := policy.Validate(string(raw))
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, err.Error())
		return
	}
	// Turning on blocking is the one change that can break a live application: require the operator to
	// confirm by typing the app name (header X-Rasp-Confirm), and say exactly which rules start blocking.
	added := policy.NewlyBlocking(app.Policy, norm)
	if len(added) > 0 && r.Header.Get("X-Rasp-Confirm") != app.Name {
		var prev map[string]any
		_ = json.Unmarshal([]byte(app.Policy), &prev)
		httpx.FailData(w, http.StatusConflict, "confirm_required", map[string]any{
			"app": app.Name, "env": app.Env, "rules": added, "prev_mode": prev["mode"],
			"instances": a.onlineInstances(app.ID),
		})
		return
	}
	if err := a.st.UpdateAppPolicy(id, norm); err != nil {
		storeErr(w, err)
		return
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(norm), &m)
	detail := fmt.Sprintf("mode=%v", m["mode"])
	if len(added) > 0 {
		detail += " confirmed_block=" + strings.Join(added, ",")
	}
	a.st.AddAudit(user, "update_policy", app.Name+"/"+app.Env, detail)
	httpx.OK(w, nil)
}

func (a *API) effective(w http.ResponseWriter, r *http.Request, _ string) {
	app, err := a.st.GetApp(httpx.PathInt(r, "id"))
	if err != nil {
		storeErr(w, err)
		return
	}
	wl, err := a.st.ListWhitelist(app.ID)
	if err != nil {
		storeErr(w, err)
		return
	}
	cfg, _ := policy.Effective(app, wl, a.st.GetSetting("kill_switch", "false") == "true")
	httpx.OK(w, cfg)
}

// ------------------------------------------------------------------ instances

func (a *API) listInstances(w http.ResponseWriter, r *http.Request, _ string) {
	list, err := a.st.ListInstances(httpx.QueryInt(r, "app_id", 0), a.onlineSince())
	if err != nil {
		storeErr(w, err)
		return
	}
	httpx.OK(w, list)
}

// ------------------------------------------------------------------ alarms

func (a *API) listAlarms(w http.ResponseWriter, r *http.Request, _ string) {
	q := r.URL.Query()
	list, total, err := a.st.QueryAlarms(store.AlarmQuery{
		AppID: httpx.QueryInt(r, "app_id", 0), AttackType: q.Get("type"), Action: q.Get("action"), Status: q.Get("status"),
		Keyword: q.Get("q"), Since: httpx.QueryInt(r, "since", 0),
		Page: int(httpx.QueryInt(r, "page", 1)), PageSize: int(httpx.QueryInt(r, "page_size", 20)),
	})
	if err != nil {
		storeErr(w, err)
		return
	}
	httpx.OK(w, map[string]any{"items": list, "total": total})
}

func (a *API) getAlarm(w http.ResponseWriter, r *http.Request, _ string) {
	al, err := a.st.GetAlarm(r.PathValue("id"))
	if err != nil {
		storeErr(w, err)
		return
	}
	httpx.OK(w, al)
}

var alarmStatuses = map[string]bool{"new": true, "confirmed": true, "false_positive": true, "fixed": true, "ignored": true}

func (a *API) setAlarmStatus(w http.ResponseWriter, r *http.Request, user string) {
	var req struct{ Status string }
	if err := httpx.ReadJSON(r, 4096, &req); err != nil || !alarmStatuses[req.Status] {
		httpx.Fail(w, http.StatusBadRequest, "status must be new/confirmed/false_positive/fixed/ignored")
		return
	}
	id := r.PathValue("id")
	if err := a.st.SetAlarmStatus(id, req.Status); err != nil {
		storeErr(w, err)
		return
	}
	a.st.AddAudit(user, "alarm_status", id, req.Status)
	httpx.OK(w, nil)
}

// whitelistFromAlarm creates an exact-path whitelist entry for the alarm's URL and attack type.
func (a *API) whitelistFromAlarm(w http.ResponseWriter, r *http.Request, user string) {
	al, err := a.st.GetAlarm(r.PathValue("id"))
	if err != nil {
		storeErr(w, err)
		return
	}
	path := al.URL
	if i := strings.Index(path, "://"); i >= 0 {
		if j := strings.Index(path[i+3:], "/"); j >= 0 {
			path = path[i+3+j:]
		} else {
			path = "/"
		}
	}
	if i := strings.Index(path, "?"); i >= 0 {
		path = path[:i]
	}
	if path == "" {
		httpx.Fail(w, http.StatusBadRequest, "alarm has no request URL (not in an HTTP request)")
		return
	}
	wl := &store.Whitelist{AppID: al.AppID, URL: path, Match: "exact", Types: al.AttackType,
		Note: "from alarm " + al.EventID, CreatedBy: user}
	if err := a.st.AddWhitelist(wl); err != nil {
		storeErr(w, err)
		return
	}
	_ = a.st.SetAlarmStatus(al.EventID, "false_positive")
	a.st.AddAudit(user, "add_whitelist", path, al.AttackType+" (from alarm)")
	httpx.OK(w, wl)
}

// ------------------------------------------------------------------ whitelist

func (a *API) listWhitelist(w http.ResponseWriter, r *http.Request, _ string) {
	list, err := a.st.ListWhitelist(httpx.QueryInt(r, "app_id", -1))
	if err != nil {
		storeErr(w, err)
		return
	}
	httpx.OK(w, list)
}

var matchTypes = map[string]bool{"exact": true, "prefix": true, "regex": true}

func (a *API) addWhitelist(w http.ResponseWriter, r *http.Request, user string) {
	var req store.Whitelist
	if err := httpx.ReadJSON(r, maxConsoleReq, &req); err != nil {
		httpx.Fail(w, http.StatusBadRequest, "invalid request")
		return
	}
	req.URL = strings.TrimSpace(req.URL)
	if req.URL == "" || !matchTypes[req.Match] {
		httpx.Fail(w, http.StatusBadRequest, "url required, match must be exact/prefix/regex")
		return
	}
	if req.Types == "" {
		req.Types = "all"
	}
	req.CreatedBy = user
	if err := a.st.AddWhitelist(&req); err != nil {
		storeErr(w, err)
		return
	}
	a.st.AddAudit(user, "add_whitelist", req.URL, req.Types)
	httpx.OK(w, req)
}

func (a *API) deleteWhitelist(w http.ResponseWriter, r *http.Request, user string) {
	id := httpx.PathInt(r, "id")
	if err := a.st.DeleteWhitelist(id); err != nil {
		storeErr(w, err)
		return
	}
	a.st.AddAudit(user, "delete_whitelist", fmt.Sprint(id), "")
	httpx.OK(w, nil)
}

// ------------------------------------------------------------------ components (SCA)

func (a *API) listComponents(w http.ResponseWriter, r *http.Request, _ string) {
	list, err := a.st.QueryComponents(httpx.QueryInt(r, "app_id", 0), strings.TrimSpace(r.URL.Query().Get("q")),
		int(httpx.QueryInt(r, "limit", 2000)))
	if err != nil {
		storeErr(w, err)
		return
	}
	httpx.OK(w, list)
}

func (a *API) componentUses(w http.ResponseWriter, r *http.Request, _ string) {
	q := r.URL.Query()
	list, err := a.st.ComponentUses(q.Get("group"), q.Get("artifact"), q.Get("version"))
	if err != nil {
		storeErr(w, err)
		return
	}
	httpx.OK(w, list)
}

// ------------------------------------------------------------------ settings & audit

var settingKeys = []string{"kill_switch", "notify_webhook", "notify_level", "alarm_retention_days"}

func (a *API) getSettings(w http.ResponseWriter, r *http.Request, _ string) {
	out := map[string]string{}
	defaults := map[string]string{"kill_switch": "false", "notify_level": "block", "alarm_retention_days": "180"}
	for _, k := range settingKeys {
		out[k] = a.st.GetSetting(k, defaults[k])
	}
	httpx.OK(w, out)
}

func (a *API) putSettings(w http.ResponseWriter, r *http.Request, user string) {
	var req map[string]string
	if err := httpx.ReadJSON(r, 8192, &req); err != nil {
		httpx.Fail(w, http.StatusBadRequest, "invalid request")
		return
	}
	for _, k := range settingKeys {
		v, ok := req[k]
		if !ok {
			continue
		}
		if k == "kill_switch" && v != "true" && v != "false" {
			httpx.Fail(w, http.StatusBadRequest, "kill_switch must be true or false")
			return
		}
		if k == "notify_webhook" && v != "" && !strings.HasPrefix(v, "http://") && !strings.HasPrefix(v, "https://") {
			httpx.Fail(w, http.StatusBadRequest, "notify_webhook must be an http(s) URL")
			return
		}
		if err := a.st.SetSetting(k, v); err != nil {
			storeErr(w, err)
			return
		}
		a.st.AddAudit(user, "setting", k, v)
	}
	httpx.OK(w, nil)
}

func (a *API) listAudit(w http.ResponseWriter, r *http.Request, _ string) {
	list, err := a.st.ListAudit(int(httpx.QueryInt(r, "limit", 200)))
	if err != nil {
		storeErr(w, err)
		return
	}
	httpx.OK(w, list)
}

// onlineInstances counts the app's agents that heartbeated recently (shown in the block confirmation).
func (a *API) onlineInstances(appID int64) int {
	list, err := a.st.ListInstances(appID, a.onlineSince())
	if err != nil {
		return 0
	}
	n := 0
	for _, i := range list {
		if i.Online {
			n++
		}
	}
	return n
}
