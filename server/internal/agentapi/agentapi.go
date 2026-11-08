// Package agentapi implements the agent-facing protocol (docs chapter 7): register, heartbeat,
// config pull and alarm upload. Every request is authenticated with an HMAC signature.
package agentapi

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"zhuwei-rasp/server/internal/httpx"
	"zhuwei-rasp/server/internal/ops"
	"zhuwei-rasp/server/internal/policy"
	"zhuwei-rasp/server/internal/signing"
	"zhuwei-rasp/server/internal/store"
)

const (
	maxBody           = 4 << 20
	maxEventsPerBatch = 500
	clockSkew         = 5 * time.Minute
	HeartbeatSec      = 30
)

type API struct {
	st     *store.Store
	nonces sync.Map // nonce -> unix millis
	notify *Notifier
	signer *signing.Signer
	// OnDependencies runs after an agent's component inventory is stored (vulnerability rematch).
	OnDependencies func()
	// Forward receives every stored alarm (SIEM); it must not block.
	Forward func(*store.Alarm)
	// AlarmRate is the sustained number of alarm events per second accepted per application (burst = 10x).
	// Excess events are dropped (they remain in the agent's local alarm.log); 0 disables the limit.
	AlarmRate float64

	bucketsMu sync.Mutex
	buckets   map[int64]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// take returns how many of n events the app may store now.
func (a *API) take(appID int64, n int) int {
	if a.AlarmRate <= 0 {
		return n
	}
	a.bucketsMu.Lock()
	defer a.bucketsMu.Unlock()
	if a.buckets == nil {
		a.buckets = map[int64]*bucket{}
	}
	burst := a.AlarmRate * 10
	b := a.buckets[appID]
	now := time.Now()
	if b == nil {
		b = &bucket{tokens: burst, last: now}
		a.buckets[appID] = b
	}
	b.tokens = min(burst, b.tokens+now.Sub(b.last).Seconds()*a.AlarmRate)
	b.last = now
	allowed := min(n, int(b.tokens))
	b.tokens -= float64(allowed)
	return allowed
}

func New(st *store.Store, n *Notifier, signer *signing.Signer) *API {
	a := &API{st: st, notify: n, signer: signer}
	go a.gcNonces()
	return a
}

func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /agent/v1/register", a.auth(a.register, false))
	mux.HandleFunc("POST /agent/v1/heartbeat", a.auth(a.heartbeat, true))
	mux.HandleFunc("GET /agent/v1/config", a.auth(a.config, true))
	mux.HandleFunc("POST /agent/v1/alarms", a.auth(a.alarms, true))
	mux.HandleFunc("POST /agent/v1/dependencies", a.auth(a.dependencies, true))
}

const maxComponents = 5000

func (a *API) dependencies(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	var req struct {
		Items []store.Component `json:"items"`
	}
	if err := json.Unmarshal(c.body, &req); err != nil {
		httpx.Fail(w, http.StatusBadRequest, "invalid dependency report")
		return
	}
	if len(req.Items) > maxComponents {
		httpx.Fail(w, http.StatusRequestEntityTooLarge, "too many components")
		return
	}
	items := req.Items[:0]
	for _, it := range req.Items {
		if it.Artifact == "" || it.Path == "" || len(it.Path) > 2048 || len(it.Artifact) > 512 || len(it.Version) > 256 {
			continue
		}
		items = append(items, it)
	}
	if err := a.st.ReplaceComponents(c.agentID, c.app.ID, items); err != nil {
		log.Printf("store components: %v", err)
		httpx.Fail(w, http.StatusInternalServerError, "store error")
		return
	}
	if a.OnDependencies != nil {
		a.OnDependencies()
	}
	httpx.OK(w, map[string]any{"accepted": len(items)})
}

type reqCtx struct {
	app     *store.App
	agentID string
	body    []byte
}

type handler func(w http.ResponseWriter, r *http.Request, c *reqCtx)

// auth verifies X-Rasp-Sign = hex(HMAC-SHA256(secret, METHOD\nPATH\nTS\nNONCE\nhex(SHA256(body)))).
func (a *API) auth(h handler, requireKnownAgent bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ops.AgentRequests.Inc(strings.TrimPrefix(r.URL.Path, "/agent/v1/"))
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil || len(body) > maxBody {
			httpx.Fail(w, http.StatusRequestEntityTooLarge, "body too large")
			return
		}
		app, err := a.st.GetAppByKey(r.Header.Get("X-Rasp-AppKey"))
		if err != nil {
			httpx.Fail(w, http.StatusUnauthorized, "invalid app key")
			return
		}
		ts, nonce, sign := r.Header.Get("X-Rasp-Timestamp"), r.Header.Get("X-Rasp-Nonce"), r.Header.Get("X-Rasp-Sign")
		tsv, err := strconv.ParseInt(ts, 10, 64)
		if err != nil || absDur(time.Since(time.UnixMilli(tsv))) > clockSkew {
			httpx.Fail(w, http.StatusUnauthorized, "timestamp out of range")
			return
		}
		if len(nonce) < 16 {
			httpx.Fail(w, http.StatusUnauthorized, "bad nonce")
			return
		}
		if !hmac.Equal([]byte(sign), []byte(Sign(app.AppSecret, r.Method, r.URL.Path, ts, nonce, body))) {
			httpx.Fail(w, http.StatusUnauthorized, "bad signature")
			return
		}
		if _, dup := a.nonces.LoadOrStore(app.AppKey+":"+nonce, time.Now().UnixMilli()); dup {
			httpx.Fail(w, http.StatusUnauthorized, "replayed request")
			return
		}
		c := &reqCtx{app: app, agentID: r.Header.Get("X-Rasp-AgentId"), body: body}
		if requireKnownAgent && !a.st.InstanceBelongsTo(c.agentID, app.ID) {
			httpx.Fail(w, http.StatusNotFound, "agent not registered")
			return
		}
		h(w, r, c)
	}
}

// Sign computes the request signature; exported for tests and tooling.
func Sign(secret, method, path, ts, nonce string, body []byte) string {
	bh := sha256.Sum256(body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(method + "\n" + path + "\n" + ts + "\n" + nonce + "\n" + hex.EncodeToString(bh[:])))
	return hex.EncodeToString(mac.Sum(nil))
}

type registerReq struct {
	AgentID      string            `json:"agent_id"`
	Language     string            `json:"language"`
	AgentVersion string            `json:"agent_version"`
	Hostname     string            `json:"hostname"`
	IPs          []string          `json:"ips"`
	PID          int64             `json:"pid"`
	OS           string            `json:"os"`
	Runtime      map[string]string `json:"runtime"`
	Server       map[string]string `json:"server"`
	StartMode    string            `json:"start_mode"`
}

func (a *API) register(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	var req registerReq
	if err := json.Unmarshal(c.body, &req); err != nil || len(req.AgentID) < 8 || len(req.AgentID) > 64 {
		httpx.Fail(w, http.StatusBadRequest, "invalid register request")
		return
	}
	if c.agentID != req.AgentID {
		httpx.Fail(w, http.StatusBadRequest, "agent id mismatch")
		return
	}
	inst := &store.Instance{
		AgentID: req.AgentID, AppID: c.app.ID, Hostname: req.Hostname, IPs: strings.Join(req.IPs, ","), PID: req.PID,
		AgentVersion: req.AgentVersion, Language: req.Language, OS: req.OS, StartMode: req.StartMode,
		Runtime:    strings.TrimSpace(req.Runtime["name"] + " " + req.Runtime["version"]),
		ServerType: req.Server["type"],
	}
	if err := a.st.UpsertInstance(inst); err != nil {
		log.Printf("register %s: %v", req.AgentID, err)
		httpx.Fail(w, http.StatusInternalServerError, "store error")
		return
	}
	_, version := a.effective(c.app)
	log.Printf("agent registered app=%s agent=%s host=%s", c.app.Name, req.AgentID, req.Hostname)
	httpx.OK(w, map[string]any{"agent_id": req.AgentID, "heartbeat_interval": HeartbeatSec, "config_version": version})
}

type heartbeatReq struct {
	ConfigVersion string          `json:"config_version"`
	Metrics       json.RawMessage `json:"metrics"`
}

func (a *API) heartbeat(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	var req heartbeatReq
	if err := json.Unmarshal(c.body, &req); err != nil {
		httpx.Fail(w, http.StatusBadRequest, "invalid heartbeat")
		return
	}
	metrics := "{}"
	if len(req.Metrics) > 0 && len(req.Metrics) < 8192 {
		metrics = string(req.Metrics)
	}
	if err := a.st.Heartbeat(c.agentID, c.app.ID, req.ConfigVersion, metrics); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.Fail(w, http.StatusNotFound, "agent not registered")
			return
		}
		httpx.Fail(w, http.StatusInternalServerError, "store error")
		return
	}
	cfg, version := a.effective(c.app)
	httpx.OK(w, map[string]any{"config_changed": version != req.ConfigVersion, "kill_switch": cfg["kill_switch"]})
}

// config returns the effective policy as a signed envelope:
//
//	{"alg":"ES256","key_id":"...","payload":"<policy JSON>","signature":"<base64 DER>"}
//
// The payload is bound to the app (app_key) and carries issued_at so agents can refuse a replayed,
// older policy. Agents verify the exact payload bytes, so it is sent as a string, not re-encoded.
func (a *API) config(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	cfg, _ := a.effective(c.app)
	cfg["app_key"] = c.app.AppKey
	cfg["issued_at"] = time.Now().UnixMilli()
	payload, err := json.Marshal(cfg)
	if err != nil {
		httpx.Fail(w, http.StatusInternalServerError, "encode policy")
		return
	}
	sig, err := a.signer.Sign(payload)
	if err != nil {
		log.Printf("sign policy: %v", err)
		httpx.Fail(w, http.StatusInternalServerError, "sign policy")
		return
	}
	httpx.OK(w, map[string]any{"alg": signing.Alg, "key_id": a.signer.KeyID(), "payload": string(payload), "signature": sig})
}

type alarmBatch struct {
	Events []json.RawMessage `json:"events"`
}

type eventHead struct {
	EventID      string `json:"event_id"`
	EventTime    int64  `json:"event_time"`
	AttackType   string `json:"attack_type"`
	Algorithm    string `json:"algorithm"`
	Action       string `json:"action"`
	Confidence   int64  `json:"confidence"`
	Reason       string `json:"reason"`
	MatchedInput string `json:"matched_input"`
	Request      *struct {
		URL      string `json:"url"`
		ClientIP string `json:"client_ip"`
		RealIP   string `json:"real_ip"`
	} `json:"request"`
}

func (a *API) alarms(w http.ResponseWriter, r *http.Request, c *reqCtx) {
	var b alarmBatch
	if err := json.Unmarshal(c.body, &b); err != nil {
		httpx.Fail(w, http.StatusBadRequest, "invalid alarm batch")
		return
	}
	if len(b.Events) > maxEventsPerBatch {
		httpx.Fail(w, http.StatusRequestEntityTooLarge, "too many events")
		return
	}
	host := a.hostname(c)
	out := make([]*store.Alarm, 0, len(b.Events))
	for _, raw := range b.Events {
		var e eventHead
		if err := json.Unmarshal(raw, &e); err != nil || e.EventID == "" || e.AttackType == "" {
			continue
		}
		al := &store.Alarm{
			EventID: e.EventID, AppID: c.app.ID, AgentID: c.agentID, Hostname: host, EventTime: e.EventTime,
			AttackType: e.AttackType, Algorithm: e.Algorithm, Action: e.Action, Confidence: e.Confidence,
			Reason: e.Reason, MatchedInput: e.MatchedInput, Raw: compact(raw),
		}
		if e.Request != nil {
			al.URL = e.Request.URL
			al.ClientIP = e.Request.RealIP
			if al.ClientIP == "" {
				al.ClientIP = e.Request.ClientIP
			}
		}
		if al.EventTime == 0 {
			al.EventTime = time.Now().UnixMilli()
		}
		out = append(out, al)
	}
	dropped := 0
	if allowed := a.take(c.app.ID, len(out)); allowed < len(out) {
		// keep the most important events: blocks before logs
		sort.SliceStable(out, func(i, j int) bool { return out[i].Action == "block" && out[j].Action != "block" })
		dropped = len(out) - allowed
		out = out[:allowed]
		ops.AlarmsDropped.Add("", int64(dropped))
		log.Printf("app %s: alarm rate limit reached, dropped %d events", c.app.Name, dropped)
	}
	if err := a.st.InsertAlarms(out); err != nil {
		log.Printf("insert alarms: %v", err)
		httpx.Fail(w, http.StatusInternalServerError, "store error")
		return
	}
	ops.AlarmsIngested.Add("", int64(len(out)))
	for _, al := range out {
		al.AppName = c.app.Name
		a.notify.Alarm(al)
		if a.Forward != nil {
			a.Forward(al)
		}
	}
	httpx.OK(w, map[string]any{"accepted": len(out), "dropped": dropped})
}

func (a *API) effective(app *store.App) (map[string]any, string) {
	wl, err := a.st.ListWhitelist(app.ID)
	if err != nil {
		log.Printf("list whitelist: %v", err)
	}
	return policy.Effective(app, wl, a.st.GetSetting("kill_switch", "false") == "true")
}

func (a *API) hostname(c *reqCtx) string {
	list, err := a.st.ListInstances(c.app.ID, 0)
	if err != nil {
		return ""
	}
	for _, i := range list {
		if i.AgentID == c.agentID {
			return i.Hostname
		}
	}
	return ""
}

func (a *API) gcNonces() {
	for range time.Tick(time.Minute) {
		limit := time.Now().Add(-2 * clockSkew).UnixMilli()
		a.nonces.Range(func(k, v any) bool {
			if v.(int64) < limit {
				a.nonces.Delete(k)
			}
			return true
		})
	}
}

func compact(raw []byte) string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return string(raw)
	}
	return buf.String()
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
