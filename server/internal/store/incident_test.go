package store

import (
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestPathPattern(t *testing.T) {
	cases := map[string]string{
		"http://shop.local/api/item/7?x=1":                             "/api/item/{n}",
		"https://h/api/order/550e8400-e29b-41d4-a716-446655440000/pay": "/api/order/{uuid}/pay",
		"/files/9f86d081884c7d659a2feaa0c55ad015/raw":                  "/files/{hex}/raw",
		"/s/aGVsbG8td29ybGQtMTIzNDU2Nzg5MC1hYmNkZWY=/view":             "/s/{token}/view",
		"/static/app.bundle.js":                                        "/static/app.bundle.js",
		"/login;jsessionid=ABC":                                        "/login",
		"http://h":                                                     "/",
		"":                                                             "(no request)",
	}
	for in, want := range cases {
		if got := PathPattern(in); got != want {
			t.Errorf("PathPattern(%q) = %q, want %q", in, got, want)
		}
	}
	a, _ := Fingerprint(1, "sql", "rule:x", "http://h/api/item/7")
	b, _ := Fingerprint(1, "sql", "rule:x", "http://h/api/item/8?q=1")
	c, _ := Fingerprint(2, "sql", "rule:x", "http://h/api/item/7")
	if a != b || a == c {
		t.Fatalf("fingerprints: %s %s %s", a, b, c)
	}
}

func TestIncidentLifecycle(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "i.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	app := &App{Name: "shop", Env: "prod", Policy: "{}"}
	_ = st.CreateApp(app)
	now := time.Now().UnixMilli()
	mk := func(id, url, action, ip string, at int64) *Alarm {
		return &Alarm{EventID: id, AppID: app.ID, AgentID: "x", EventTime: at, AttackType: "sql", Algorithm: "rule:x", Action: action, URL: url, ClientIP: ip, Raw: "{}"}
	}
	batch := []*Alarm{}
	for i := 0; i < 30; i++ {
		batch = append(batch, mk(RandomHex(6), "http://h/api/item/"+strconv.Itoa(1000+i), []string{"log", "block"}[i%2], "10.0.0."+string(rune('1'+i%3)), now-int64(i)*1000))
	}
	batch = append(batch, mk("other", "http://h/admin/export", "log", "10.9.9.9", now))
	if err := st.InsertAlarms(batch); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertAlarms(batch[:5]); err != nil { // retried batch: no double counting
		t.Fatal(err)
	}
	list, total, err := st.QueryIncidents(IncidentQuery{})
	if err != nil || total != 2 {
		t.Fatalf("incidents = %d %v", total, err)
	}
	var item *Incident
	for _, in := range list {
		if in.PathPattern == "/api/item/{n}" {
			item = in
		}
	}
	if item == nil {
		t.Fatalf("no /api/item/{n} incident in %+v", list)
	}
	if item.Count != 30 || item.Blocked != 15 || item.FirstSeen != now-29000 || item.LastSeen != now || item.AppName != "shop" {
		t.Fatalf("aggregate = %+v", item)
	}
	if blocked, _, _ := st.QueryIncidents(IncidentQuery{Blocked: true}); len(blocked) != 1 {
		t.Fatalf("blocked filter = %d", len(blocked))
	}
	src, _ := st.IncidentSources(item.Fingerprint, 10)
	if len(src) != 3 || src[0].Count != 10 {
		t.Fatalf("sources = %+v", src)
	}
	alarms, n, _ := st.QueryAlarms(AlarmQuery{Fingerprint: item.Fingerprint, PageSize: 5})
	if n != 30 || len(alarms) != 5 || alarms[0].Fingerprint != item.Fingerprint {
		t.Fatalf("incident alarms = %d %d", n, len(alarms))
	}
	// bulk triage of the incident's alarms
	changed, err := st.SetIncidentStatus(item.Fingerprint, "fixed", true)
	if err != nil || changed != 30 {
		t.Fatalf("triage = %d %v", changed, err)
	}
	// a recurrence reopens a fixed incident
	_ = st.InsertAlarms([]*Alarm{mk("again", "http://h/api/item/99", "block", "10.0.0.5", now+5000)})
	in, _ := st.GetIncident(item.Fingerprint)
	if in.Status != "new" || in.Reopened != 1 || in.Count != 31 || in.LastEventID != "again" {
		t.Fatalf("reopen = %+v", in)
	}
	// ... but an incident judged a false positive stays so
	_, _ = st.SetIncidentStatus(item.Fingerprint, "false_positive", false)
	_ = st.InsertAlarms([]*Alarm{mk("again2", "http://h/api/item/100", "block", "10.0.0.5", now+6000)})
	if in, _ := st.GetIncident(item.Fingerprint); in.Status != "false_positive" {
		t.Fatalf("false positive reopened: %+v", in)
	}
	if _, err := st.SetIncidentStatus("nope", "fixed", false); err != ErrNotFound {
		t.Fatalf("unknown incident = %v", err)
	}
}

func TestIncidentBackfill(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UnixMilli()
	for i := 0; i < 2500; i++ { // simulate alarms stored before incidents existed
		if _, err := st.db.Exec(`INSERT INTO alarm(event_id, app_id, agent_id, event_time, received_at, attack_type, action, url, raw)
			VALUES(?,1,'x',?,?, 'ssrf', 'log', ?, '{}')`, RandomHex(8), now-int64(i), now, "http://h/fetch/"+string(rune('0'+i%10))); err != nil {
			t.Fatal(err)
		}
	}
	n, err := st.BackfillIncidents(1000)
	if err != nil || n != 2500 {
		t.Fatalf("backfill = %d %v", n, err)
	}
	list, total, _ := st.QueryIncidents(IncidentQuery{})
	if total != 1 || list[0].Count != 2500 || list[0].PathPattern != "/fetch/{n}" {
		t.Fatalf("after backfill = %d %+v", total, list)
	}
	if again, _ := st.BackfillIncidents(1000); again != 0 {
		t.Fatalf("second backfill = %d", again)
	}
}
