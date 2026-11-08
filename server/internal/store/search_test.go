package store

import (
	"path/filepath"
	"testing"
	"time"
)

// The FTS path must return exactly what the old LIKE scan returned.
func TestAlarmKeywordSearchMatchesLike(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	app := &App{Name: "a", Env: "prod", Policy: "{}"}
	_ = st.CreateApp(app)
	now := time.Now().UnixMilli()
	rows := []struct{ url, ip, host, input string }{
		{"http://shop.local/api/item/7", "10.0.0.1", "web-01", "abcd"},
		{"http://shop.local/api/item/77", "10.0.0.2", "web-02", `say "hi"`},
		{"http://shop.local/Admin/Login", "192.168.1.10", "WEB-03", "user OR 1"},
		{"http://other.local/x", "10.0.0.17", "db-01", "订单编号查询"},
	}
	var batch []*Alarm
	for i, r := range rows {
		batch = append(batch, &Alarm{EventID: RandomHex(8), AppID: app.ID, AgentID: "x", EventTime: now - int64(i), AttackType: "sql",
			Action: "log", URL: r.url, ClientIP: r.ip, Hostname: r.host, MatchedInput: r.input, Raw: "{}"})
	}
	if err := st.InsertAlarms(batch); err != nil {
		t.Fatal(err)
	}
	// 3+ characters use the trigram index, shorter ones the LIKE fallback; FTS operators typed by a user
	// must be treated as literal text. The LIKE scan is the ground truth for every case.
	cases := []string{"item/7", "item/77", "admin/login", "10.0.0.1", "web-0", `"hi"`, "OR 1", "订单编号", "nothing-here",
		"77", "x", `" OR "`, "NEAR(", "*"}
	for _, kw := range cases {
		var want int
		like := "%" + kw + "%"
		_ = st.db.QueryRow(`SELECT COUNT(*) FROM alarm WHERE url LIKE ? OR client_ip LIKE ? OR hostname LIKE ? OR matched_input LIKE ?`,
			like, like, like, like).Scan(&want)
		_, got, err := st.QueryAlarms(AlarmQuery{Keyword: kw})
		if err != nil {
			t.Fatalf("search %q: %v", kw, err)
		}
		if got != want {
			t.Errorf("search %q: fts=%d like=%d", kw, got, want)
		}
	}
	// deletes (retention) keep the index in sync
	if _, err := st.db.Exec(`DELETE FROM alarm WHERE url LIKE '%item/77'`); err != nil {
		t.Fatal(err)
	}
	if _, got, _ := st.QueryAlarms(AlarmQuery{Keyword: "item/7"}); got != 1 {
		t.Errorf("after delete: %d", got)
	}
}
