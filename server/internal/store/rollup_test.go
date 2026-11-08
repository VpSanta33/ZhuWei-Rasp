package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestAlarmRollupMatchesRawCounts(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	app := &App{Name: "a", Env: "prod", Policy: "{}"}
	_ = st.CreateApp(app)
	now := time.Now().UnixMilli()
	var batch []*Alarm
	for i := 0; i < 300; i++ {
		batch = append(batch, &Alarm{EventID: RandomHex(8), AppID: app.ID, AgentID: "x", EventTime: now - int64(i%5)*3600_000,
			AttackType: []string{"sql", "ssrf", "command"}[i%3], Action: []string{"log", "block"}[i%2], ClientIP: []string{"1.1.1.1", "2.2.2.2"}[i%2], Raw: "{}"})
	}
	if err := st.InsertAlarms(batch); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertAlarms(batch[:50]); err != nil { // agent retry: duplicates must not be counted
		t.Fatal(err)
	}
	since := now - 24*3600_000
	byType, _ := st.AlarmStats(since, "attack_type", 10)
	total := int64(0)
	for _, c := range byType {
		total += c.Count
	}
	if total != 300 || len(byType) != 3 || byType[0].Count != 100 {
		t.Fatalf("by type = %+v", byType)
	}
	if ips, _ := st.AlarmStats(since, "client_ip", 10); len(ips) != 2 || ips[0].Count != 150 {
		t.Fatalf("by ip = %+v", ips)
	}
	if apps, _ := st.AlarmStats(since, "app", 10); len(apps) != 1 || apps[0].Key != "a" || apps[0].Count != 300 {
		t.Fatalf("by app = %+v", apps)
	}
	// migration path: rebuild from raw rows gives the same numbers
	_, _ = st.db.Exec(`DELETE FROM alarm_rollup`)
	_ = st.SetSetting("alarm_rollup_v1", "")
	if err := st.backfillRollup(); err != nil {
		t.Fatal(err)
	}
	if again, _ := st.AlarmStats(since, "attack_type", 10); again[0].Count != 100 {
		t.Fatalf("backfill = %+v", again)
	}
	// retention removes old rollups together with old alarms (hour granularity at the cutoff)
	old := []*Alarm{{EventID: "old-1", AppID: app.ID, AgentID: "x", EventTime: now - 10*24*3600_000, AttackType: "jndi", Action: "log", Raw: "{}"}}
	_ = st.InsertAlarms(old)
	if all, _ := st.AlarmStats(0, "attack_type", 10); len(all) != 4 {
		t.Fatalf("before purge = %+v", all)
	}
	if n, err := st.PurgeAlarms(5 * 24 * time.Hour); err != nil || n != 1 {
		t.Fatalf("purge = %d %v", n, err)
	}
	left, _ := st.AlarmStats(0, "attack_type", 10)
	sum := int64(0)
	for _, c := range left {
		sum += c.Count
		if c.Key == "jndi" {
			t.Fatalf("purged alarm still counted: %+v", left)
		}
	}
	if sum != 300 {
		t.Fatalf("recent alarms after purge = %d", sum)
	}
}
