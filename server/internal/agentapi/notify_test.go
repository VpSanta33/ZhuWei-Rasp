package agentapi

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"zhuwei-rasp/server/internal/store"
)

func TestNotifierAggregatesPerIncident(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_ = st.SetSetting("notify_webhook", "http://example.invalid/hook")
	var sent []string
	n := &Notifier{st: st, window: time.Minute, windows: map[string]*incidentWindow{}}
	n.post = func(text string, _ any) { sent = append(sent, text) }
	t0 := time.Now()
	alarm := func(fp, action string) *store.Alarm {
		return &store.Alarm{Fingerprint: fp, Action: action, AttackType: "sql", AppName: "shop", URL: "http://h/api/item/7", ClientIP: "10.0.0.1"}
	}
	for i := 0; i < 10; i++ {
		n.handle(alarm("fp1", "block"), t0.Add(time.Duration(i)*time.Second))
	}
	n.handle(alarm("fp2", "block"), t0)
	n.handle(alarm("fp3", "log"), t0) // notify_level=block: log-only alarms are not sent
	if len(sent) != 2 || !strings.Contains(sent[0], "incident=fp1") || !strings.Contains(sent[1], "incident=fp2") {
		t.Fatalf("immediate notifications = %q", sent)
	}
	n.flush(t0.Add(30 * time.Second)) // window still open
	if len(sent) != 2 {
		t.Fatalf("early flush sent %q", sent[2:])
	}
	n.flush(t0.Add(61 * time.Second))
	if len(sent) != 3 || !strings.Contains(sent[2], "incident fp1: 9 more sql alarms (9 blocked)") || !strings.Contains(sent[2], "path=/api/item/{n}") {
		t.Fatalf("summary = %q", sent)
	}
	// a new window starts with an immediate notification again
	n.handle(alarm("fp1", "block"), t0.Add(2*time.Minute))
	if len(sent) != 4 || !strings.Contains(sent[3], "incident=fp1") {
		t.Fatalf("new window = %q", sent)
	}
}
