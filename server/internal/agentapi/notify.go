package agentapi

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"zhuwei-rasp/server/internal/store"
)

// Notifier pushes alarms to a webhook (WeCom/DingTalk/Feishu bots, SIEM collectors ...).
// Same fingerprint (app + type + url + algorithm) is sent at most once per 5 minutes.
type Notifier struct {
	st     *store.Store
	client *http.Client
	queue  chan *store.Alarm
	mu     sync.Mutex
	seen   map[string]time.Time
}

func NewNotifier(st *store.Store) *Notifier {
	n := &Notifier{st: st, client: &http.Client{Timeout: 5 * time.Second}, queue: make(chan *store.Alarm, 1000), seen: map[string]time.Time{}}
	go n.loop()
	return n
}

func (n *Notifier) Alarm(a *store.Alarm) {
	select {
	case n.queue <- a:
	default: // drop rather than block ingestion
	}
}

func (n *Notifier) loop() {
	for a := range n.queue {
		url := n.st.GetSetting("notify_webhook", "")
		if url == "" {
			continue
		}
		if n.st.GetSetting("notify_level", "block") == "block" && a.Action != "block" {
			continue
		}
		key := a.AppName + "|" + a.AttackType + "|" + a.URL + "|" + a.Algorithm
		n.mu.Lock()
		last, dup := n.seen[key]
		if dup && time.Since(last) < 5*time.Minute {
			n.mu.Unlock()
			continue
		}
		n.seen[key] = time.Now()
		if len(n.seen) > 10000 {
			n.seen = map[string]time.Time{}
		}
		n.mu.Unlock()

		text := "[ZhuWei-RASP] " + a.Action + " " + a.AttackType + " app=" + a.AppName + " host=" + a.Hostname +
			" url=" + a.URL + " ip=" + a.ClientIP + " reason=" + a.Reason
		body, _ := json.Marshal(map[string]any{
			"msgtype": "text", "text": map[string]string{"content": text}, // WeCom / DingTalk bot format
			"event": a,
		})
		resp, err := n.client.Post(url, "application/json", bytes.NewReader(body))
		if err != nil {
			log.Printf("webhook notify failed: %v", err)
			continue
		}
		resp.Body.Close()
	}
}
