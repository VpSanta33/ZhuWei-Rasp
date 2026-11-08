package agentapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"zhuwei-rasp/server/internal/store"
)

// Notifier pushes alarms to a webhook (WeCom/DingTalk/Feishu bots, SIEM collectors ...), aggregated per
// incident (docs 6.5.3): the first alarm of an incident is sent at once; further alarms of the same incident
// within the window are counted and summarised in one follow-up message when the window closes.
type Notifier struct {
	st     *store.Store
	client *http.Client
	queue  chan *store.Alarm
	window time.Duration
	post   func(text string, event any) // webhook sender; replaced in tests

	mu      sync.Mutex
	windows map[string]*incidentWindow
}

type incidentWindow struct {
	start      time.Time
	suppressed int
	blocked    int
	last       *store.Alarm
}

const notifyWindow = 5 * time.Minute

func NewNotifier(st *store.Store) *Notifier {
	n := &Notifier{st: st, client: &http.Client{Timeout: 5 * time.Second}, queue: make(chan *store.Alarm, 1000),
		window: notifyWindow, windows: map[string]*incidentWindow{}}
	n.post = n.Send
	go n.loop()
	go func() {
		for range time.Tick(30 * time.Second) {
			n.flush(time.Now())
		}
	}()
	return n
}

// Send posts a plain message (bot "text" format plus a machine-readable event) to the configured webhook.
func (n *Notifier) Send(text string, event any) {
	url := n.st.GetSetting("notify_webhook", "")
	if url == "" {
		return
	}
	body, _ := json.Marshal(map[string]any{"msgtype": "text", "text": map[string]string{"content": text}, "event": event})
	resp, err := n.client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("webhook notify failed: %v", err)
		return
	}
	resp.Body.Close()
}

// Alarm enqueues a stored alarm for notification; it never blocks ingestion.
func (n *Notifier) Alarm(a *store.Alarm) {
	select {
	case n.queue <- a:
	default: // drop rather than block ingestion
	}
}

func (n *Notifier) loop() {
	for a := range n.queue {
		n.handle(a, time.Now())
	}
}

func key(a *store.Alarm) string {
	if a.Fingerprint != "" {
		return a.Fingerprint
	}
	return a.AppName + "|" + a.AttackType + "|" + a.URL + "|" + a.Algorithm
}

// handle decides whether an alarm is announced now or folded into its incident's current window.
func (n *Notifier) handle(a *store.Alarm, now time.Time) {
	if n.st.GetSetting("notify_webhook", "") == "" {
		return
	}
	if n.st.GetSetting("notify_level", "block") == "block" && a.Action != "block" {
		return
	}
	k := key(a)
	n.mu.Lock()
	w := n.windows[k]
	if w != nil && now.Sub(w.start) < n.window {
		w.suppressed++
		if a.Action == "block" {
			w.blocked++
		}
		w.last = a
		n.mu.Unlock()
		return
	}
	var closing *incidentWindow
	if w != nil && w.suppressed > 0 {
		closing = w // window expired but not flushed yet: report it before the new first alarm
	}
	n.windows[k] = &incidentWindow{start: now}
	if len(n.windows) > 10_000 { // bound memory under a flood of distinct incidents
		n.windows = map[string]*incidentWindow{k: n.windows[k]}
	}
	n.mu.Unlock()
	if closing != nil {
		n.summary(closing)
	}
	text := "[ZhuWei-RASP] " + a.Action + " " + a.AttackType + " app=" + a.AppName + " host=" + a.Hostname +
		" url=" + a.URL + " ip=" + a.ClientIP + " reason=" + a.Reason
	if a.Fingerprint != "" {
		text += " incident=" + a.Fingerprint
	}
	n.post(text, a)
}

// flush sends summaries for windows that have closed and forgets idle ones.
func (n *Notifier) flush(now time.Time) {
	var due []*incidentWindow
	n.mu.Lock()
	for k, w := range n.windows {
		if now.Sub(w.start) >= n.window {
			if w.suppressed > 0 {
				due = append(due, w)
			}
			delete(n.windows, k)
		}
	}
	n.mu.Unlock()
	for _, w := range due {
		n.summary(w)
	}
}

func (n *Notifier) summary(w *incidentWindow) {
	a := w.last
	text := fmt.Sprintf("[ZhuWei-RASP] incident %s: %d more %s alarms (%d blocked) in the last %s, app=%s path=%s last ip=%s",
		a.Fingerprint, w.suppressed, a.AttackType, w.blocked, n.window, a.AppName, store.PathPattern(a.URL), a.ClientIP)
	n.post(text, map[string]any{"type": "incident_summary", "fingerprint": a.Fingerprint, "suppressed": w.suppressed,
		"blocked": w.blocked, "window_seconds": int(n.window.Seconds()), "last_alarm": a})
}
