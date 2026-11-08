// Package ops provides health checks and Prometheus metrics (text exposition format, no dependencies).
package ops

import (
	"fmt"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Counter is a monotonically increasing value, optionally with one label.
type Counter struct {
	name, help, label string
	mu                sync.Mutex
	values            map[string]*atomic.Int64
}

var (
	registryMu sync.Mutex
	counters   []*Counter
	gauges     []gaugeFunc
	started    = time.Now()
)

type gaugeFunc struct {
	name, help string
	fn         func() map[string]float64 // label value ("" = unlabelled) -> value
	label      string
}

// NewCounter registers a counter; label may be "" for an unlabelled counter.
func NewCounter(name, help, label string) *Counter {
	c := &Counter{name: name, help: help, label: label, values: map[string]*atomic.Int64{}}
	registryMu.Lock()
	counters = append(counters, c)
	registryMu.Unlock()
	return c
}

func (c *Counter) Add(labelValue string, n int64) {
	c.mu.Lock()
	v := c.values[labelValue]
	if v == nil {
		v = &atomic.Int64{}
		c.values[labelValue] = v
	}
	c.mu.Unlock()
	v.Add(n)
}

func (c *Counter) Inc(labelValue string) { c.Add(labelValue, 1) }

// Gauge registers a value computed at scrape time.
func Gauge(name, help, label string, fn func() map[string]float64) {
	registryMu.Lock()
	gauges = append(gauges, gaugeFunc{name: name, help: help, label: label, fn: fn})
	registryMu.Unlock()
}

// Common counters shared across packages.
var (
	HTTPRequests   = NewCounter("rasp_http_requests_total", "HTTP requests by status class.", "code")
	AgentRequests  = NewCounter("rasp_agent_requests_total", "Agent API requests by endpoint.", "endpoint")
	AlarmsIngested = NewCounter("rasp_alarms_ingested_total", "Alarm events stored.", "")
	AlarmsDropped  = NewCounter("rasp_alarms_rate_limited_total", "Alarm events rejected by per-app rate limiting.", "")
	LoginFailures  = NewCounter("rasp_console_login_failures_total", "Failed console logins.", "")
)

func esc(v string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(v)
}

func writeSeries(b *strings.Builder, name, label, lv string, v float64) {
	if label == "" {
		fmt.Fprintf(b, "%s %v\n", name, v)
		return
	}
	fmt.Fprintf(b, "%s{%s=\"%s\"} %v\n", name, label, esc(lv), v)
}

// MetricsHandler serves all registered metrics plus process basics.
func MetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b strings.Builder
		registryMu.Lock()
		cs, gs := append([]*Counter(nil), counters...), append([]gaugeFunc(nil), gauges...)
		registryMu.Unlock()
		for _, c := range cs {
			fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n", c.name, c.help, c.name)
			c.mu.Lock()
			keys := make([]string, 0, len(c.values))
			for k := range c.values {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			if len(keys) == 0 && c.label == "" {
				fmt.Fprintf(&b, "%s 0\n", c.name)
			}
			for _, k := range keys {
				writeSeries(&b, c.name, c.label, k, float64(c.values[k].Load()))
			}
			c.mu.Unlock()
		}
		for _, g := range gs {
			fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n", g.name, g.help, g.name)
			vals := g.fn()
			keys := make([]string, 0, len(vals))
			for k := range vals {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				writeSeries(&b, g.name, g.label, k, vals[k])
			}
		}
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		fmt.Fprintf(&b, "# HELP rasp_process_uptime_seconds Seconds since start.\n# TYPE rasp_process_uptime_seconds gauge\nrasp_process_uptime_seconds %.0f\n", time.Since(started).Seconds())
		fmt.Fprintf(&b, "# HELP rasp_process_goroutines Goroutines.\n# TYPE rasp_process_goroutines gauge\nrasp_process_goroutines %d\n", runtime.NumGoroutine())
		fmt.Fprintf(&b, "# HELP rasp_process_heap_bytes Heap in use.\n# TYPE rasp_process_heap_bytes gauge\nrasp_process_heap_bytes %d\n", ms.HeapInuse)
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(b.String()))
	})
}

// CountStatus wraps a handler and counts responses by status class (2xx, 4xx, ...).
func CountStatus(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, code: 200}
		next.ServeHTTP(rec, r)
		HTTPRequests.Inc(fmt.Sprintf("%dxx", rec.code/100))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.code = code
	s.ResponseWriter.WriteHeader(code)
}

// Health registers /healthz (liveness: the process serves requests) and /readyz (readiness: ready returns nil).
func Health(mux *http.ServeMux, ready func() error) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if err := ready(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("not ready: " + err.Error() + "\n"))
			return
		}
		_, _ = w.Write([]byte("ready\n"))
	})
}
