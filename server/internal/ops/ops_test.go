package ops

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsExposition(t *testing.T) {
	c := NewCounter("test_events_total", "Test.", "kind")
	c.Inc(`a"b`)
	c.Add("x", 3)
	Gauge("test_gauge", "Gauge.", "", func() map[string]float64 { return map[string]float64{"": 1.5} })
	rec := httptest.NewRecorder()
	MetricsHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{"# TYPE test_events_total counter", `test_events_total{kind="a\"b"} 1`, `test_events_total{kind="x"} 3`,
		"test_gauge 1.5", "rasp_alarms_ingested_total 0", "rasp_process_uptime_seconds"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in\n%s", want, body)
		}
	}
	mux := http.NewServeMux()
	ok := true
	Health(mux, func() error {
		if ok {
			return nil
		}
		return http.ErrServerClosed
	})
	for _, tc := range []struct {
		ready bool
		code  int
	}{{true, 200}, {false, 503}} {
		ok = tc.ready
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
		if rec.Code != tc.code {
			t.Errorf("readyz(ready=%v) = %d", tc.ready, rec.Code)
		}
	}
}
