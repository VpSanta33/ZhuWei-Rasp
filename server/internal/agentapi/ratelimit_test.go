package agentapi

import (
	"testing"
	"time"
)

func TestAlarmRateLimit(t *testing.T) {
	a := &API{AlarmRate: 10} // burst 100
	if got := a.take(1, 80); got != 80 {
		t.Fatalf("first batch = %d", got)
	}
	if got := a.take(1, 80); got != 20 {
		t.Fatalf("burst exhausted = %d, want 20", got)
	}
	if got := a.take(2, 50); got != 50 {
		t.Fatalf("other app has its own bucket = %d", got)
	}
	a.buckets[1].last = a.buckets[1].last.Add(-2 * time.Second) // 2 s later: 20 tokens refilled
	if got := a.take(1, 100); got != 20 {
		t.Fatalf("refill = %d, want 20", got)
	}
	if got := (&API{}).take(1, 1_000_000); got != 1_000_000 {
		t.Fatalf("disabled limit = %d", got)
	}
}
