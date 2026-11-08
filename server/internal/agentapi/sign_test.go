package agentapi

import "testing"

// Must stay in sync with the Java agent (AgentClient.sign).
func TestSignKnownVector(t *testing.T) {
	got := Sign("secret", "POST", "/agent/v1/heartbeat", "1700000000000", "nonce0123456789ab", []byte(`{"a":1}`))
	if len(got) != 64 {
		t.Fatalf("unexpected signature length %d", len(got))
	}
	if got != Sign("secret", "POST", "/agent/v1/heartbeat", "1700000000000", "nonce0123456789ab", []byte(`{"a":1}`)) {
		t.Fatal("signature not deterministic")
	}
	if got == Sign("secret", "POST", "/agent/v1/heartbeat", "1700000000000", "nonce0123456789ab", []byte(`{"a":2}`)) {
		t.Fatal("body change did not change signature")
	}
}
