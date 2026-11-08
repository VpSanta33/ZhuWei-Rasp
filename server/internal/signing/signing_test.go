package signing

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "k.pem")
	s1, created, err := LoadOrCreate(p)
	if err != nil || !created {
		t.Fatalf("create: %v %v", created, err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v", fi.Mode().Perm())
	}
	s2, created, err := LoadOrCreate(p)
	if err != nil || created {
		t.Fatalf("reload: %v %v", created, err)
	}
	if s1.KeyID() != s2.KeyID() || s1.PublicKey() != s2.PublicKey() {
		t.Fatal("reloaded key differs")
	}
	sig, err := s1.Sign([]byte(`{"mode":"block"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !s2.Verify([]byte(`{"mode":"block"}`), sig) {
		t.Fatal("signature does not verify")
	}
	if s2.Verify([]byte(`{"mode":"off"}`), sig) {
		t.Fatal("tampered payload verified")
	}
	if _, err := os.Stat(p + ".pub"); err != nil {
		t.Fatal("public key file missing")
	}
}

func TestRejectsWrongKeyType(t *testing.T) {
	p := filepath.Join(t.TempDir(), "k.pem")
	_ = os.WriteFile(p, []byte("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n"), 0o600)
	if _, _, err := LoadOrCreate(p); err == nil {
		t.Fatal("expected error")
	}
}
