package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecureFiles(t *testing.T) {
	dir := t.TempDir()
	key, db := filepath.Join(dir, "k"), filepath.Join(dir, "r.db")
	_ = os.WriteFile(key, []byte("x"), 0o644)
	_ = os.WriteFile(db, []byte("x"), 0o644)
	if err := secureFiles(key, db); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("world-readable key accepted: %v", err)
	}
	_ = os.Chmod(key, 0o600)
	if err := secureFiles(key, db); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(db); fi.Mode().Perm() != 0o600 {
		t.Fatalf("db mode = %v", fi.Mode().Perm())
	}
}

func TestConfigWarnings(t *testing.T) {
	if w := configWarnings("127.0.0.1:8480", "", "http://127.0.0.1:8480", "127.0.0.1:9480", "https://hook"); len(w) != 0 {
		t.Fatalf("local dev setup warned: %v", w)
	}
	w := configWarnings(":8480", "", "http://rasp.corp:8480", "0.0.0.0:9480", "http://hook")
	if len(w) != 4 {
		t.Fatalf("warnings = %v", w)
	}
	if w := configWarnings(":8443", "cert.pem", "https://rasp.corp:8443", "", ""); len(w) != 0 {
		t.Fatalf("TLS setup warned: %v", w)
	}
}
