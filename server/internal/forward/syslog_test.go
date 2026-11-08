package forward

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"zhuwei-rasp/server/internal/store"
)

var header = regexp.MustCompile(`^<(\d+)>1 \d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z \S+ zhuwei-rasp \d+ (alarm|audit) - (.*)$`)

// accept waits for one connection, failing the test instead of hanging.
func accept(t *testing.T, ln net.Listener) net.Conn {
	t.Helper()
	ch := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			ch <- c
		}
	}()
	select {
	case c := <-ch:
		return c
	case <-time.After(10 * time.Second):
		t.Fatal("no connection from the forwarder within 10s")
		return nil
	}
}

// readFrames reads RFC 6587 octet-counted frames.
func readFrames(t *testing.T, c net.Conn, n int) []string {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(c)
	var out []string
	for len(out) < n {
		lenStr, err := r.ReadString(' ')
		if err != nil {
			t.Fatalf("frame length: %v (got %d frames)", err, len(out))
		}
		size, err := strconv.Atoi(strings.TrimSpace(lenStr))
		if err != nil {
			t.Fatalf("bad frame length %q", lenStr)
		}
		buf := make([]byte, size)
		if _, err := io.ReadFull(r, buf); err != nil {
			t.Fatal(err)
		}
		out = append(out, string(buf))
	}
	return out
}

var hostile = &store.Alarm{EventID: "ev-1", EventTime: 1_700_000_000_123, AppName: "shop|prod", AppID: 1, Hostname: "web-01",
	AttackType: "sql", Algorithm: "rule:sql-user-input", Action: "block", Confidence: 40,
	URL: "http://h/api?q=1", ClientIP: "203.0.113.7", Reason: "SQL text | contains input", MatchedInput: "a=b\\c\nd", Fingerprint: "fp1"}

func TestTCPJSONAndAudit(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	f, err := New(Config{Addr: ln.Addr().String(), Protocol: "tcp", Format: "json", Version: "0.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	f.Alarm(hostile)
	f.Audit(store.Audit{At: 1_700_000_000_000, User: "root", Action: "update_policy", Target: "shop/prod", Detail: "mode=block"})
	c := accept(t, ln)
	defer c.Close()
	frames := readFrames(t, c, 2)
	m := header.FindStringSubmatch(frames[0])
	if m == nil || m[1] != strconv.Itoa(20*8+3) || m[2] != "alarm" {
		t.Fatalf("alarm header: %q", frames[0])
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(m[3]), &payload); err != nil || payload["incident"] != "fp1" || payload["matched_input"] != "a=b\\c\nd" {
		t.Fatalf("alarm payload %v: %v", err, payload)
	}
	m = header.FindStringSubmatch(frames[1])
	if m == nil || m[1] != strconv.Itoa(20*8+6) || m[2] != "audit" || !strings.Contains(m[3], `"action":"update_policy"`) {
		t.Fatalf("audit frame: %q", frames[1])
	}
}

func TestCEFEscaping(t *testing.T) {
	cef := alarmCEF(hostile, "0.1.0")
	// header: 7 unescaped pipes; the pipe inside the reason is escaped
	if !strings.HasPrefix(cef, `CEF:0|ZhuWei|RASP|0.1.0|sql|SQL text \| contains input|8|`) {
		t.Fatalf("header = %q", cef)
	}
	ext := cef[strings.LastIndex(cef, "|8|")+3:]
	for _, want := range []string{"act=blocked", "src=203.0.113.7", `cs1=shop|prod`, `cs4=a\=b\\c\nd`, "rt=1700000000123", "cs2=fp1", "externalId=ev-1"} {
		if !strings.Contains(ext, want) {
			t.Errorf("extension lacks %q: %s", want, ext)
		}
	}
	if strings.Contains(cef, "\n") {
		t.Error("raw newline in CEF record")
	}
	low := *hostile
	low.Action, low.Confidence = "log", 85
	if !strings.Contains(alarmCEF(&low, "x"), "|7|") {
		t.Error("severity for logged high-confidence alarm")
	}
}

func TestUDPAndLevelFilter(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	f, err := New(Config{Addr: pc.LocalAddr().String(), Protocol: "udp", Format: "cef", Level: "block"})
	if err != nil {
		t.Fatal(err)
	}
	logged := *hostile
	logged.Action, logged.EventID = "log", "ev-log"
	f.Alarm(&logged) // filtered out by Level=block
	f.Alarm(hostile)
	buf := make([]byte, 65535)
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	msg := string(buf[:n])
	if !strings.Contains(msg, "externalId=ev-1") || strings.Contains(msg, "ev-log") || !header.MatchString(msg) {
		t.Fatalf("udp datagram: %q", msg)
	}
}

func selfSigned(t *testing.T, dir string) (tls.Certificate, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, caFile
}

func TestTLSAndReconnect(t *testing.T) {
	dir := t.TempDir()
	cert, caFile := selfSigned(t, dir)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	f, err := New(Config{Addr: addr, Protocol: "tls", CAFile: caFile})
	if err != nil {
		t.Fatal(err)
	}
	f.Alarm(hostile)
	c := accept(t, ln)
	if fr := readFrames(t, c, 1); !strings.Contains(fr[0], `"event_id":"ev-1"`) {
		t.Fatalf("tls frame %q", fr[0])
	}
	// the SIEM restarts: the forwarder reconnects and keeps delivering
	c.Close()
	ln.Close()
	ln2, err := tls.Listen("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Skipf("cannot rebind %s: %v", addr, err)
	}
	defer ln2.Close()
	time.Sleep(1100 * time.Millisecond) // idle long enough for the liveness probe
	second := *hostile
	second.EventID = "ev-2"
	f.Alarm(&second) // exactly one message: it must not be lost in the dead connection
	c2 := accept(t, ln2)
	defer c2.Close()
	if fr := readFrames(t, c2, 1); !strings.Contains(fr[0], `"event_id":"ev-2"`) {
		t.Fatalf("after reconnect %q", fr[0])
	}
}

func TestUntrustedCertificateRefused(t *testing.T) {
	cert, _ := selfSigned(t, t.TempDir())
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	f, _ := New(Config{Addr: ln.Addr().String(), Protocol: "tls"}) // system roots only: must not trust the test CA
	if _, err := f.dial(); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("untrusted certificate accepted: %v", err)
	}
}

func TestValidate(t *testing.T) {
	for _, c := range []Config{{Addr: "nohost"}, {Addr: "h:514", Protocol: "smtp"}, {Addr: "h:514", Format: "xml"}, {Addr: "h:514", Level: "some"}} {
		if err := c.Validate(); err == nil {
			t.Errorf("Validate(%+v) should fail", c)
		}
	}
}
