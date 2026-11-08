// Package forward ships alarms and audit records to a SIEM over syslog (RFC 5424), with a JSON or CEF payload.
//
// Transport: TCP or TLS with octet-counted framing (RFC 6587), or UDP (one message per datagram). Delivery
// runs on a background goroutine with a bounded queue; ingestion is never blocked, overflow is dropped and
// counted (rasp_siem_dropped_total).
package forward

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"zhuwei-rasp/server/internal/ops"
	"zhuwei-rasp/server/internal/store"
)

type Config struct {
	Addr     string // host:port
	Protocol string // tcp (default), tls, udp
	Format   string // json (default) or cef
	CAFile   string // PEM bundle for a private CA (tls)
	Level    string // all (default) or block: which alarms to forward; audit records are always sent
	Version  string // product version in CEF headers
}

var (
	forwarded = ops.NewCounter("rasp_siem_forwarded_total", "Records delivered to the SIEM.", "kind")
	dropped   = ops.NewCounter("rasp_siem_dropped_total", "Records dropped (queue full or delivery failed).", "kind")
)

// syslog facility local4 (20); severities: 3 error (blocked attack), 4 warning (logged attack), 6 info (audit)
const facility = 20

type record struct {
	kind     string // alarm | audit
	msgID    string
	severity int
	at       time.Time
	payload  string
}

type Forwarder struct {
	cfg      Config
	hostname string
	queue    chan record
	dial     func() (net.Conn, error)
}

// Validate checks the configuration at start-up.
func (c *Config) Validate() error {
	if _, _, err := net.SplitHostPort(c.Addr); err != nil {
		return fmt.Errorf("syslog address must be host:port: %w", err)
	}
	switch c.Protocol {
	case "", "tcp", "tls", "udp":
	default:
		return fmt.Errorf("syslog protocol must be tcp, tls or udp")
	}
	switch c.Format {
	case "", "json", "cef":
	default:
		return fmt.Errorf("syslog format must be json or cef")
	}
	switch c.Level {
	case "", "all", "block":
	default:
		return fmt.Errorf("syslog level must be all or block")
	}
	return nil
}

// New starts the delivery goroutine.
func New(cfg Config) (*Forwarder, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.Protocol == "" {
		cfg.Protocol = "tcp"
	}
	if cfg.Format == "" {
		cfg.Format = "json"
	}
	host, _ := os.Hostname()
	f := &Forwarder{cfg: cfg, hostname: sanitize(host, 255), queue: make(chan record, 10_000)}
	var tlsCfg *tls.Config
	if cfg.Protocol == "tls" {
		h, _, _ := net.SplitHostPort(cfg.Addr)
		tlsCfg = &tls.Config{ServerName: h, MinVersion: tls.VersionTLS12}
		if cfg.CAFile != "" {
			pem, err := os.ReadFile(cfg.CAFile)
			if err != nil {
				return nil, err
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("no certificates in %s", cfg.CAFile)
			}
			tlsCfg.RootCAs = pool
		}
	}
	f.dial = func() (net.Conn, error) {
		d := &net.Dialer{Timeout: 10 * time.Second}
		switch cfg.Protocol {
		case "udp":
			return d.Dial("udp", cfg.Addr)
		case "tls":
			return tls.DialWithDialer(d, "tcp", cfg.Addr, tlsCfg)
		}
		return d.Dial("tcp", cfg.Addr)
	}
	go f.loop()
	return f, nil
}

func (f *Forwarder) enqueue(r record) {
	select {
	case f.queue <- r:
	default:
		dropped.Inc(r.kind)
	}
}

// Alarm forwards one stored alarm (subject to Level).
func (f *Forwarder) Alarm(a *store.Alarm) {
	if f.cfg.Level == "block" && a.Action != "block" {
		return
	}
	sev := 4
	if a.Action == "block" {
		sev = 3
	}
	at := time.UnixMilli(a.EventTime)
	var payload string
	if f.cfg.Format == "cef" {
		payload = alarmCEF(a, f.cfg.Version)
	} else {
		b, _ := json.Marshal(map[string]any{"type": "alarm", "event_id": a.EventID, "event_time": a.EventTime, "app": a.AppName,
			"app_id": a.AppID, "agent_id": a.AgentID, "host": a.Hostname, "attack_type": a.AttackType, "algorithm": a.Algorithm,
			"action": a.Action, "confidence": a.Confidence, "url": a.URL, "client_ip": a.ClientIP, "reason": a.Reason,
			"matched_input": a.MatchedInput, "incident": a.Fingerprint})
		payload = string(b)
	}
	f.enqueue(record{kind: "alarm", msgID: "alarm", severity: sev, at: at, payload: payload})
}

// Audit forwards one administrative audit record.
func (f *Forwarder) Audit(a store.Audit) {
	var payload string
	if f.cfg.Format == "cef" {
		payload = fmt.Sprintf("CEF:0|ZhuWei|RASP|%s|audit:%s|%s|3|rt=%d suser=%s act=%s msg=%s",
			cefHeader(f.cfg.Version), cefHeader(a.Action), cefHeader(a.Action), a.At, cefExt(a.User), cefExt(a.Action),
			cefExt(strings.TrimSpace(a.Target+" "+a.Detail)))
	} else {
		b, _ := json.Marshal(map[string]any{"type": "audit", "at": a.At, "user": a.User, "action": a.Action, "target": a.Target, "detail": a.Detail})
		payload = string(b)
	}
	f.enqueue(record{kind: "audit", msgID: "audit", severity: 6, at: time.UnixMilli(a.At), payload: payload})
}

// format renders an RFC 5424 message: <PRI>1 TIMESTAMP HOST APP PROCID MSGID - MSG
func (f *Forwarder) format(r record) string {
	return fmt.Sprintf("<%d>1 %s %s zhuwei-rasp %d %s - %s", facility*8+r.severity,
		r.at.UTC().Format("2006-01-02T15:04:05.000Z"), f.hostname, os.Getpid(), r.msgID, r.payload)
}

// alive probes an idle stream connection: a peer that closed (SIEM restart) shows up as EOF, while a live
// one just times out. Without this, the first writes after a restart land in the dead socket's buffer
// and are lost silently.
func alive(c net.Conn) bool {
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
	var b [1]byte
	_, err := c.Read(b[:])
	_ = c.SetReadDeadline(time.Time{})
	if err == nil {
		return true // the receiver sent something; syslog receivers normally do not, but the link is up
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return false
}

func (f *Forwarder) loop() {
	var conn net.Conn
	var lastWrite time.Time
	backoff := time.Second
	for r := range f.queue {
		msg := f.format(r)
		if f.cfg.Protocol == "udp" && len(msg) > 8192 {
			msg = msg[:8192] // keep datagrams deliverable; TCP/TLS carry full messages
		}
		frame := msg
		if f.cfg.Protocol != "udp" {
			frame = strconv.Itoa(len(msg)) + " " + msg // RFC 6587 octet counting
		}
		sent := false
		for attempt := 0; attempt < 2 && !sent; attempt++ {
			if conn != nil && f.cfg.Protocol != "udp" && time.Since(lastWrite) > time.Second && !alive(conn) {
				conn.Close()
				conn = nil
			}
			if conn == nil {
				c, err := f.dial()
				if err != nil {
					log.Printf("siem: connect %s: %v", f.cfg.Addr, err)
					time.Sleep(backoff)
					backoff = min(backoff*2, time.Minute)
					continue
				}
				conn, backoff = c, time.Second
			}
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := conn.Write([]byte(frame)); err != nil {
				log.Printf("siem: write: %v", err)
				conn.Close()
				conn = nil
				continue
			}
			sent, lastWrite = true, time.Now()
		}
		if sent {
			forwarded.Inc(r.kind)
		} else {
			dropped.Inc(r.kind)
		}
	}
}

// ------------------------------------------------------------------ CEF

func cefSeverity(a *store.Alarm) int {
	if a.Action == "block" {
		return 8
	}
	switch {
	case a.Confidence >= 80:
		return 7
	case a.Confidence >= 50:
		return 5
	}
	return 3
}

// cefHeader escapes header fields (pipe and backslash).
func cefHeader(s string) string {
	return strings.NewReplacer(`\`, `\\`, `|`, `\|`, "\n", " ", "\r", " ").Replace(s)
}

// cefExt escapes extension values (backslash, equals sign, line breaks).
func cefExt(s string) string {
	return strings.NewReplacer(`\`, `\\`, `=`, `\=`, "\n", `\n`, "\r", `\r`).Replace(s)
}

func alarmCEF(a *store.Alarm, version string) string {
	act := "logged"
	if a.Action == "block" {
		act = "blocked"
	}
	name := a.Reason
	if name == "" {
		name = a.AttackType
	}
	ext := []string{
		"rt=" + strconv.FormatInt(a.EventTime, 10),
		"src=" + cefExt(a.ClientIP),
		"dhost=" + cefExt(a.Hostname),
		"request=" + cefExt(a.URL),
		"act=" + act,
		"cs1Label=app", "cs1=" + cefExt(a.AppName),
		"cs2Label=incident", "cs2=" + cefExt(a.Fingerprint),
		"cs3Label=algorithm", "cs3=" + cefExt(a.Algorithm),
		"cs4Label=matchedInput", "cs4=" + cefExt(truncate(a.MatchedInput, 1024)),
		"cn1Label=confidence", "cn1=" + strconv.FormatInt(a.Confidence, 10),
		"externalId=" + cefExt(a.EventID),
	}
	return fmt.Sprintf("CEF:0|ZhuWei|RASP|%s|%s|%s|%d|%s", cefHeader(version), cefHeader(a.AttackType), cefHeader(truncate(name, 256)),
		cefSeverity(a), strings.Join(ext, " "))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// sanitize keeps a syslog header field printable ASCII without spaces.
func sanitize(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		if r > 32 && r < 127 {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "-"
	}
	return truncate(b.String(), n)
}
