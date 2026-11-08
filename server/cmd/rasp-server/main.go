// Command rasp-server is the ZhuWei-RASP management server: agent API, console API and web console
// in one binary (the MVP form of docs chapter 3; services can be split later along the same packages).
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"zhuwei-rasp/server/internal/agentapi"
	"zhuwei-rasp/server/internal/console"
	"zhuwei-rasp/server/internal/httpx"
	"zhuwei-rasp/server/internal/ldapauth"
	"zhuwei-rasp/server/internal/ops"
	"zhuwei-rasp/server/internal/signing"
	"zhuwei-rasp/server/internal/store"
	"zhuwei-rasp/server/internal/vuln"
	"zhuwei-rasp/server/web"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "import-osv":
			importOSV(os.Args[2:])
			return
		case "user":
			userCmd(os.Args[2:])
			return
		case "backup":
			backupCmd(os.Args[2:])
			return
		}
	}
	listen := flag.String("listen", envOr("RASP_LISTEN", ":8080"), "listen address")
	dbPath := flag.String("db", envOr("RASP_DB", "rasp.db"), "SQLite database file")
	adminUser := flag.String("admin-user", envOr("RASP_ADMIN_USER", "admin"), "name of the first admin, created on an empty database")
	agentURL := flag.String("agent-url", envOr("RASP_AGENT_URL", ""), "URL agents use to reach this server (for install snippets)")
	tlsCert := flag.String("tls-cert", envOr("RASP_TLS_CERT", ""), "TLS certificate file (enables HTTPS)")
	tlsKey := flag.String("tls-key", envOr("RASP_TLS_KEY", ""), "TLS key file")
	opsListen := flag.String("ops-listen", envOr("RASP_OPS_LISTEN", ""), "internal listener for /metrics, /healthz and /readyz (e.g. 127.0.0.1:9480); empty = off")
	alarmRate := flag.Float64("alarm-rate", envFloat("RASP_ALARM_RATE", 100), "alarm events per second accepted per application (burst 10x); 0 = unlimited")
	ldapCfg := &ldapauth.Config{}
	flag.StringVar(&ldapCfg.URL, "ldap-url", envOr("RASP_LDAP_URL", ""), "LDAP/AD server for console login, e.g. ldaps://ldap.corp:636 (empty = local accounts only)")
	flag.BoolVar(&ldapCfg.StartTLS, "ldap-starttls", envOr("RASP_LDAP_STARTTLS", "") == "true", "upgrade ldap:// connections with StartTLS")
	flag.StringVar(&ldapCfg.CAFile, "ldap-ca", envOr("RASP_LDAP_CA", ""), "PEM CA bundle for the LDAP server certificate")
	flag.StringVar(&ldapCfg.BindDN, "ldap-bind-dn", envOr("RASP_LDAP_BIND_DN", ""), "service account DN for user lookups (password from RASP_LDAP_BIND_PASSWORD)")
	flag.StringVar(&ldapCfg.BaseDN, "ldap-base-dn", envOr("RASP_LDAP_BASE_DN", ""), "base DN of user entries")
	flag.StringVar(&ldapCfg.UserAttr, "ldap-user-attr", envOr("RASP_LDAP_USER_ATTR", "uid"), "login name attribute (uid; sAMAccountName for AD)")
	flag.StringVar(&ldapCfg.AdminGroup, "ldap-admin-group", envOr("RASP_LDAP_ADMIN_GROUP", ""), "group DN mapped to the admin role")
	flag.StringVar(&ldapCfg.OperatorGroup, "ldap-operator-group", envOr("RASP_LDAP_OPERATOR_GROUP", ""), "group DN mapped to the operator role")
	flag.StringVar(&ldapCfg.ViewerGroup, "ldap-viewer-group", envOr("RASP_LDAP_VIEWER_GROUP", ""), "group DN mapped to the viewer role")
	osvURL := flag.String("osv-url", envOr("RASP_OSV_URL", ""), "download OSV advisories from this URL periodically, e.g. https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip (empty = off; import offline with `rasp-server import-osv`)")
	osvEvery := flag.Duration("osv-interval", 24*time.Hour, "interval for -osv-url updates")
	signKey := flag.String("sign-key", envOr("RASP_SIGN_KEY", ""), "policy signing key (PKCS#8 PEM, ECDSA P-256; default <db dir>/rasp-sign.key, created if missing)")
	flag.Parse()
	ldapCfg.BindPassword = os.Getenv("RASP_LDAP_BIND_PASSWORD") // never a flag: it would show in ps
	if ldapCfg.Enabled() {
		if err := ldapCfg.Validate(); err != nil {
			log.Fatalf("ldap: %v", err)
		}
		log.Printf("console login: local accounts, then LDAP %s (users looked up by %s under %s)", ldapCfg.URL, ldapCfg.UserAttr, ldapCfg.BaseDN)
	}
	if *signKey == "" {
		*signKey = filepath.Join(filepath.Dir(*dbPath), "rasp-sign.key")
	}
	signer, created, err := signing.LoadOrCreate(*signKey)
	if err != nil {
		log.Fatalf("policy signing key: %v", err)
	}
	if created {
		log.Printf("generated policy signing key %s (back it up; agents pin its public key)", *signKey)
	}
	log.Printf("policy signing key id=%s public key: %s", signer.KeyID(), *signKey+".pub")

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer st.Close()
	bootstrapAdmin(st, *adminUser)
	if err := secureFiles(*signKey, *dbPath); err != nil {
		log.Fatal(err)
	}

	if *agentURL == "" {
		scheme := "http"
		if *tlsCert != "" {
			scheme = "https"
		}
		*agentURL = fmt.Sprintf("%s://<this-server-host>%s", scheme, *listen)
	}

	mux := http.NewServeMux()
	notifier := agentapi.NewNotifier(st)
	vulns := vuln.NewService(st, notifier.Send)
	agents := agentapi.New(st, notifier, signer)
	agents.OnDependencies = vulns.Trigger
	agents.AlarmRate = *alarmRate
	agents.Register(mux)
	consoleAPI := console.New(st, *agentURL, signer)
	consoleAPI.Vulns = vulns
	if ldapCfg.Enabled() {
		consoleAPI.LDAP = ldapCfg
	}
	consoleAPI.Register(mux)
	vulns.Trigger() // match components already in the database against the current advisories
	if *osvURL != "" {
		if !strings.HasPrefix(*osvURL, "https://") {
			log.Fatalf("-osv-url must use https://")
		}
		if *osvEvery < time.Hour {
			*osvEvery = time.Hour
		}
		log.Printf("vulnerability data: automatic update from %s every %s", *osvURL, *osvEvery)
		vulns.StartAutoUpdate(*osvURL, *osvEvery, func(detail string) { st.AddAudit("system", "import_vulns", *osvURL, detail) })
	}
	warnings := configWarnings(*listen, *tlsCert, *agentURL, *opsListen, st.GetSetting("notify_webhook", ""))
	if ldapCfg.Enabled() && !ldapCfg.Encrypted() {
		warnings = append(warnings, "LDAP connection is not encrypted (use ldaps:// or -ldap-starttls): user passwords would be sent in clear text")
	}
	for _, w := range warnings {
		log.Printf("CONFIG WARNING: %s", w)
	}
	ready := func() error { return st.Ping() }
	ops.Health(mux, ready)
	registerGauges(st)
	if *opsListen != "" {
		opsMux := http.NewServeMux()
		ops.Health(opsMux, ready)
		opsMux.Handle("GET /metrics", ops.MetricsHandler())
		go func() {
			log.Printf("ops endpoints (/metrics, /healthz, /readyz) on %s", *opsListen)
			if err := http.ListenAndServe(*opsListen, opsMux); err != nil {
				log.Fatalf("ops listener: %v", err)
			}
		}()
	}
	mux.Handle("GET /", http.FileServerFS(web.FS))

	go housekeeping(st)

	srv := &http.Server{
		Addr:              *listen,
		Handler:           ops.CountStatus(httpx.Recover(securityHeaders(mux))),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		log.Printf("ZhuWei-RASP server listening on %s (db=%s)", *listen, *dbPath)
		var err error
		if *tlsCert != "" {
			err = srv.ListenAndServeTLS(*tlsCert, *tlsKey)
		} else {
			log.Printf("WARNING: plain HTTP. Use -tls-cert/-tls-key or a TLS-terminating proxy in production")
			err = srv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	log.Printf("server stopped")
}

// housekeeping purges old alarms and long-offline instances once an hour.
func housekeeping(st *store.Store) {
	for {
		days, err := strconv.Atoi(st.GetSetting("alarm_retention_days", "180"))
		if err != nil || days < 1 {
			days = 180
		}
		if n, err := st.PurgeAlarms(time.Duration(days) * 24 * time.Hour); err == nil && n > 0 {
			log.Printf("purged %d alarms older than %d days", n, days)
		}
		if n, err := st.PurgeExpiredTokens(); err == nil && n > 0 {
			log.Printf("purged %d expired console sessions/tokens", n)
		}
		if n, err := st.PurgeInstances(7 * 24 * time.Hour); err == nil && n > 0 {
			log.Printf("purged %d instances offline for more than 7 days", n)
		}
		time.Sleep(time.Hour)
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'")
		next.ServeHTTP(w, r)
	})
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// importOSV implements `rasp-server import-osv [-db rasp.db] <export.zip|advisory.json|dir> ...`: offline import
// of OSV advisories (e.g. https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip) followed by a rematch.
// It can run while the server is up (SQLite WAL); new findings are announced on the configured webhook.
func importOSV(args []string) {
	fset := flag.NewFlagSet("import-osv", flag.ExitOnError)
	dbPath := fset.String("db", envOr("RASP_DB", "rasp.db"), "SQLite database file")
	fset.Usage = func() {
		fmt.Fprintln(fset.Output(), "usage: rasp-server import-osv [-db rasp.db] <export.zip|advisory.json|directory> ...")
		fset.PrintDefaults()
	}
	_ = fset.Parse(args)
	if fset.NArg() == 0 {
		fset.Usage()
		os.Exit(2)
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer st.Close()
	svc := vuln.NewService(st, agentapi.NewNotifier(st).Send)
	for _, path := range fset.Args() {
		res, err := svc.ImportPath(path)
		if err != nil {
			log.Fatalf("import %s: %v", path, err)
		}
		st.AddAudit("cli", "import_vulns", res.Source, fmt.Sprintf("documents=%d inserted=%d updated=%d withdrawn=%d findings=%d new=%d",
			res.Files, res.Store.Inserted, res.Store.Updated, res.Store.Withdrawn, res.Match.Findings, res.Match.NewFindings))
		fmt.Printf("%s: %d documents (%d skipped), %d inserted, %d updated, %d unchanged, %d withdrawn; "+
			"%d components checked, %d findings (%d new)\n", path, res.Files, res.Skipped, res.Store.Inserted, res.Store.Updated,
			res.Store.Unchanged, res.Store.Withdrawn, res.Match.Components, res.Match.Findings, res.Match.NewFindings)
		for _, e := range res.Errors {
			fmt.Println("  warning:", e)
		}
	}
}

// bootstrapAdmin creates the first admin on an empty database. Its password comes from RASP_ADMIN_PASSWORD
// (at least 12 characters) or is generated and printed once. Afterwards accounts are managed in the console
// API or with `rasp-server user`, and RASP_ADMIN_PASSWORD is ignored.
func bootstrapAdmin(st *store.Store, name string) {
	n, err := st.CountUsers()
	if err != nil {
		log.Fatalf("count users: %v", err)
	}
	pass := os.Getenv("RASP_ADMIN_PASSWORD")
	if n > 0 {
		if pass != "" {
			log.Printf("note: RASP_ADMIN_PASSWORD is only used to create the first admin; %d console users exist. Use `rasp-server user passwd` to reset a password.", n)
		}
		return
	}
	generated := pass == ""
	if generated {
		pass = store.RandomHex(12)
	}
	if err := st.CreateUser(name, store.RoleAdmin, pass); err != nil {
		log.Fatalf("create first admin %q: %v (RASP_ADMIN_PASSWORD must be at least %d characters)", name, err, store.MinPasswordLength)
	}
	st.AddAudit("system", "create_user", name, "role=admin (first start)")
	if generated {
		log.Printf("created admin %q with generated password: %s  (change it after first login)", name, pass)
	} else {
		log.Printf("created admin %q from RASP_ADMIN_PASSWORD", name)
	}
}

// userCmd implements `rasp-server user <list|add|passwd|role|disable|enable> [-db rasp.db] ...` for
// administration on the server host, e.g. recovering a lost admin password. Passwords are read from
// RASP_NEW_PASSWORD or the first line of stdin, never from the command line (shell history, ps).
func userCmd(args []string) {
	usage := func() {
		fmt.Fprintln(os.Stderr, `usage: rasp-server user [-db rasp.db] <command>
  list                          list console users
  add <name> <viewer|operator|admin>   create a user (password from RASP_NEW_PASSWORD or stdin)
  passwd <name>                 reset a password (from RASP_NEW_PASSWORD or stdin); revokes its sessions
  role <name> <role>            change a role
  disable <name> | enable <name>`)
		os.Exit(2)
	}
	fset := flag.NewFlagSet("user", flag.ExitOnError)
	dbPath := fset.String("db", envOr("RASP_DB", "rasp.db"), "SQLite database file")
	fset.Usage = usage
	_ = fset.Parse(args)
	a := fset.Args()
	if len(a) == 0 {
		usage()
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer st.Close()
	readPassword := func() string {
		if p := os.Getenv("RASP_NEW_PASSWORD"); p != "" {
			return p
		}
		fmt.Fprint(os.Stderr, "new password: ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		return strings.TrimRight(line, "\r\n")
	}
	need := func(n int) {
		if len(a) != n {
			usage()
		}
	}
	var detail string
	switch a[0] {
	case "list":
		need(1)
		users, err := st.ListUsers()
		if err != nil {
			log.Fatal(err)
		}
		for _, u := range users {
			state := "enabled"
			if u.Disabled {
				state = "disabled"
			}
			fmt.Printf("%-24s %-9s %s\n", u.Username, u.Role, state)
		}
		return
	case "add":
		need(3)
		err, detail = st.CreateUser(a[1], a[2], readPassword()), "role="+a[2]
	case "passwd":
		need(2)
		p := readPassword()
		err, detail = st.UpdateUser(a[1], nil, nil, &p), "password reset"
	case "role":
		need(3)
		err, detail = st.UpdateUser(a[1], &a[2], nil, nil), "role="+a[2]
	case "disable", "enable":
		need(2)
		d := a[0] == "disable"
		err, detail = st.UpdateUser(a[1], nil, &d, nil), a[0]+"d"
	default:
		usage()
	}
	if err != nil {
		log.Fatalf("user %s: %v", a[0], err)
	}
	st.AddAudit("cli", "user_"+a[0], a[1], detail)
	fmt.Printf("ok: %s %s\n", a[0], a[1])
}

func envFloat(k string, def float64) float64 {
	if v, err := strconv.ParseFloat(os.Getenv(k), 64); err == nil {
		return v
	}
	return def
}

// registerGauges exposes fleet and vulnerability state, computed at scrape time.
func registerGauges(st *store.Store) {
	onlineSince := func() int64 { return time.Now().Add(-3 * agentapi.HeartbeatSec * time.Second).UnixMilli() }
	fleet := func(key string) func() map[string]float64 {
		return func() map[string]float64 {
			m, err := st.FleetCounts(onlineSince())
			if err != nil {
				return nil
			}
			return map[string]float64{"": m[key]}
		}
	}
	ops.Gauge("rasp_apps", "Registered applications.", "", fleet("apps"))
	ops.Gauge("rasp_instances", "Known agent instances.", "", fleet("instances"))
	ops.Gauge("rasp_instances_online", "Agent instances with a recent heartbeat.", "", fleet("instances_online"))
	ops.Gauge("rasp_alarms_last_24h", "Alarm events in the last 24 hours.", "", fleet("alarms_24h"))
	ops.Gauge("rasp_kill_switch", "1 when the global kill switch is on.", "", func() map[string]float64 {
		if st.GetSetting("kill_switch", "false") == "true" {
			return map[string]float64{"": 1}
		}
		return map[string]float64{"": 0}
	})
	ops.Gauge("rasp_vulnerable_findings", "Vulnerable component findings by severity.", "severity", func() map[string]float64 {
		sum, err := st.SummarizeVulns(0)
		if err != nil {
			return nil
		}
		out := map[string]float64{}
		for _, lvl := range []string{"critical", "high", "medium", "low", "unknown"} {
			out[lvl] = float64(sum.BySeverity[lvl])
		}
		return out
	})
}

// backupCmd implements `rasp-server backup [-db rasp.db] [-with-key] <output.db>`: an online, consistent
// snapshot of the database (safe while the server runs), integrity-checked. With -with-key the policy signing
// private key is copied next to it (<output>.sign.key, mode 0600): without that key a restored platform
// cannot sign policies the agents accept. Restore: stop the server and copy the files back.
func backupCmd(args []string) {
	fset := flag.NewFlagSet("backup", flag.ExitOnError)
	dbPath := fset.String("db", envOr("RASP_DB", "rasp.db"), "SQLite database file")
	withKey := fset.Bool("with-key", false, "also copy the policy signing private key")
	signKey := fset.String("sign-key", envOr("RASP_SIGN_KEY", ""), "signing key path (default <db dir>/rasp-sign.key)")
	fset.Usage = func() {
		fmt.Fprintln(fset.Output(), "usage: rasp-server backup [-db rasp.db] [-with-key] <output.db>")
		fset.PrintDefaults()
	}
	_ = fset.Parse(args)
	if fset.NArg() != 1 {
		fset.Usage()
		os.Exit(2)
	}
	out := fset.Arg(0)
	if _, err := os.Stat(out); err == nil {
		log.Fatalf("backup: %s already exists", out)
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer st.Close()
	start := time.Now()
	if err := st.Backup(out); err != nil {
		_ = os.Remove(out)
		log.Fatalf("backup: %v", err)
	}
	_ = os.Chmod(out, 0o600) // contains app secrets and password hashes
	info, _ := os.Stat(out)
	fmt.Printf("database backup %s (%d bytes, integrity ok) in %s\n", out, info.Size(), time.Since(start).Round(time.Millisecond))
	if *withKey {
		if *signKey == "" {
			*signKey = filepath.Join(filepath.Dir(*dbPath), "rasp-sign.key")
		}
		key, err := os.ReadFile(*signKey)
		if err != nil {
			log.Fatalf("read signing key: %v", err)
		}
		if err := os.WriteFile(out+".sign.key", key, 0o600); err != nil {
			log.Fatalf("write signing key copy: %v", err)
		}
		fmt.Printf("signing key copied to %s.sign.key (keep it as secret as the original)\n", out)
	}
	st.AddAudit("cli", "backup", out, fmt.Sprintf("with_key=%v", *withKey))
}

// secureFiles refuses a signing key other users can read (whoever holds it can sign policies, e.g. "off",
// that every agent accepts) and restricts the database files, which hold app secrets and password hashes.
func secureFiles(signKey, dbPath string) error {
	if fi, err := os.Stat(signKey); err == nil && fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("policy signing key %s is accessible by other users (mode %04o); run: chmod 600 %s", signKey, fi.Mode().Perm(), signKey)
	}
	for _, f := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		if fi, err := os.Stat(f); err == nil && fi.Mode().Perm()&0o077 != 0 {
			if err := os.Chmod(f, 0o600); err != nil {
				log.Printf("CONFIG WARNING: cannot restrict %s to mode 0600: %v", f, err)
			}
		}
	}
	return nil
}

func isLoopback(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// configWarnings lists risky but legal settings, logged at every start.
func configWarnings(listen, tlsCert, agentURL, opsListen, webhook string) []string {
	var w []string
	if tlsCert == "" && !isLoopback(listen) {
		w = append(w, "serving plain HTTP on "+listen+"; use -tls-cert/-tls-key or put a TLS-terminating proxy in front")
	}
	if u, err := url.Parse(agentURL); err == nil && u.Scheme == "http" && !isLoopback(u.Host) && !strings.Contains(u.Host, "<") {
		w = append(w, "agent URL "+agentURL+" is plain HTTP: alarm data (request URLs, parameters) would travel unencrypted")
	}
	if opsListen != "" && !isLoopback(opsListen) {
		w = append(w, "ops listener "+opsListen+" is not loopback-only; /metrics has no authentication, restrict it with a firewall")
	}
	if strings.HasPrefix(webhook, "http://") {
		w = append(w, "notification webhook uses plain HTTP")
	}
	return w
}
