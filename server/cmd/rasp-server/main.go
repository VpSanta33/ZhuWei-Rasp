// Command rasp-server is the ZhuWei-RASP management server: agent API, console API and web console
// in one binary (the MVP form of docs chapter 3; services can be split later along the same packages).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"zhuwei-rasp/server/internal/agentapi"
	"zhuwei-rasp/server/internal/console"
	"zhuwei-rasp/server/internal/httpx"
	"zhuwei-rasp/server/internal/signing"
	"zhuwei-rasp/server/internal/store"
	"zhuwei-rasp/server/web"
)

func main() {
	listen := flag.String("listen", envOr("RASP_LISTEN", ":8080"), "listen address")
	dbPath := flag.String("db", envOr("RASP_DB", "rasp.db"), "SQLite database file")
	adminUser := flag.String("admin-user", envOr("RASP_ADMIN_USER", "admin"), "console admin user")
	agentURL := flag.String("agent-url", envOr("RASP_AGENT_URL", ""), "URL agents use to reach this server (for install snippets)")
	tlsCert := flag.String("tls-cert", envOr("RASP_TLS_CERT", ""), "TLS certificate file (enables HTTPS)")
	tlsKey := flag.String("tls-key", envOr("RASP_TLS_KEY", ""), "TLS key file")
	signKey := flag.String("sign-key", envOr("RASP_SIGN_KEY", ""), "policy signing key (PKCS#8 PEM, ECDSA P-256; default <db dir>/rasp-sign.key, created if missing)")
	flag.Parse()
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

	adminPass := os.Getenv("RASP_ADMIN_PASSWORD")
	if adminPass == "" {
		adminPass = store.RandomHex(8)
		log.Printf("RASP_ADMIN_PASSWORD not set, generated console password for %q: %s", *adminUser, adminPass)
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer st.Close()

	if *agentURL == "" {
		scheme := "http"
		if *tlsCert != "" {
			scheme = "https"
		}
		*agentURL = fmt.Sprintf("%s://<this-server-host>%s", scheme, *listen)
	}

	mux := http.NewServeMux()
	agentapi.New(st, agentapi.NewNotifier(st), signer).Register(mux)
	console.New(st, *adminUser, adminPass, *agentURL, signer).Register(mux)
	mux.Handle("GET /", http.FileServerFS(web.FS))

	go housekeeping(st)

	srv := &http.Server{
		Addr:              *listen,
		Handler:           httpx.Recover(securityHeaders(mux)),
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
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'self' 'unsafe-inline'")
		next.ServeHTTP(w, r)
	})
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
