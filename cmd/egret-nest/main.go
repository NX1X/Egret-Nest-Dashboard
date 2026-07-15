// Command egret-nest is the Egret Nest Dashboard: an optional, self-hosted
// server that ingests Egret run reports and renders them. It is a single static
// binary with an embedded UI and a pure-Go SQLite store.
//
// Usage:
//
//	egret-nest                 run the server (default)
//	egret-nest backup <path>   write a consistent DB snapshot to <path> (must not exist)
//	egret-nest version         print the version and exit
//
// Configuration (all via env):
//
//	EGRET_NEST_ADDR         listen address        (default ":8080")
//	EGRET_NEST_DB           sqlite file path      (default "egret-nest.db")
//	EGRET_NEST_TOKEN        optional legacy shared ingest token (prefer scoped tokens)
//	EGRET_NEST_INSTANCE     display name          (default "Egret Nest")
//	EGRET_NEST_OPEN_INGEST  "1" = accept /ingest with no token (dev only)
//	EGRET_NEST_BEHIND_PROXY "1" = trust X-Forwarded-Proto (set only behind a TLS proxy)
//	EGRET_NEST_TLS_CERT / _TLS_KEY  PEM cert+key paths to serve HTTPS natively
//	                        (set both, or neither and terminate TLS at a proxy)
//	EGRET_NEST_BASE_URL     external base URL (for OAuth redirect; else derived from request)
//	EGRET_NEST_GITHUB_CLIENT_ID / _CLIENT_SECRET  enable "Login with GitHub" (the Egret App's OAuth)
//	EGRET_NEST_GITHUB_ALLOWED_ORG  auto-provision only members of this GitHub org
//	EGRET_NEST_OIDC_ISSUER / _CLIENT_ID / _CLIENT_SECRET  enable generic OIDC login
//	EGRET_NEST_OIDC_NAME           button label for OIDC (default "SSO")
//	EGRET_NEST_OIDC_ALLOWED_DOMAIN auto-provision only emails at this domain
//	EGRET_NEST_SECRET_KEY   32-byte key (hex or base64) to encrypt TOTP seeds at rest
//	EGRET_NEST_METRICS_TOKEN bearer token gating /metrics (unset = endpoint disabled)
//	EGRET_NEST_RETENTION_DAYS prune runs older than N days (unset/0 = keep forever)
//	EGRET_NEST_AUDIT_RETENTION_DAYS audit-log retention (unset/0 = fall back to RETENTION_DAYS)
//	EGRET_NEST_WEBHOOK_SECRET HMAC-SHA256 secret for POST /webhook/github (unset = endpoint disabled)
//	EGRET_NEST_SETUP_TOKEN  one-time token required at /setup (unset = a random one is generated + logged)
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/NX1X/Egret-Nest-Dashboard/internal/auth"
	"github.com/NX1X/Egret-Nest-Dashboard/internal/server"
	"github.com/NX1X/Egret-Nest-Dashboard/internal/store"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "-v", "--version":
			fmt.Printf("egret-nest %s\n", version)
			return
		case "backup":
			runBackup(os.Args[2:])
			return
		case "healthcheck":
			runHealthcheck()
			return
		default:
			log.Fatalf("egret-nest: unknown command %q (try: backup, healthcheck, version)", os.Args[1])
		}
	}
	serve()
}

// runHealthcheck does an in-process GET of /healthz against the listener and
// exits non-zero on failure. It is the container HEALTHCHECK (the distroless
// image has no shell/curl), so it actually exercises the HTTP server rather than
// just proving the binary can print a string.
func runHealthcheck() {
	addr := getenv("EGRET_NEST_ADDR", ":8080")
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		port = "8080"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		log.Fatalf("egret-nest: healthcheck: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("egret-nest: healthcheck: status %d", resp.StatusCode)
	}
}

// runBackup writes a consistent snapshot of the configured database to a new file.
func runBackup(args []string) {
	if len(args) != 1 {
		log.Fatalf("usage: egret-nest backup <destination-path>")
	}
	dbPath := getenv("EGRET_NEST_DB", "egret-nest.db")
	st, err := store.Open(dbPath)
	if err != nil {
		log.Fatalf("egret-nest: %v", err)
	}
	defer st.Close()
	if err := st.Backup(args[0]); err != nil {
		log.Fatalf("egret-nest: %v", err)
	}
	log.Printf("egret-nest: backed up %s -> %s", dbPath, args[0])
}

func serve() {
	addr := getenv("EGRET_NEST_ADDR", ":8080")
	dbPath := getenv("EGRET_NEST_DB", "egret-nest.db")

	st, err := store.Open(dbPath)
	if err != nil {
		log.Fatalf("egret-nest: %v", err)
	}
	defer st.Close()

	// At-rest encryption for TOTP seeds (optional but recommended).
	box, err := auth.NewSecretBox(os.Getenv("EGRET_NEST_SECRET_KEY"))
	if err != nil {
		log.Fatalf("egret-nest: EGRET_NEST_SECRET_KEY: %v", err)
	}
	if box == nil {
		log.Printf("egret-nest: WARNING — EGRET_NEST_SECRET_KEY not set; TOTP seeds are stored unencrypted")
	}
	st.UseSecretBox(box)

	srv, err := server.New(st, server.Config{
		Instance:           os.Getenv("EGRET_NEST_INSTANCE"),
		IngestToken:        os.Getenv("EGRET_NEST_TOKEN"),
		OpenIngest:         os.Getenv("EGRET_NEST_OPEN_INGEST") == "1",
		BehindProxy:        os.Getenv("EGRET_NEST_BEHIND_PROXY") == "1",
		BaseURL:            os.Getenv("EGRET_NEST_BASE_URL"),
		GitHubClientID:     os.Getenv("EGRET_NEST_GITHUB_CLIENT_ID"),
		GitHubClientSecret: os.Getenv("EGRET_NEST_GITHUB_CLIENT_SECRET"),
		GitHubAllowedOrg:   os.Getenv("EGRET_NEST_GITHUB_ALLOWED_ORG"),
		OIDCIssuer:         os.Getenv("EGRET_NEST_OIDC_ISSUER"),
		OIDCClientID:       os.Getenv("EGRET_NEST_OIDC_CLIENT_ID"),
		OIDCClientSecret:   os.Getenv("EGRET_NEST_OIDC_CLIENT_SECRET"),
		OIDCName:           os.Getenv("EGRET_NEST_OIDC_NAME"),
		OIDCAllowedDomain:  os.Getenv("EGRET_NEST_OIDC_ALLOWED_DOMAIN"),
		MetricsToken:       os.Getenv("EGRET_NEST_METRICS_TOKEN"),
		RetentionDays:      atoiDefault(os.Getenv("EGRET_NEST_RETENTION_DAYS"), 0),
		AuditRetentionDays: atoiDefault(os.Getenv("EGRET_NEST_AUDIT_RETENTION_DAYS"), 0),
		WebhookSecret:      os.Getenv("EGRET_NEST_WEBHOOK_SECRET"),
		SetupToken:         os.Getenv("EGRET_NEST_SETUP_TOKEN"),
	})
	if err != nil {
		log.Fatalf("egret-nest: %v", err)
	}

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Native TLS: set BOTH EGRET_NEST_TLS_CERT and EGRET_NEST_TLS_KEY (PEM paths)
	// to serve HTTPS directly. Otherwise the server speaks plain HTTP — intended
	// to sit behind a TLS-terminating proxy (set EGRET_NEST_BEHIND_PROXY=1) or on
	// localhost. When TLS is on, requests arrive with r.TLS set, so session/CSRF
	// cookies get the Secure + __Host- treatment and HSTS automatically.
	tlsCert := os.Getenv("EGRET_NEST_TLS_CERT")
	tlsKey := os.Getenv("EGRET_NEST_TLS_KEY")
	tlsEnabled := tlsCert != "" && tlsKey != ""
	if (tlsCert == "") != (tlsKey == "") {
		log.Fatalf("egret-nest: set BOTH EGRET_NEST_TLS_CERT and EGRET_NEST_TLS_KEY, or neither")
	}
	if tlsEnabled {
		httpSrv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	// Graceful shutdown on signal.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Background maintenance: session/replay pruning + optional retention.
	go srv.RunJanitor(ctx)

	go func() {
		scheme := "http"
		if tlsEnabled {
			scheme = "https"
		}
		log.Printf("egret-nest %s: listening on %s (%s, db %s)", version, addr, scheme, dbPath)
		var err error
		if tlsEnabled {
			err = httpSrv.ListenAndServeTLS(tlsCert, tlsKey)
		} else {
			err = httpSrv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("egret-nest: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("egret-nest: shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutCtx); err != nil {
		log.Printf("egret-nest: shutdown error: %v", err)
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// atoiDefault parses a non-negative int from s, returning def on empty/invalid.
func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		log.Printf("egret-nest: ignoring invalid integer %q, using %d", s, def)
		return def
	}
	return n
}
