// Package server exposes the ingest API and the web dashboard over stdlib
// net/http (Go 1.22 routing). No third-party web framework - per the dependency
// policy, the standard library is enough.
package server

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NX1X/Egret-Nest-Dashboard/internal/auth"
	"github.com/NX1X/Egret-Nest-Dashboard/internal/model"
	"github.com/NX1X/Egret-Nest-Dashboard/internal/store"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

const maxIngestBytes = 8 << 20 // 8 MiB

// Config holds server settings (populated from env in cmd/egret-nest).
type Config struct {
	Instance    string // display name
	IngestToken string // optional legacy shared ingest token (prefer scoped tokens)
	OpenIngest  bool   // dev only: allow /ingest with no token when no shared token set
	BehindProxy bool   // trust X-Forwarded-Proto (set only when behind a trusted proxy)
	BaseURL     string // external base URL, for OAuth redirect (else derived from request)

	// GitHub OAuth ("Login with GitHub"). Empty client id/secret disables it.
	GitHubClientID     string
	GitHubClientSecret string
	GitHubAllowedOrg   string // auto-provision only members of this org (else no auto-provision)

	// Generic OIDC ("Login with SSO"). Empty issuer/client id/secret disables it.
	OIDCIssuer        string
	OIDCClientID      string
	OIDCClientSecret  string
	OIDCName          string // button label, e.g. "Okta" (default "SSO")
	OIDCAllowedDomain string // if set, auto-provision only emails at this domain

	// Ops / hardening (N5).
	MetricsToken       string // bearer token gating /metrics; empty disables the endpoint
	RetentionDays      int    // if > 0, the janitor prunes runs older than this
	AuditRetentionDays int    // audit-log retention; if 0, falls back to RetentionDays

	// Webhooks (N4). HMAC-SHA256 secret for POST /webhook/github; empty disables it.
	WebhookSecret string

	// One-time first-run setup token. If empty and the instance is un-bootstrapped,
	// New generates one and logs it - so /setup can't be claimed by whoever reaches
	// it first. Tests set a known value.
	SetupToken string
}

// Server wires the store and templates to HTTP handlers.
type Server struct {
	store        *store.Store
	cfg          Config
	tmpl         *template.Template
	loginLimiter *failLimiter
	// SSO providers are hot-swappable (env config merged with UI-stored config via
	// /admin/auth). Read them through ghOAuth()/oidcProv(); each Load() is nil when
	// that provider is not configured. atomic.Pointer makes a mid-request swap safe.
	oauth      atomic.Pointer[githubOAuth]
	oidc       atomic.Pointer[oidcProvider]
	authMu     sync.Mutex // serializes /admin/auth writes (snapshot→write→reload→rollback)
	logs       *ringLog   // in-memory access log for the admin Logs page
	setupToken string     // required on POST /setup while un-bootstrapped
}

// ghOAuth returns the current GitHub OAuth provider, or nil when not configured.
func (s *Server) ghOAuth() *githubOAuth { return s.oauth.Load() }

// oidcProv returns the current OIDC provider, or nil when not configured.
func (s *Server) oidcProv() *oidcProvider { return s.oidc.Load() }

// New builds a Server. It parses the embedded templates once.
func New(st *store.Store, cfg Config) (*Server, error) {
	if cfg.Instance == "" {
		cfg.Instance = "Egret Nest"
	}
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"short": shortSHA,
		"spark": sparkBars,
		"ftime": func(t time.Time) string {
			if t.IsZero() {
				return "-"
			}
			return t.Format("2006-01-02 15:04:05 MST")
		},
	}).ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	if cfg.MetricsToken != "" && len(cfg.MetricsToken) < 32 {
		// /metrics has no rate limiter; require a high-entropy token so it can't be
		// brute-forced online. 32+ chars (e.g. a base64 256-bit secret).
		return nil, fmt.Errorf("EGRET_NEST_METRICS_TOKEN must be at least 32 characters")
	}
	srv := &Server{
		store:        st,
		cfg:          cfg,
		tmpl:         tmpl,
		loginLimiter: newFailLimiter(5, 15*time.Minute), // 5 failures / 15 min per IP+login
		logs:         newRingLog(1000),
	}
	// Build the SSO providers from env config merged with any UI-stored (encrypted)
	// config, validating the redirect-trust requirement. Stored atomically so
	// /admin/auth can hot-swap them without a restart.
	if err := srv.reloadAuthProviders(context.Background()); err != nil {
		return nil, err
	}
	// First-run bootstrap protection: while un-bootstrapped, POST /setup requires a
	// one-time token so an attacker can't claim the admin before the operator. Use
	// the configured token, else mint + log one.
	if n, _ := st.CountUsers(); n == 0 {
		srv.setupToken = cfg.SetupToken
		if srv.setupToken == "" {
			tok, _, err := auth.NewSecretToken()
			if err != nil {
				return nil, fmt.Errorf("generating setup token: %w", err)
			}
			srv.setupToken = tok
			log.Printf("egret-nest: FIRST-RUN SETUP TOKEN (enter at /setup): %s", tok)
		}
	}
	return srv, nil
}

// Handler returns the router wrapped in the global middleware chain (panic
// recovery → security headers → session loading).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Public.
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST /ingest", s.handleIngest)                // bearer-token authenticated
	mux.HandleFunc("POST /webhook/github", s.handleGitHubWebhook) // HMAC-verified; 404 when disabled
	mux.HandleFunc("GET /metrics", s.handleMetrics)               // token-gated; 404 when disabled
	mux.Handle("GET /static/", s.staticHandler())                 // embedded CSS (CSP style-src 'self')
	// Auth flows.
	mux.HandleFunc("GET /setup", s.handleSetupForm)
	mux.HandleFunc("POST /setup", s.handleSetup)
	mux.HandleFunc("GET /login", s.handleLoginForm)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("POST /logout", s.handleLogout)
	// GitHub OAuth + OIDC (no-op with 404 when not configured).
	mux.HandleFunc("GET /auth/github/login", s.handleGithubLogin)
	mux.HandleFunc("GET /auth/github/callback", s.handleGithubCallback)
	mux.HandleFunc("GET /auth/oidc/login", s.handleOIDCLogin)
	mux.HandleFunc("GET /auth/oidc/callback", s.handleOIDCCallback)
	// Protected dashboard.
	mux.HandleFunc("GET /{$}", s.requireAuth(s.handleIndex))
	mux.HandleFunc("GET /runs/{id}", s.requireAuth(s.handleRun))
	mux.HandleFunc("GET /repos", s.requireAuth(s.handleRepos))
	mux.HandleFunc("GET /repos/{repo...}", s.requireAuth(s.handleRepo))
	// Self-service account (TOTP 2FA enrolment for local password accounts).
	mux.HandleFunc("GET /account", s.requireAuth(s.handleAccount))
	mux.HandleFunc("POST /account", s.requireAuth(s.handleAccountPost))
	// Org self-service management (org owner/admin, or instance admin). The picker
	// is open to any authenticated user (it just lists the orgs they can manage -
	// possibly none); the per-org pages are gated by requireOrgManager.
	mux.HandleFunc("GET /orgs", s.requireAuth(s.handleOrgList))
	mux.HandleFunc("GET /org/{id}/tokens", s.requireOrgManager(s.handleOrgTokens))
	mux.HandleFunc("POST /org/{id}/tokens", s.requireOrgManager(s.handleOrgTokensPost))
	mux.HandleFunc("GET /org/{id}/members", s.requireOrgManager(s.handleOrgMembers))
	mux.HandleFunc("POST /org/{id}/members", s.requireOrgManager(s.handleOrgMembersPost))
	// Admin console (instance-admin only).
	mux.HandleFunc("GET /audit", s.requireAdmin(s.handleAudit))
	mux.HandleFunc("GET /admin/settings", s.requireAdmin(s.handleSettings))
	mux.HandleFunc("POST /admin/settings", s.requireAdmin(s.handleSettingsPost))
	mux.HandleFunc("GET /admin/tokens", s.requireAdmin(s.handleTokens))
	mux.HandleFunc("POST /admin/tokens", s.requireAdmin(s.handleTokensPost))
	mux.HandleFunc("GET /admin/users", s.requireAdmin(s.handleUsers))
	mux.HandleFunc("POST /admin/users", s.requireAdmin(s.handleUsersPost))
	mux.HandleFunc("GET /admin/auth", s.requireAdmin(s.handleAuthConfig))
	mux.HandleFunc("POST /admin/auth", s.requireAdmin(s.handleAuthConfigPost))
	mux.HandleFunc("GET /admin/logs", s.requireAdmin(s.handleLogs))

	return s.recoverPanic(s.securityHeaders(s.sessionLoader(s.accessLog(mux))))
}

// staticHandler serves the embedded /static assets (just app.css) with a long
// cache lifetime. The content is immutable per build. Directory paths (trailing
// slash) 404 so the embedded dir is never listed.
func (s *Server) staticHandler() http.Handler {
	fs := http.FileServer(http.FS(staticFS))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=3600")
		fs.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	// Actually check the DB so liveness/readiness (and the container healthcheck)
	// detect a locked/unreachable store, not just that the process is up.
	if err := s.store.Ping(); err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("ok"))
}

// handleIngest accepts an Envelope, validates the schema version, stores it, and
// returns the new run id plus any newly-seen endpoints (drift).
func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	// Bound the body first, then decode (schema-check) before we can evaluate a
	// repo-scoped token. The MaxBytesReader caps the work an unauthenticated
	// caller can cause.
	r.Body = http.MaxBytesReader(w, r.Body, maxIngestBytes)

	// Lenient decode: unknown fields are allowed so additive contract changes
	// don't break older dashboards (per the compatibility policy).
	var env model.Envelope
	if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}
	if env.SchemaVersion != model.SchemaVersion {
		http.Error(w, "unsupported schema_version "+strconv.Itoa(env.SchemaVersion)+
			" (this dashboard supports "+strconv.Itoa(model.SchemaVersion)+")",
			http.StatusBadRequest)
		return
	}

	orgID, ok := s.ingestAuthorized(bearerToken(r), &env)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	id, newEndpoints, err := s.store.InsertEnvelope(&env, orgID)
	if err != nil {
		log.Printf("egret-nest: storing run: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"id":            id,
		"new_endpoints": newEndpoints,
	})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r) // non-nil: route is behind requireAuth
	runs, err := s.store.ListRuns(u.ID, u.IsAdmin, 100)
	if err != nil {
		log.Printf("egret-nest: listing runs: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.render(w, "index.html", map[string]any{
		"Instance": s.instanceName(),
		"Active":   "runs",
		"Runs":     runs,
		"User":     u,
		"CSRF":     s.csrfToken(w, r),
	})
}

func (s *Server) handleRun(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad run id", http.StatusBadRequest)
		return
	}
	u := currentUser(r)
	run, err := s.store.GetRun(id, u.ID, u.IsAdmin)
	if err != nil {
		log.Printf("egret-nest: getting run %d: %v", id, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if run == nil {
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}
	s.render(w, "run.html", map[string]any{
		"Instance": s.instanceName(),
		"Active":   "runs",
		"Run":      run,
		"User":     u,
	})
}

func (s *Server) handleRepos(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	repos, err := s.store.ListRepos(u.ID, u.IsAdmin)
	if err != nil {
		log.Printf("egret-nest: listing repos: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.render(w, "repos.html", map[string]any{
		"Instance": s.instanceName(), "User": u, "CSRF": s.csrfToken(w, r), "Active": "repos", "Repos": repos,
	})
}

func (s *Server) handleRepo(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	repo := r.PathValue("repo")
	if repo == "" {
		http.Error(w, "bad repository", http.StatusBadRequest)
		return
	}
	// Authorize before touching the (org-agnostic) endpoints_seen table.
	visible, err := s.store.RepoVisible(repo, u.ID, u.IsAdmin)
	if err != nil {
		log.Printf("egret-nest: repo visibility: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !visible {
		http.Error(w, "repository not found", http.StatusNotFound)
		return
	}
	runs, err := s.store.RunsForRepo(repo, u.ID, u.IsAdmin, 100)
	if err != nil {
		log.Printf("egret-nest: runs for repo: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	endpoints, err := s.store.EndpointsForRepo(repo, u.ID, u.IsAdmin)
	if err != nil {
		log.Printf("egret-nest: endpoints for repo: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.render(w, "repo.html", map[string]any{
		"Instance": s.instanceName(), "User": u, "CSRF": s.csrfToken(w, r), "Active": "repos",
		"Repo": repo, "Runs": runs, "Endpoints": endpoints,
		// Chronological per-run trends for the drift sparklines.
		"DriftTrend": trend(runs, func(r store.RunSummary) int { return r.NumNewEndpoints }),
		"ViolTrend":  trend(runs, func(r store.RunSummary) int { return r.NumViolations }),
	})
}

// bearerToken extracts the ingest token from the Authorization bearer header or
// the X-Egret-Token header.
func bearerToken(r *http.Request) string {
	if v := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); v != "" && v != r.Header.Get("Authorization") {
		return v
	}
	return r.Header.Get("X-Egret-Token")
}

// ingestAuthorized authorizes an ingest POST. Precedence:
//  1. a valid, non-revoked scoped token (repo scope, if set, must match);
//  2. the optional legacy shared token (constant-time);
//  3. otherwise denied - unless OpenIngest is set AND no shared token is
//     configured (explicit dev escape hatch only).
//
// Returns the org the run should be attributed to and whether the request is
// authorized. Legacy/open ingest attributes to org 0 (visible only to admins).
func (s *Server) ingestAuthorized(token string, env *model.Envelope) (orgID int64, ok bool) {
	if token != "" {
		if it, _ := s.store.GetIngestTokenByHash(auth.HashToken(token)); it != nil {
			if it.Repository != "" && !strings.EqualFold(it.Repository, env.Run.Repository) {
				return 0, false
			}
			_ = s.store.TouchIngestToken(it.ID)
			return it.OrgID, true
		}
		if s.cfg.IngestToken != "" && auth.EqualToken(token, s.cfg.IngestToken) {
			return 0, true
		}
		return 0, false
	}
	return 0, s.cfg.OpenIngest && s.cfg.IngestToken == ""
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	s.renderStatus(w, http.StatusOK, name, data)
}

// renderStatus renders a template to a buffer first, so a template error yields a
// clean 500 (no partially-written body) and the status/Content-Type are set once,
// before the body - avoiding superfluous-WriteHeader bugs.
func (s *Server) renderStatus(w http.ResponseWriter, status int, name string, data any) {
	var buf bytes.Buffer
	if err := s.tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		log.Printf("egret-nest: template %s: %v", name, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// shortSHA trims a commit SHA to 8 chars for display.
func shortSHA(sha string) string {
	if len(sha) > 8 {
		return sha[:8]
	}
	return sha
}
