package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/NX1X/Egret-Nest-Dashboard/internal/auth"
	"github.com/NX1X/Egret-Nest-Dashboard/internal/model"
)

// handleAudit renders the instance audit log (admin-only; route is wrapped in
// requireAdmin). Read-only view of the append-only security event stream.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	events, err := s.store.ListAuditLog(300)
	if err != nil {
		log.Printf("egret-nest: listing audit log: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.render(w, "audit.html", map[string]any{
		"Instance": s.instanceName(), "User": u, "CSRF": s.csrfToken(w, r), "Active": "audit", "Events": events,
	})
}

// Settings keys (GUI-managed app config, stored in the settings table).
const (
	settingInstanceName     = "instance_name"
	settingRetentionDays    = "retention_days"
	settingAuditRetention   = "audit_retention_days"
	settingMetricsTokenHash = "metrics_token_hash"
)

// metricsAuthorized reports whether /metrics is enabled and whether the presented
// bearer token is valid. A GUI-generated token (stored hashed in settings) takes
// precedence; the EGRET_NEST_METRICS_TOKEN env var is the bootstrap fallback.
func (s *Server) metricsAuthorized(presented string) (enabled, ok bool) {
	if hash, _ := s.store.GetSetting(settingMetricsTokenHash); hash != "" {
		return true, presented != "" && auth.EqualToken(auth.HashToken(presented), hash)
	}
	if s.cfg.MetricsToken != "" {
		return true, auth.EqualToken(presented, s.cfg.MetricsToken)
	}
	return false, false
}

// handleMetrics serves Prometheus text-format counters. It is disabled (404)
// unless a metrics token is configured (via the admin Settings page or the
// EGRET_NEST_METRICS_TOKEN env var), and then requires that bearer token
// (constant-time) - metrics reveal fleet size / activity and must not be public.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	enabled, ok := s.metricsAuthorized(bearerToken(r))
	if !enabled {
		http.NotFound(w, r)
		return
	}
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	m, err := s.store.Snapshot()
	if err != nil {
		log.Printf("egret-nest: metrics snapshot: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w, "# HELP egret_nest_users Total user accounts.\n# TYPE egret_nest_users gauge\negret_nest_users %d\n", m.Users)
	fmt.Fprintf(w, "# HELP egret_nest_orgs Total organizations.\n# TYPE egret_nest_orgs gauge\negret_nest_orgs %d\n", m.Orgs)
	fmt.Fprintf(w, "# HELP egret_nest_runs Total ingested runs.\n# TYPE egret_nest_runs gauge\negret_nest_runs %d\n", m.Runs)
	fmt.Fprintf(w, "# HELP egret_nest_active_sessions Non-expired login sessions.\n# TYPE egret_nest_active_sessions gauge\negret_nest_active_sessions %d\n", m.ActiveSessions)
	fmt.Fprintf(w, "# HELP egret_nest_ingest_tokens Non-revoked ingest tokens.\n# TYPE egret_nest_ingest_tokens gauge\negret_nest_ingest_tokens %d\n", m.IngestTokens)
	fmt.Fprintf(w, "# HELP egret_nest_audit_events Audit-log rows.\n# TYPE egret_nest_audit_events gauge\negret_nest_audit_events %d\n", m.AuditEvents)
	fmt.Fprintf(w, "# HELP egret_nest_endpoints Distinct observed endpoints.\n# TYPE egret_nest_endpoints gauge\negret_nest_endpoints %d\n", m.Endpoints)
}

// RunJanitor runs periodic maintenance until ctx is cancelled: it always prunes
// expired sessions and stale anti-replay records, and - when RetentionDays > 0 -
// deletes runs and audit events past the retention window. Runs once immediately,
// then hourly. Errors are logged, never fatal.
func (s *Server) RunJanitor(ctx context.Context) {
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()
	s.janitorPass()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.janitorPass()
		}
	}
}

func (s *Server) janitorPass() {
	if err := s.store.PruneExpiredSessions(); err != nil {
		log.Printf("egret-nest: janitor prune sessions: %v", err)
	}
	// TOTP anti-replay records only need to outlive their validity window; an hour
	// is far beyond the 30s period + skew.
	if err := s.store.PruneTOTPUsed(time.Now().Add(-time.Hour)); err != nil {
		log.Printf("egret-nest: janitor prune totp: %v", err)
	}
	if d := s.retentionDays(); d > 0 {
		cutoff := time.Now().AddDate(0, 0, -d)
		if n, err := s.store.PruneRunsBefore(cutoff); err != nil {
			log.Printf("egret-nest: janitor prune runs: %v", err)
		} else if n > 0 {
			log.Printf("egret-nest: janitor pruned %d run(s) older than %d days", n, d)
		}
	}
	// Audit-log retention is a separate knob because the audit trail holds PII
	// (logins/emails + client IP) that the run data does not, and may warrant a
	// shorter (or different) window. Falls back to RetentionDays when unset.
	if d := s.auditRetentionDays(); d > 0 {
		cutoff := time.Now().AddDate(0, 0, -d)
		if n, err := s.store.PruneAuditBefore(cutoff); err != nil {
			log.Printf("egret-nest: janitor prune audit: %v", err)
		} else if n > 0 {
			log.Printf("egret-nest: janitor pruned %d audit event(s) older than %d days", n, d)
		}
	}
}

// externalURL is the dashboard's base URL for display (CI snippets): the
// configured BaseURL when set, else derived from the request.
func (s *Server) externalURL(r *http.Request) string {
	if s.cfg.BaseURL != "" {
		return strings.TrimRight(s.cfg.BaseURL, "/")
	}
	scheme := "http"
	if s.secure(r) {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// --- admin: Settings ---

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	s.renderSettings(w, r, "")
}

// renderSettings renders the settings page; newToken (if non-empty) is a freshly
// generated /metrics token shown exactly once.
func (s *Server) renderSettings(w http.ResponseWriter, r *http.Request, newToken string) {
	if newToken != "" {
		w.Header().Set("Cache-Control", "no-store") // shown-once secret
	}
	hash, _ := s.store.GetSetting(settingMetricsTokenHash)
	s.render(w, "settings.html", map[string]any{
		"Instance": s.instanceName(), "User": currentUser(r), "CSRF": s.csrfToken(w, r), "Active": "settings",
		"InstanceName": s.instanceName(), "RetentionDays": s.retentionDays(),
		"AuditRetentionDays": s.auditRetentionDays(),
		"MetricsEnabled":     hash != "" || s.cfg.MetricsToken != "",
		"MetricsEnvSet":      s.cfg.MetricsToken != "",
		"NewMetricsToken":    newToken,
		// Read-only auth-provider status. Providers are configured via env vars at
		// deploy time (secrets never live in the DB/UI); this just surfaces what's
		// active so operators can see it without grepping the process env.
		"AuthGitHub":     s.ghOAuth() != nil,
		"AuthGitHubOrg":  s.cfg.GitHubAllowedOrg,
		"AuthOIDC":       s.oidcProv() != nil,
		"AuthOIDCName":   s.oidcName(),
		"AuthOIDCDomain": s.cfg.OIDCAllowedDomain,
	})
}

func (s *Server) handleSettingsPost(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	actor := ""
	if u := currentUser(r); u != nil {
		actor = u.Login
	}
	switch r.PostFormValue("action") {
	case "save":
		name := strings.TrimSpace(r.PostFormValue("instance_name"))
		if len(name) > 100 {
			name = name[:100]
		}
		if name != "" {
			_ = s.store.SetSetting(settingInstanceName, name)
		} else {
			_ = s.store.DeleteSetting(settingInstanceName)
		}
		s.saveIntSetting(settingRetentionDays, r.PostFormValue("retention_days"))
		s.saveIntSetting(settingAuditRetention, r.PostFormValue("audit_retention_days"))
		s.audit(r, actor, "settings.change", "instance/retention updated")
	case "metrics_generate":
		token, hash, err := auth.NewSecretToken()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := s.store.SetSetting(settingMetricsTokenHash, hash); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		s.audit(r, actor, "settings.metrics_token.generate", "")
		s.renderSettings(w, r, token) // show once
		return
	case "metrics_clear":
		if err := s.store.DeleteSetting(settingMetricsTokenHash); err != nil {
			log.Printf("egret-nest: clearing metrics token: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		s.audit(r, actor, "settings.metrics_token.clear", "")
	}
	http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
}

// saveIntSetting stores a non-negative integer setting, or clears it when blank.
func (s *Server) saveIntSetting(key, raw string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		_ = s.store.DeleteSetting(key)
		return
	}
	if n, err := strconv.Atoi(raw); err == nil && n >= 0 {
		_ = s.store.SetSetting(key, strconv.Itoa(n))
	}
}

// --- admin: Connect a repo (orgs + ingest tokens) ---

func (s *Server) handleTokens(w http.ResponseWriter, r *http.Request) {
	s.renderTokens(w, r, "", "")
}

func (s *Server) renderTokens(w http.ResponseWriter, r *http.Request, newToken, snippetRepo string) {
	if newToken != "" {
		w.Header().Set("Cache-Control", "no-store") // shown-once secret
	}
	orgs, err := s.store.ListOrgs()
	if err != nil {
		log.Printf("egret-nest: listing orgs: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	tokens, err := s.store.ListIngestTokens()
	if err != nil {
		log.Printf("egret-nest: listing tokens: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.render(w, "tokens.html", map[string]any{
		"Instance": s.instanceName(), "User": currentUser(r), "CSRF": s.csrfToken(w, r), "Active": "tokens",
		"Orgs": orgs, "Tokens": tokens, "IngestURL": s.externalURL(r) + "/ingest",
		// When BaseURL is unset the URL is derived from the request Host (which is
		// client-controlled) - surface that so the admin sets a trusted base URL
		// rather than pasting a host-derived endpoint into CI.
		"IngestURLDerived": s.cfg.BaseURL == "",
		"NewToken":         newToken, "SnippetRepo": snippetRepo,
	})
}

func (s *Server) handleTokensPost(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	actor := ""
	if u := currentUser(r); u != nil {
		actor = u.Login
	}
	switch r.PostFormValue("action") {
	case "create_org":
		name := strings.TrimSpace(r.PostFormValue("org_name"))
		if !validOrgName(name) {
			s.renderTokens(w, r, "", "")
			return
		}
		if existing, _ := s.store.GetOrgByName(name); existing == nil {
			if _, err := s.store.CreateOrg(name); err != nil {
				log.Printf("egret-nest: create org: %v", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			s.audit(r, actor, "org.create", name)
		}
	case "create_token":
		orgID, _ := strconv.ParseInt(r.PostFormValue("org_id"), 10, 64)
		// Cap server-side (the HTML maxlength is client-only, trivially bypassed).
		repo := cap140(strings.ToLower(strings.TrimSpace(r.PostFormValue("repository"))))
		name := cap64(strings.TrimSpace(r.PostFormValue("token_name")))
		if orgID == 0 {
			s.renderTokens(w, r, "", "")
			return
		}
		token, hash, err := auth.NewSecretToken()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if _, err := s.store.CreateIngestToken(&model.IngestToken{
			OrgID: orgID, Repository: repo, Name: name, TokenHash: hash,
		}); err != nil {
			log.Printf("egret-nest: create token: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		s.audit(r, actor, "token.create", fmt.Sprintf("org=%d repo=%q", orgID, repo))
		s.renderTokens(w, r, token, repo) // show token once
		return
	case "revoke":
		id, _ := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
		if id != 0 {
			if err := s.store.RevokeIngestToken(id); err != nil {
				log.Printf("egret-nest: revoking token %d: %v", id, err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			s.audit(r, actor, "token.revoke", fmt.Sprintf("id=%d", id))
		}
	}
	http.Redirect(w, r, "/admin/tokens", http.StatusSeeOther)
}

func cap140(s string) string {
	if len(s) > 140 {
		return s[:140]
	}
	return s
}

func cap64(s string) string {
	if len(s) > 64 {
		return s[:64]
	}
	return s
}

// validOrgName accepts a reasonable, bounded org name.
func validOrgName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, c := range name {
		if !(c == '-' || c == '_' || c == '.' || c == ' ' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

// --- admin: Users & org membership ---

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers()
	if err != nil {
		log.Printf("egret-nest: listing users: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	orgs, err := s.store.ListOrgs()
	if err != nil {
		log.Printf("egret-nest: listing orgs: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.render(w, "users.html", map[string]any{
		"Instance": s.instanceName(), "User": currentUser(r), "CSRF": s.csrfToken(w, r), "Active": "users",
		"Users": users, "Orgs": orgs, "Roles": []string{"owner", "admin", "member", "viewer"},
	})
}

func (s *Server) handleUsersPost(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	actor := ""
	if u := currentUser(r); u != nil {
		actor = u.Login
	}
	userID, _ := strconv.ParseInt(r.PostFormValue("user_id"), 10, 64)
	orgID, _ := strconv.ParseInt(r.PostFormValue("org_id"), 10, 64)
	switch r.PostFormValue("action") {
	case "grant":
		role := model.Role(r.PostFormValue("role"))
		if userID == 0 || orgID == 0 || !role.Valid() {
			s.handleUsers(w, r)
			return
		}
		if err := s.store.AddMembership(orgID, userID, role); err != nil {
			log.Printf("egret-nest: grant membership: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		s.audit(r, actor, "membership.grant", fmt.Sprintf("user=%d org=%d role=%s", userID, orgID, role))
	case "revoke":
		if userID != 0 && orgID != 0 {
			if err := s.store.RemoveMembership(orgID, userID); err != nil {
				log.Printf("egret-nest: revoke membership: %v", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			s.audit(r, actor, "membership.revoke", fmt.Sprintf("user=%d org=%d", userID, orgID))
		}
	}
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// --- admin: Logs (recent HTTP requests) ---

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	s.render(w, "logs.html", map[string]any{
		"Instance": s.instanceName(), "User": currentUser(r), "CSRF": s.csrfToken(w, r), "Active": "logs",
		"Entries": s.logs.recent(500),
	})
}

// capForAudit truncates attacker-influenceable text (e.g. an IdP-supplied,
// unverified email) before it is stored in an audit detail, so it can't bloat the
// row. Rendering is already escaped by html/template.
func capForAudit(s string) string {
	const max = 128
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// retentionDays returns the run-retention window: the GUI setting when set,
// otherwise the EGRET_NEST_RETENTION_DAYS env default.
func (s *Server) retentionDays() int {
	if v, _ := s.store.GetSetting(settingRetentionDays); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return s.cfg.RetentionDays
}

// auditRetentionDays returns the audit-log retention window: the GUI setting, then
// the dedicated env knob, then the general run-retention window.
func (s *Server) auditRetentionDays() int {
	if v, _ := s.store.GetSetting(settingAuditRetention); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	if s.cfg.AuditRetentionDays > 0 {
		return s.cfg.AuditRetentionDays
	}
	return s.retentionDays()
}

// instanceName returns the display name: the GUI setting when set, else the
// EGRET_NEST_INSTANCE env default.
func (s *Server) instanceName() string {
	if v, _ := s.store.GetSetting(settingInstanceName); v != "" {
		return v
	}
	return s.cfg.Instance
}
