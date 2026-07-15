package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/NX1X/Egret-Nest-Dashboard/internal/store"
)

// The /admin/auth page lets an instance admin configure the GitHub OAuth and OIDC
// login providers from the UI. Client secrets are stored ENCRYPTED at rest and
// never rendered back. A provider set via environment variables is authoritative
// and shown read-only. On save the providers are rebuilt and hot-swapped.

func (s *Server) handleAuthConfig(w http.ResponseWriter, r *http.Request) {
	s.renderAuthConfig(w, r, "")
}

func (s *Server) renderAuthConfig(w http.ResponseWriter, r *http.Request, notice string) {
	_, ghSrc, oidcSrc, err := s.effectiveAuthConfig()
	if err != nil {
		log.Printf("egret-nest: effective auth config: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	ghSecretSet, _ := s.store.HasSetting(keyGHClientSecret)
	oidcSecretSet, _ := s.store.HasSetting(keyOIDCClientSecret)
	// UI-stored (non-secret) values to prefill the forms.
	ghID, _ := s.store.GetSetting(keyGHClientID)
	ghOrg, _ := s.store.GetSetting(keyGHAllowedOrg)
	oidcIssuer, _ := s.store.GetSetting(keyOIDCIssuer)
	oidcID, _ := s.store.GetSetting(keyOIDCClientID)
	oidcName, _ := s.store.GetSetting(keyOIDCName)
	oidcDomain, _ := s.store.GetSetting(keyOIDCDomain)

	s.render(w, "auth_config.html", map[string]any{
		"Instance": s.instanceName(), "User": currentUser(r), "CSRF": s.csrfToken(w, r), "Active": "auth",
		"Notice":          notice,
		"CanStoreSecrets": s.store.SecretsEnabled(),
		"BaseURLSet":      s.cfg.BaseURL != "",
		"BaseURL":         s.cfg.BaseURL,
		"RedirectGitHub":  strings.TrimRight(s.cfg.BaseURL, "/") + "/auth/github/callback",
		"RedirectOIDC":    strings.TrimRight(s.cfg.BaseURL, "/") + "/auth/oidc/callback",
		// GitHub
		"GHSource": string(ghSrc), "GHEnv": ghSrc == sourceEnv,
		"GHClientID": ghID, "GHAllowedOrg": ghOrg, "GHSecretSet": ghSecretSet,
		// OIDC
		"OIDCSource": string(oidcSrc), "OIDCEnv": oidcSrc == sourceEnv,
		"OIDCIssuer": oidcIssuer, "OIDCClientID": oidcID, "OIDCName": oidcName,
		"OIDCDomain": oidcDomain, "OIDCSecretSet": oidcSecretSet,
	})
}

func (s *Server) handleAuthConfigPost(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	// Serialize all auth-config mutations: the snapshot→write→reload→rollback
	// sequence must not interleave with a concurrent save (which could revert a
	// just-applied change or corrupt the rollback snapshot).
	s.authMu.Lock()
	defer s.authMu.Unlock()

	actor := ""
	if u := currentUser(r); u != nil {
		actor = u.Login
	}
	// Re-check source: never let the UI overwrite an env-managed provider.
	_, ghSrc, oidcSrc, err := s.effectiveAuthConfig()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// OIDC reload does network discovery; bound it.
	cctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	reloadOIDC := func() error { return s.reloadOIDC(cctx) }

	switch r.PostFormValue("action") {
	case "github_save":
		if ghSrc == sourceEnv {
			s.renderAuthConfig(w, r, "GitHub login is managed by environment variables and can't be edited here.")
			return
		}
		clientID := strings.TrimSpace(r.PostFormValue("client_id"))
		clientSecret := r.PostFormValue("client_secret") // may be blank = keep existing
		allowedOrg := strings.TrimSpace(r.PostFormValue("allowed_org"))
		if clientID == "" {
			s.renderAuthConfig(w, r, "A GitHub Client ID is required.")
			return
		}
		if clientSecret == "" {
			if set, _ := s.store.HasSetting(keyGHClientSecret); !set {
				s.renderAuthConfig(w, r, "A GitHub Client Secret is required.")
				return
			}
		}
		if err := s.saveProvider(s.reloadGitHub, map[string]string{
			keyGHClientID: clientID, keyGHAllowedOrg: allowedOrg,
		}, keyGHClientSecret, clientSecret); err != nil {
			log.Printf("egret-nest: github auth save: %v", err)
			s.renderAuthConfig(w, r, saveErrMessage(err))
			return
		}
		s.audit(r, actor, "auth.github.configure", "provider updated via UI")
		s.renderAuthConfig(w, r, "GitHub login updated.")
		return

	case "github_clear":
		if ghSrc == sourceEnv {
			s.renderAuthConfig(w, r, "GitHub login is managed by environment variables.")
			return
		}
		if err := s.clearProvider(s.reloadGitHub, keyGHClientID, keyGHClientSecret, keyGHAllowedOrg); err != nil {
			log.Printf("egret-nest: github auth clear: %v", err)
			s.renderAuthConfig(w, r, saveErrMessage(err))
			return
		}
		s.audit(r, actor, "auth.github.disable", "provider disabled via UI")
		s.renderAuthConfig(w, r, "GitHub login disabled.")
		return

	case "oidc_save":
		if oidcSrc == sourceEnv {
			s.renderAuthConfig(w, r, "OIDC login is managed by environment variables and can't be edited here.")
			return
		}
		issuer := strings.TrimSpace(r.PostFormValue("issuer"))
		clientID := strings.TrimSpace(r.PostFormValue("client_id"))
		clientSecret := r.PostFormValue("client_secret")
		name := strings.TrimSpace(r.PostFormValue("name"))
		domain := strings.TrimSpace(r.PostFormValue("allowed_domain"))
		if issuer == "" || clientID == "" {
			s.renderAuthConfig(w, r, "OIDC Issuer URL and Client ID are required.")
			return
		}
		if clientSecret == "" {
			if set, _ := s.store.HasSetting(keyOIDCClientSecret); !set {
				s.renderAuthConfig(w, r, "An OIDC Client Secret is required.")
				return
			}
		}
		if err := s.saveProvider(reloadOIDC, map[string]string{
			keyOIDCIssuer: issuer, keyOIDCClientID: clientID, keyOIDCName: name, keyOIDCDomain: domain,
		}, keyOIDCClientSecret, clientSecret); err != nil {
			log.Printf("egret-nest: oidc auth save: %v", err)
			s.renderAuthConfig(w, r, saveErrMessage(err))
			return
		}
		s.audit(r, actor, "auth.oidc.configure", "provider updated via UI")
		s.renderAuthConfig(w, r, "OIDC login updated.")
		return

	case "oidc_clear":
		if oidcSrc == sourceEnv {
			s.renderAuthConfig(w, r, "OIDC login is managed by environment variables.")
			return
		}
		if err := s.clearProvider(reloadOIDC, keyOIDCIssuer, keyOIDCClientID, keyOIDCClientSecret, keyOIDCName, keyOIDCDomain); err != nil {
			log.Printf("egret-nest: oidc auth clear: %v", err)
			s.renderAuthConfig(w, r, saveErrMessage(err))
			return
		}
		s.audit(r, actor, "auth.oidc.disable", "provider disabled via UI")
		s.renderAuthConfig(w, r, "OIDC login disabled.")
		return
	}
	http.Redirect(w, r, "/admin/auth", http.StatusSeeOther)
}

// saveProvider atomically writes the plaintext settings + (optionally) the sealed
// secret, then rebuilds ONLY the affected provider via reload. If the rebuild
// fails (e.g. a bad OIDC issuer), it rolls the stored config back to its previous
// values and reloads again, so the live provider and the DB stay consistent. The
// caller holds s.authMu. reload must rebuild only the one provider being changed —
// so a GitHub change is never blocked by OIDC discovery health, and vice-versa.
func (s *Server) saveProvider(reload func() error, settings map[string]string, secretKey, secretVal string) error {
	// Snapshot the prior raw stored values (secret stays as ciphertext) for rollback.
	prev := map[string]string{secretKey: ""}
	for k := range settings {
		prev[k] = ""
	}
	for k := range prev {
		prev[k], _ = s.store.GetSetting(k)
	}

	// Build one atomic write batch. The secret is sealed here (errors, without
	// writing anything, if no encryption key is configured). A blank secret is
	// omitted so the existing one is kept.
	batch := map[string]string{}
	for k, v := range settings {
		batch[k] = v
	}
	if secretVal != "" {
		sealed, err := s.store.SealSecret(secretKey, secretVal)
		if err != nil {
			return err
		}
		batch[secretKey] = sealed
	}
	if err := s.store.WriteSettings(batch); err != nil {
		return err
	}

	if err := reload(); err != nil {
		_ = s.store.WriteSettings(prev) // restore prior raw values atomically
		_ = reload()
		return err
	}
	return nil
}

// clearProvider atomically removes a provider's settings and rebuilds it. On a
// reload failure it restores the prior values (so a disable never silently no-ops
// while claiming success) and returns the error. Caller holds s.authMu.
func (s *Server) clearProvider(reload func() error, keys ...string) error {
	prev := map[string]string{}
	del := map[string]string{}
	for _, k := range keys {
		prev[k], _ = s.store.GetSetting(k)
		del[k] = "" // "" ⇒ delete
	}
	if err := s.store.WriteSettings(del); err != nil {
		return err
	}
	if err := reload(); err != nil {
		_ = s.store.WriteSettings(prev)
		_ = reload()
		return err
	}
	return nil
}

// saveErrMessage maps internal errors to a safe, actionable UI message. It NEVER
// reflects a raw upstream error (OIDC discovery errors can echo internal response
// bodies — an SSRF oracle); the real error is logged server-side by the caller.
func saveErrMessage(err error) string {
	switch {
	case errors.Is(err, store.ErrNoSecretKey):
		return "Set EGRET_NEST_SECRET_KEY (32-byte hex/base64) and restart before storing a secret in the UI."
	case errors.Is(err, errBaseURLRequired):
		return "Set EGRET_NEST_BASE_URL (your dashboard's public URL) and restart before enabling SSO."
	case errors.Is(err, errIssuerScheme):
		return "The OIDC issuer URL must start with https://."
	case errors.Is(err, errIssuerNoHost):
		return "Couldn't resolve the OIDC issuer host — check the URL."
	case errors.Is(err, errIssuerBlocked):
		return "The OIDC issuer resolves to an internal/loopback address, which isn't allowed."
	default:
		return "Couldn't enable that provider — check the issuer is a reachable OIDC endpoint over https."
	}
}
