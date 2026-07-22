package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
)

// SSO providers (GitHub OAuth, OIDC) can be configured two ways:
//   - Environment variables (12-factor / GitOps) - authoritative when set.
//   - The admin UI at /admin/auth - stored in the settings table, with client
//     secrets ENCRYPTED at rest (EGRET_NEST_SECRET_KEY). Applied only where the
//     corresponding env var is NOT set, so env always wins.
//
// The effective config is recomputed and the providers rebuilt+atomically swapped
// by reloadAuthProviders - at startup (from New) and after every /admin/auth save.

// setting keys for UI-stored auth config (secrets marked).
const (
	keyGHClientID       = "auth.github.client_id"
	keyGHClientSecret   = "auth.github.client_secret" // secret (encrypted)
	keyGHAllowedOrg     = "auth.github.allowed_org"
	keyOIDCIssuer       = "auth.oidc.issuer"
	keyOIDCClientID     = "auth.oidc.client_id"
	keyOIDCClientSecret = "auth.oidc.client_secret" // secret (encrypted)
	keyOIDCName         = "auth.oidc.name"
	keyOIDCDomain       = "auth.oidc.allowed_domain"
)

// authSource describes where a provider's config comes from.
type authSource string

const (
	sourceEnv  authSource = "env"  // set via environment (read-only in the UI)
	sourceDB   authSource = "db"   // set via the admin UI
	sourceNone authSource = "none" // not configured
)

// effectiveAuthConfig returns s.cfg with GitHub/OIDC fields filled from the DB
// when (and only when) the corresponding env var is unset, plus each provider's
// source. Env always takes precedence - a provider set in the environment is
// never overridden by UI-stored values.
func (s *Server) effectiveAuthConfig() (cfg Config, gh authSource, oidc authSource, err error) {
	cfg = s.cfg // copy; s.cfg (the env config) is never mutated

	// GitHub: env wins; else fall back to UI-stored config (needs id + secret).
	switch {
	case cfg.GitHubClientID != "":
		gh = sourceEnv
	default:
		id, e := s.store.GetSetting(keyGHClientID)
		if e != nil {
			return cfg, "", "", e
		}
		if id != "" {
			sec, e := s.store.GetSecretSetting(keyGHClientSecret)
			if e != nil {
				return cfg, "", "", e
			}
			org, _ := s.store.GetSetting(keyGHAllowedOrg)
			cfg.GitHubClientID, cfg.GitHubClientSecret, cfg.GitHubAllowedOrg = id, sec, org
			gh = sourceDB
		} else {
			gh = sourceNone
		}
	}

	// OIDC: env wins; else UI-stored (needs issuer + client id + secret).
	switch {
	case cfg.OIDCIssuer != "":
		oidc = sourceEnv
	default:
		iss, e := s.store.GetSetting(keyOIDCIssuer)
		if e != nil {
			return cfg, "", "", e
		}
		if iss != "" {
			sec, e := s.store.GetSecretSetting(keyOIDCClientSecret)
			if e != nil {
				return cfg, "", "", e
			}
			cfg.OIDCIssuer = iss
			cfg.OIDCClientID, _ = s.store.GetSetting(keyOIDCClientID)
			cfg.OIDCClientSecret = sec
			cfg.OIDCName, _ = s.store.GetSetting(keyOIDCName)
			cfg.OIDCAllowedDomain, _ = s.store.GetSetting(keyOIDCDomain)
			oidc = sourceDB
		} else {
			oidc = sourceNone
		}
	}
	return cfg, gh, oidc, nil
}

// errBaseURLRequired is returned when SSO would be enabled without a trusted base
// URL for the redirect_uri.
var errBaseURLRequired = errors.New("EGRET_NEST_BASE_URL must be set before enabling GitHub OAuth or OIDC")

// Sentinel errors for issuer validation (mapped to safe UI messages; the raw
// upstream error is never reflected to the client).
var (
	errIssuerScheme  = errors.New("the OIDC issuer URL must use https")
	errIssuerNoHost  = errors.New("the OIDC issuer host could not be resolved")
	errIssuerBlocked = errors.New("the OIDC issuer resolves to a disallowed (internal/loopback) address")
)

// reloadAuthProviders rebuilds BOTH providers - used only at startup. Runtime
// changes go through reloadGitHub / reloadOIDC so a failure in one provider (e.g.
// an OIDC issuer that won't resolve) can never block or silently no-op a change to
// the other. Startup wants a config error to fail loudly, so it returns the error.
func (s *Server) reloadAuthProviders(ctx context.Context) error {
	if err := s.reloadGitHub(); err != nil {
		return err
	}
	return s.reloadOIDC(ctx)
}

// reloadGitHub rebuilds and atomically swaps the GitHub provider from the effective
// config. It performs no network I/O, so it cannot fail transiently - a GitHub
// enable/disable is deterministic and never blocked by OIDC health.
func (s *Server) reloadGitHub() error {
	cfg, _, _, err := s.effectiveAuthConfig()
	if err != nil {
		return err
	}
	gh := newGithubOAuth(cfg)
	if gh != nil && cfg.BaseURL == "" {
		return errBaseURLRequired
	}
	s.oauth.Store(gh)
	return nil
}

// reloadOIDC rebuilds and atomically swaps the OIDC provider. Issuer discovery is a
// server-side network call, so when the issuer comes from the UI (not env) it is
// first validated to reject non-https and internal/loopback targets (SSRF guard).
// On any failure the previous provider stays live (no partial swap).
func (s *Server) reloadOIDC(ctx context.Context) error {
	cfg, _, oidcSrc, err := s.effectiveAuthConfig()
	if err != nil {
		return err
	}
	// SSRF guard for UI-supplied issuers only. Env-configured issuers are operator
	// intent (may legitimately be an internal IdP) and are trusted as-is. For a
	// UI issuer, reject one that resolves internal at save time (fail fast), and
	// route every OIDC network call (discovery, JWKS, token/userinfo - including
	// endpoints the discovery document itself declares) through a guarded client
	// that re-checks the *resolved* IP at dial time, so a DNS rebind or an
	// attacker-declared token_endpoint can't land a fetch on an internal address.
	var discoveryClient *http.Client
	if cfg.OIDCIssuer != "" && oidcSrc == sourceDB {
		if err := validateIssuerURL(cfg.OIDCIssuer); err != nil {
			return err
		}
		discoveryClient = guardedOIDCClient()
	}
	oidc, err := newOIDCProvider(ctx, cfg, discoveryClient)
	if err != nil {
		return err
	}
	if oidc != nil && cfg.BaseURL == "" {
		return errBaseURLRequired
	}
	s.oidc.Store(oidc)
	return nil
}

// validateIssuerURL enforces https and rejects, at save time, an issuer that
// resolves to loopback/link-local/private/unspecified addresses (the cloud-metadata
// IP 169.254.169.254 is link-local, so it's covered) - a fail-fast check so an
// obviously-internal issuer is refused before it's stored. The dial-time guard in
// guardedOIDCClient re-checks the resolved IP on every OIDC fetch, so this save-time
// check is UX/defence-in-depth, not the sole barrier (it can't be, across a rebind).
func validateIssuerURL(raw string) error {
	u, e := url.Parse(raw)
	if e != nil || u.Host == "" {
		return errIssuerNoHost
	}
	if u.Scheme != "https" {
		return errIssuerScheme
	}
	ips, e := net.LookupIP(u.Hostname())
	if e != nil || len(ips) == 0 {
		return errIssuerNoHost
	}
	for _, ip := range ips {
		if isInternalIP(ip) {
			return errIssuerBlocked
		}
	}
	return nil
}

// isInternalIP reports whether an address is one we refuse to let the dashboard
// reach on an OIDC admin's behalf: loopback, link-local (covers the cloud
// metadata IP 169.254.169.254), private, or unspecified. Shared by the
// save-time issuer check and the dial-time guard on token/JWKS/userinfo fetches.
func isInternalIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsPrivate() || ip.IsUnspecified()
}
