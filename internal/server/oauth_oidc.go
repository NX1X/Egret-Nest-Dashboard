package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/NX1X/Egret-Nest-Dashboard/internal/auth"
	"github.com/NX1X/Egret-Nest-Dashboard/internal/model"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	oidcStateCookie    = "egret_oidc_state"
	oidcNonceCookie    = "egret_oidc_nonce"
	oidcVerifierCookie = "egret_oidc_verifier"
)

// oidcHTTP bounds every OIDC network call (discovery, token exchange, JWKS) so a
// slow/unresponsive issuer can't hang a handler goroutine or process startup.
var oidcHTTP = &http.Client{Timeout: 15 * time.Second}

// oidcClaims are the ID-token fields we consume.
type oidcClaims struct {
	Subject       string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Nonce         string `json:"nonce"`
}

// oidcProvider implements generic OIDC login (Okta, Entra, Google, Keycloak…).
// authenticate is a field so tests can inject verified claims without standing up
// a real IdP + JWT signing; production wires it to oauth2 exchange + go-oidc
// verify (with PKCE + nonce).
type oidcProvider struct {
	name          string
	clientID      string
	allowedDomain string
	oauth2        *oauth2.Config
	authenticate  func(ctx context.Context, code, nonce, verifier string) (*oidcClaims, error)
}

// guardedOIDCClient returns an HTTP client whose dial refuses any destination
// that resolves to an internal address (loopback/link-local/private/unspecified).
// It allows any external host but re-checks the *resolved* IP at dial time, and
// dials exactly the IP it checked (no separate lookup the kernel could race) - so
// every OIDC fetch on a UI-configured issuer's behalf is covered: discovery, the
// JWKS fetch (go-oidc caches this client on the Provider), and the endpoints the
// discovery document itself declares (token_endpoint, userinfo), which may
// legitimately live on a different host than the issuer. A DNS rebind or an
// attacker-declared endpoint pointing at an internal service is caught at dial
// time, not only at save time. TLS SNI + cert verification still bind to the
// hostname (we change only which IP we connect to).
func guardedOIDCClient() *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("oidc: cannot resolve %q", host)
			}
			var lastErr error
			for _, ip := range ips {
				if isInternalIP(ip) {
					// Never dial it. Log it too: an OIDC host resolving to an internal
					// address (especially alongside external ones) is a signal of a
					// rebind attempt or a hostile DNS operator probing the guard.
					log.Printf("egret-nest: WARNING - OIDC host %q resolved to internal address %s; refusing that dial", host, ip)
					lastErr = fmt.Errorf("oidc: refusing dial to internal address %s (%s)", ip, host)
					continue
				}
				c, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if err == nil {
					return c, nil
				}
				lastErr = err
			}
			if lastErr == nil {
				lastErr = fmt.Errorf("oidc: no dialable address for %q", host)
			}
			return nil, lastErr
		},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: tr}
}

// newOIDCProvider performs OIDC discovery and returns a provider, or nil when
// OIDC is not configured. discoveryClient guards every OIDC network call against
// internal-IP targets (UI-supplied issuers); pass nil to use the default client
// (env-supplied issuers, operator-trusted).
func newOIDCProvider(ctx context.Context, cfg Config, discoveryClient *http.Client) (*oidcProvider, error) {
	if cfg.OIDCIssuer == "" || cfg.OIDCClientID == "" || cfg.OIDCClientSecret == "" {
		return nil, nil
	}
	dc := discoveryClient
	if dc == nil {
		dc = oidcHTTP
	}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, dc), cfg.OIDCIssuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for %q: %w", cfg.OIDCIssuer, err)
	}
	name := cfg.OIDCName
	if name == "" {
		name = "SSO"
	}
	if cfg.OIDCAllowedDomain == "" {
		log.Printf("egret-nest: WARNING - OIDC enabled without EGRET_NEST_OIDC_ALLOWED_DOMAIN; " +
			"any account the issuer authenticates will be auto-provisioned")
	}
	oc := &oauth2.Config{
		ClientID:     cfg.OIDCClientID,
		ClientSecret: cfg.OIDCClientSecret,
		RedirectURL:  strings.TrimRight(cfg.BaseURL, "/") + "/auth/oidc/callback",
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
	// JWKS is fetched by the verifier through provider.client - the SAME dc captured
	// at NewProvider above - so for a UI issuer the guarded client already covers the
	// JWKS dial (do NOT switch this to VerifierContext with a different client, or the
	// internal-IP guard is lost on JWKS). exchangeClient covers the token/userinfo
	// dials the same way; env issuers keep the default client (operator-trusted).
	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.OIDCClientID})
	exchangeClient := oidcHTTP
	if discoveryClient != nil {
		exchangeClient = discoveryClient
	}
	p := &oidcProvider{name: name, clientID: cfg.OIDCClientID, allowedDomain: cfg.OIDCAllowedDomain, oauth2: oc}
	p.authenticate = func(ctx context.Context, code, nonce, pkceVerifier string) (*oidcClaims, error) {
		ctx = oidc.ClientContext(ctx, exchangeClient) // guards the token_endpoint dial for UI issuers
		tok, err := oc.Exchange(ctx, code, oauth2.VerifierOption(pkceVerifier))
		if err != nil {
			return nil, fmt.Errorf("token exchange: %w", err)
		}
		raw, ok := tok.Extra("id_token").(string)
		if !ok || raw == "" {
			return nil, fmt.Errorf("no id_token in response")
		}
		idt, err := verifier.Verify(ctx, raw)
		if err != nil {
			return nil, fmt.Errorf("verifying id token: %w", err)
		}
		if !auth.EqualToken(idt.Nonce, nonce) {
			return nil, fmt.Errorf("nonce mismatch")
		}
		var c oidcClaims
		if err := idt.Claims(&c); err != nil {
			return nil, err
		}
		c.Nonce = idt.Nonce
		return &c, nil
	}
	return p, nil
}

func (p *oidcProvider) loginURL(state, nonce, pkceVerifier string) string {
	return p.oauth2.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(pkceVerifier))
}

// domainAllowed reports whether an email may sign in / be provisioned. With no
// configured domain, any user the IdP authenticated is accepted (the IdP is the
// trust boundary); with a domain, the email must match it.
func (p *oidcProvider) domainAllowed(email string) bool {
	if p.allowedDomain == "" {
		return true
	}
	return strings.HasSuffix(strings.ToLower(email), "@"+strings.ToLower(p.allowedDomain))
}

// --- handlers ---

func (s *Server) setEphemeralCookie(w http.ResponseWriter, r *http.Request, name, val string) {
	http.SetCookie(w, &http.Cookie{
		Name: s.cookieName(r, name), Value: val, Path: "/", MaxAge: 600,
		HttpOnly: true, Secure: s.secure(r), SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearCookie(w http.ResponseWriter, r *http.Request, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: s.cookieName(r, name), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.secure(r), SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	od := s.oidcProv()
	if od == nil {
		http.NotFound(w, r)
		return
	}
	state, _, err1 := auth.NewSecretToken()
	nonce, _, err2 := auth.NewSecretToken()
	if err1 != nil || err2 != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	pkce := oauth2.GenerateVerifier()
	s.setEphemeralCookie(w, r, oidcStateCookie, state)
	s.setEphemeralCookie(w, r, oidcNonceCookie, nonce)
	s.setEphemeralCookie(w, r, oidcVerifierCookie, pkce)
	http.Redirect(w, r, od.loginURL(state, nonce, pkce), http.StatusSeeOther)
}

func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	od := s.oidcProv()
	if od == nil {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	stateCookie, ok := s.readCookie(r, oidcStateCookie)
	if !ok || !auth.EqualToken(stateCookie, q.Get("state")) {
		http.Error(w, "invalid oidc state", http.StatusBadRequest)
		return
	}
	nonce, ok := s.readCookie(r, oidcNonceCookie)
	if !ok {
		http.Error(w, "invalid oidc nonce", http.StatusBadRequest)
		return
	}
	verifier, ok := s.readCookie(r, oidcVerifierCookie)
	if !ok {
		http.Error(w, "invalid oidc session", http.StatusBadRequest)
		return
	}
	s.clearCookie(w, r, oidcStateCookie)
	s.clearCookie(w, r, oidcNonceCookie)
	s.clearCookie(w, r, oidcVerifierCookie)

	code := q.Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}
	claims, err := od.authenticate(r.Context(), code, nonce, verifier)
	if err != nil || claims == nil || claims.Subject == "" {
		log.Printf("egret-nest: oidc authenticate: %v", err)
		http.Error(w, "authentication failed", http.StatusBadGateway)
		return
	}

	// Authorization is enforced on EVERY login (not just first provisioning): when
	// a domain allowlist is configured, the email must be IdP-verified AND match
	// the domain - so an unverified/spoofed email can't bypass the gate, and a
	// user later removed from the domain loses access.
	if od.allowedDomain != "" {
		if !claims.EmailVerified {
			// Don't record the raw, IdP-unverified email as the audit "actor" (it is
			// attacker-influenceable and unverified); note it, capped, in the detail.
			s.audit(r, "", "login.oidc.denied", "email not verified by IdP: "+capForAudit(claims.Email))
			http.Error(w, "this account is not authorized", http.StatusForbidden)
			return
		}
		if !od.domainAllowed(claims.Email) {
			s.audit(r, claims.Email, "login.oidc.denied", "email domain not allowed")
			http.Error(w, "this account is not authorized", http.StatusForbidden)
			return
		}
	}

	subject := "oidc:" + claims.Subject
	user, err := s.store.GetUserByExternalID(subject)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if user == nil {
		user, err = s.provisionOIDCUser(claims.Email, subject)
		if err != nil {
			log.Printf("egret-nest: provisioning oidc user: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	if err := s.startSession(w, r, user.ID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.audit(r, user.Login, "login.oidc", "")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) provisionOIDCUser(email, subject string) (*model.User, error) {
	login := oidcLoginFromEmail(email)
	if u, _ := s.store.GetUserByLogin(login); u != nil {
		login = login + "-" + auth.HashToken(subject)[:8]
	}
	uid, err := s.store.CreateUser(&model.User{Login: login, Email: email, ExternalID: subject})
	if err != nil {
		return nil, err
	}
	// Fail closed: no org membership on provisioning - an instance admin grants
	// access on /admin/users. The IdP-domain gate is authN, not authZ to telemetry.
	return s.store.GetUserByID(uid)
}

// oidcLoginFromEmail derives a login from the email local-part, restricted to the
// login charset.
func oidcLoginFromEmail(email string) string {
	local := email
	if i := strings.IndexByte(email, '@'); i > 0 {
		local = email[:i]
	}
	var b strings.Builder
	for _, c := range strings.ToLower(local) {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' {
			b.WriteRune(c)
		}
	}
	if s := strings.Trim(b.String(), "._-"); s != "" {
		return s
	}
	return "sso-user"
}

// oidcName returns the SSO button label, or "" when OIDC is disabled.
func (s *Server) oidcName() string {
	od := s.oidcProv()
	if od == nil {
		return ""
	}
	return od.name
}
