package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/NX1X/Egret-Nest-Dashboard/internal/auth"
	"github.com/NX1X/Egret-Nest-Dashboard/internal/model"
)

const oauthStateCookie = "egret_oauth_state"

var oauthHTTP = &http.Client{Timeout: 15 * time.Second}

// githubOAuth implements "Login with GitHub" via the Egret GitHub App's OAuth
// (user-to-server) flow. The token endpoints are fields so tests can point them
// at a mock server.
type githubOAuth struct {
	clientID     string
	clientSecret string
	allowedOrg   string // if set, non-linked users are auto-provisioned only when a member
	authorizeURL string
	tokenURL     string
	apiURL       string
}

// newGithubOAuth returns a provider, or nil when OAuth is not configured.
func newGithubOAuth(cfg Config) *githubOAuth {
	if cfg.GitHubClientID == "" || cfg.GitHubClientSecret == "" {
		return nil
	}
	return &githubOAuth{
		clientID:     cfg.GitHubClientID,
		clientSecret: cfg.GitHubClientSecret,
		allowedOrg:   cfg.GitHubAllowedOrg,
		authorizeURL: "https://github.com/login/oauth/authorize",
		tokenURL:     "https://github.com/login/oauth/access_token",
		apiURL:       "https://api.github.com",
	}
}

func (g *githubOAuth) loginURL(state, redirectURI string) string {
	v := url.Values{}
	v.Set("client_id", g.clientID)
	v.Set("redirect_uri", redirectURI)
	v.Set("state", state)
	v.Set("scope", "read:org")
	return g.authorizeURL + "?" + v.Encode()
}

// exchange trades an authorization code for a user access token.
func (g *githubOAuth) exchange(ctx context.Context, code, redirectURI string) (string, error) {
	form := url.Values{}
	form.Set("client_id", g.clientID)
	form.Set("client_secret", g.clientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := oauthHTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("token endpoint: %s", resp.Status)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", err
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("oauth exchange failed: %s", out.Error)
	}
	return out.AccessToken, nil
}

// apiGet performs an authenticated GET, decoding out on a 2xx, and returns the
// status code (so callers can branch on 404 etc.).
func (g *githubOAuth) apiGet(ctx context.Context, token, path string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.apiURL+path, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "egret-nest")
	resp, err := oauthHTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 5<<20)) //nolint:errcheck
		resp.Body.Close()
	}()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && out != nil {
		if err := json.NewDecoder(io.LimitReader(resp.Body, 5<<20)).Decode(out); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

// fetchUser returns the authenticated user's login, numeric id, and email.
func (g *githubOAuth) fetchUser(ctx context.Context, token string) (login string, id int64, email string, err error) {
	var u struct {
		Login string `json:"login"`
		ID    int64  `json:"id"`
		Email string `json:"email"`
	}
	code, err := g.apiGet(ctx, token, "/user", &u)
	if err != nil {
		return "", 0, "", err
	}
	if code < 200 || code >= 300 {
		return "", 0, "", fmt.Errorf("/user: status %d", code)
	}
	return u.Login, u.ID, u.Email, nil
}

// isOrgMember reports whether the user is an active member of the allowed org.
// Uses the single-membership endpoint (no pagination) and fails closed. Returns
// false when no allowed org is configured.
func (g *githubOAuth) isOrgMember(ctx context.Context, token string) (bool, error) {
	if g.allowedOrg == "" {
		return false, nil
	}
	var out struct {
		State string `json:"state"`
	}
	code, err := g.apiGet(ctx, token, "/user/memberships/orgs/"+url.PathEscape(g.allowedOrg), &out)
	if err != nil {
		return false, err
	}
	if code == http.StatusNotFound || code == http.StatusForbidden {
		return false, nil // not a member / membership not visible
	}
	if code < 200 || code >= 300 {
		return false, fmt.Errorf("org membership check: status %d", code)
	}
	return out.State == "active", nil
}

// --- handlers ---

// oauthRedirectURI is derived solely from the configured BaseURL - never from the
// request Host header - so a spoofed Host can't redirect the code/token. New()
// requires BaseURL whenever OAuth is enabled.
func (s *Server) oauthRedirectURI() string {
	return strings.TrimRight(s.cfg.BaseURL, "/") + "/auth/github/callback"
}

func (s *Server) handleGithubLogin(w http.ResponseWriter, r *http.Request) {
	gh := s.ghOAuth()
	if gh == nil {
		http.NotFound(w, r)
		return
	}
	state, _, err := auth.NewSecretToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.setEphemeralCookie(w, r, oauthStateCookie, state)
	http.Redirect(w, r, gh.loginURL(state, s.oauthRedirectURI()), http.StatusSeeOther)
}

func (s *Server) handleGithubCallback(w http.ResponseWriter, r *http.Request) {
	gh := s.ghOAuth()
	if gh == nil {
		http.NotFound(w, r)
		return
	}
	// CSRF: the state in the callback must match the cookie set at /login.
	q := r.URL.Query()
	stateCookie, ok := s.readCookie(r, oauthStateCookie)
	if !ok || !auth.EqualToken(stateCookie, q.Get("state")) {
		http.Error(w, "invalid oauth state", http.StatusBadRequest)
		return
	}
	s.clearCookie(w, r, oauthStateCookie)

	code := q.Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	token, err := gh.exchange(ctx, code, s.oauthRedirectURI())
	if err != nil {
		log.Printf("egret-nest: oauth exchange: %v", err)
		http.Error(w, "authentication failed", http.StatusBadGateway)
		return
	}
	login, id, email, err := gh.fetchUser(ctx, token)
	if err != nil || id == 0 {
		log.Printf("egret-nest: oauth user fetch: %v", err)
		http.Error(w, "authentication failed", http.StatusBadGateway)
		return
	}
	subject := fmt.Sprintf("github:%d", id)

	user, err := s.store.GetUserByExternalID(subject)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Authorization is re-verified on EVERY login. With an allowed org, the user
	// must currently be a member (so revoked members lose access); new members
	// are auto-provisioned. Without an allowed org, only pre-linked accounts may
	// sign in (secure by default).
	if gh.allowedOrg != "" {
		member, err := gh.isOrgMember(ctx, token)
		if err != nil {
			log.Printf("egret-nest: oauth org check: %v", err)
			http.Error(w, "authentication failed", http.StatusBadGateway)
			return
		}
		if !member {
			s.audit(r, login, "login.github.denied", "not a current member of the allowed org")
			http.Error(w, "this GitHub account is not authorized", http.StatusForbidden)
			return
		}
		if user == nil {
			if !s.ssoProvisioningAllowed(w, r, login, "login.github.denied") {
				return
			}
			user, err = s.provisionGithubUser(login, subject, email)
			if err != nil {
				log.Printf("egret-nest: provisioning github user: %v", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}
	} else if user == nil {
		s.audit(r, login, "login.github.denied", "account not provisioned")
		http.Error(w, "this GitHub account is not provisioned for access", http.StatusForbidden)
		return
	}

	if err := s.startSession(w, r, user.ID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.audit(r, user.Login, "login.github", "")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ssoProvisioningAllowed reports whether a brand-new SSO account may be
// auto-provisioned right now. It refuses (writing a 403 + audit) while the
// instance is not yet bootstrapped, so an SSO login can't create the very first
// account and squat the instance before the operator completes /setup. Callers
// invoke it only when the linked account does not yet exist; an already-existing
// user logging in is never gated here.
func (s *Server) ssoProvisioningAllowed(w http.ResponseWriter, r *http.Request, actor, deniedAction string) bool {
	done, err := s.store.Bootstrapped()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return false
	}
	if !done {
		s.audit(r, actor, deniedAction, "instance not yet bootstrapped")
		http.Error(w, "complete first-run setup before SSO login is available", http.StatusForbidden)
		return false
	}
	return true
}

// provisionGithubUser creates a member account linked to the GitHub identity,
// choosing a non-colliding login.
func (s *Server) provisionGithubUser(login, subject, email string) (*model.User, error) {
	candidate := login
	if candidate == "" {
		candidate = "github-user"
	}
	if u, _ := s.store.GetUserByLogin(candidate); u != nil {
		candidate = fmt.Sprintf("%s-gh%s", login, strings.TrimPrefix(subject, "github:"))
	}
	uid, err := s.store.CreateUser(&model.User{Login: candidate, Email: email, ExternalID: subject})
	if err != nil {
		return nil, err
	}
	// Fail closed: a newly-provisioned SSO user gets NO org membership, so they can
	// see nothing until an instance admin grants access on /admin/users. Passing the
	// GitHub-org gate is authentication, not authorization to a repo's telemetry.
	return s.store.GetUserByID(uid)
}
