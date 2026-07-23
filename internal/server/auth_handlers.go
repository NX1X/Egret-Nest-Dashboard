package server

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/NX1X/Egret-Nest-Dashboard/internal/auth"
	"github.com/NX1X/Egret-Nest-Dashboard/internal/model"
)

const minPasswordLen = 12

// dummyPasswordHash is a valid-format argon2id hash (default params) used to
// equalize login timing. When the login is unknown or the account has no local
// password, we still run one argon2id verification against this hash before
// returning the generic failure, so response time doesn't reveal whether an
// account exists (user-enumeration side-channel). Computed once at package init.
var dummyPasswordHash = mustDummyPasswordHash()

func mustDummyPasswordHash() string {
	h, err := auth.HashPassword("egret-nest-login-timing-equalizer")
	if err != nil {
		panic("egret-nest: computing dummy password hash: " + err.Error())
	}
	return h
}

// handleSetupForm renders the first-run bootstrap-admin form (only when there are
// no users yet).
func (s *Server) handleSetupForm(w http.ResponseWriter, r *http.Request) {
	// Gate on the dedicated `bootstrapped` flag (not a raw user count): a non-admin
	// account created by another path must not be able to retire the setup page.
	if done, _ := s.store.Bootstrapped(); done {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, "setup.html", map[string]any{
		"Instance": s.instanceName(),
		"CSRF":     s.csrfToken(w, r),
	})
}

// handleSetup creates the first admin user + a default org atomically, then logs
// them in. It requires the one-time setup token (so an unauthenticated attacker
// can't claim the admin before the operator) and the creation is a single atomic
// claim (so two concurrent requests can't both mint an admin).
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if done, _ := s.store.Bootstrapped(); done {
		http.Error(w, "setup already completed", http.StatusForbidden)
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	// One-time setup token (constant-time). A nil pointer means the token was never
	// set or was already burned, which only happens after the server minted+logged
	// one - so it's always required.
	tok := s.setupToken.Load()
	if tok == nil || *tok == "" || !auth.EqualToken(*tok, r.PostFormValue("setup_token")) {
		s.audit(r, "", "setup.denied", "bad or missing setup token")
		s.renderSetupError(w, r, "invalid setup token - see the server log at first start")
		return
	}
	login := strings.TrimSpace(r.PostFormValue("login"))
	password := r.PostFormValue("password")

	if err := validateLogin(login); err != "" {
		s.renderSetupError(w, r, err)
		return
	}
	if len(password) < minPasswordLen {
		s.renderSetupError(w, r, fmt.Sprintf("password must be at least %d characters", minPasswordLen))
		return
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	uid, ok, err := s.store.BootstrapAdmin(login, hash)
	if err != nil {
		log.Printf("egret-nest: bootstrap admin: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok {
		// Lost the race - someone bootstrapped concurrently. Fail closed.
		http.Error(w, "setup already completed", http.StatusForbidden)
		return
	}
	s.setupToken.Store(nil) // one-time: burn it after a successful bootstrap
	s.audit(r, login, "setup", "bootstrap admin created")

	if err := s.startSession(w, r, uid); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// handleLoginForm renders the login page.
func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	if currentUser(r) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if done, _ := s.store.Bootstrapped(); !done {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	s.render(w, "login.html", map[string]any{
		"Instance": s.instanceName(),
		"CSRF":     s.csrfToken(w, r),
		"GitHub":   s.ghOAuth() != nil,
		"OIDCName": s.oidcName(),
	})
}

// handleLogin verifies password (+ TOTP when enabled) and starts a session.
// All failures return the same generic message to avoid user enumeration.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	login := strings.TrimSpace(r.PostFormValue("login"))
	password := r.PostFormValue("password")
	totpCode := r.PostFormValue("totp")

	// Validate the login shape before touching the DB, audit log, or rate limiter
	// so an attacker cannot submit oversized/garbage identifiers.
	if validateLogin(login) != "" {
		s.audit(r, "", "login.failed", "invalid login format")
		s.renderLoginError(w, r, "invalid credentials")
		return
	}

	now := time.Now()
	key := clientIP(r) + "|" + strings.ToLower(login)
	if s.loginLimiter.blocked(key, now) {
		s.audit(r, login, "login.blocked", "too many failed attempts")
		s.renderStatus(w, http.StatusTooManyRequests, "login.html", map[string]any{
			"Instance": s.instanceName(), "CSRF": s.csrfToken(w, r), "GitHub": s.ghOAuth() != nil,
			"OIDCName": s.oidcName(), "Error": "too many attempts - try again later",
		})
		return
	}
	// fail records the failed attempt against the limiter, then shows a generic error.
	fail := func() {
		s.loginLimiter.fail(key, now)
		s.renderLoginError(w, r, "invalid credentials")
	}

	user, err := s.store.GetUserByLogin(login)
	if err != nil {
		// A decrypt failure here (e.g. EGRET_NEST_SECRET_KEY lost/rotated) would
		// otherwise be an unexplained 500 + total lockout - log it so operators can
		// see the cause. See docs/AUTH.md "TOTP-at-rest key rotation".
		log.Printf("egret-nest: loading user %q for login: %v", login, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if user == nil || user.PasswordHash == "" {
		// Run a dummy argon2id verification so this path takes about the same wall
		// time as a real password check - otherwise a fast "no such user" response
		// leaks which logins exist. Result is intentionally discarded.
		_, _ = auth.VerifyPassword(password, dummyPasswordHash)
		s.audit(r, login, "login.failed", "unknown user or non-local account")
		fail()
		return
	}
	ok, err := auth.VerifyPassword(password, user.PasswordHash)
	if err != nil || !ok {
		s.audit(r, login, "login.failed", "bad password")
		fail()
		return
	}
	if user.TOTPEnabled {
		counter, ok := auth.VerifyTOTPCounter(user.TOTPSecret, totpCode, time.Now(), 1)
		if !ok {
			s.audit(r, login, "login.failed", "bad totp")
			fail()
			return
		}
		// Anti-replay: a code is valid for its whole skew window; consume it once.
		claimed, err := s.store.ClaimTOTPCode(user.ID, counter)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !claimed {
			s.audit(r, login, "login.failed", "totp replay")
			fail()
			return
		}
	}

	s.loginLimiter.reset(key) // clear failure count on success
	if err := s.startSession(w, r, user.ID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.audit(r, login, "login", "")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// handleLogout revokes the current session.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	if val, ok := s.readCookie(r, sessionCookie); ok {
		_ = s.store.DeleteSession(auth.HashToken(val))
	}
	if u := currentUser(r); u != nil {
		s.audit(r, u.Login, "logout", "")
	}
	s.clearSessionCookie(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// startSession mints a fresh random session token, persists its hash, and sets
// the cookie. Sessions are only ever created here (at successful auth) with a new
// random id - there is no pre-auth session that gets "upgraded" - so session
// fixation does not apply. We do not delete the user's other sessions, to allow
// concurrent devices; "sign out everywhere" (DeleteUserSessions) is a separate
// explicit action.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, userID int64) error {
	token, hash, err := auth.NewSecretToken()
	if err != nil {
		return err
	}
	expires := time.Now().Add(sessionTTL)
	if err := s.store.CreateSession(userID, hash, expires); err != nil {
		return err
	}
	s.setSessionCookie(w, r, token, expires)
	return nil
}

func (s *Server) renderSetupError(w http.ResponseWriter, r *http.Request, msg string) {
	s.renderStatus(w, http.StatusBadRequest, "setup.html",
		map[string]any{"Instance": s.instanceName(), "CSRF": s.csrfToken(w, r), "Error": msg})
}

func (s *Server) renderLoginError(w http.ResponseWriter, r *http.Request, msg string) {
	s.renderStatus(w, http.StatusUnauthorized, "login.html",
		map[string]any{"Instance": s.instanceName(), "CSRF": s.csrfToken(w, r),
			"GitHub": s.ghOAuth() != nil, "OIDCName": s.oidcName(), "Error": msg})
}

// audit records a security event; best-effort.
func (s *Server) audit(r *http.Request, actor, action, detail string) {
	_ = s.store.Audit(model.AuditEvent{ActorLogin: actor, Action: action, Detail: detail, IP: clientIP(r)})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// validateLogin returns an error message or "" if valid.
func validateLogin(login string) string {
	if login == "" {
		return "login is required"
	}
	if len(login) > 64 {
		return "login too long"
	}
	for _, c := range login {
		if !(c == '-' || c == '_' || c == '.' || c == '@' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return "login may contain only letters, digits, and - _ . @"
		}
	}
	return ""
}
