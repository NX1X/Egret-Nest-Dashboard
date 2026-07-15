package server

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/NX1X/Egret-Nest-Dashboard/internal/auth"
	"github.com/NX1X/Egret-Nest-Dashboard/internal/model"
)

type ctxKey int

const userCtxKey ctxKey = 0

const (
	sessionCookie = "egret_session"
	csrfCookie    = "egret_csrf"
	sessionTTL    = 12 * time.Hour
)

// secure reports whether the request is effectively HTTPS, controlling the
// Secure cookie attribute + HSTS. The X-Forwarded-Proto header is trusted ONLY
// when the deployment declares it is behind a trusted TLS-terminating proxy
// (EGRET_NEST_BEHIND_PROXY); otherwise a direct HTTP client could forge it.
func (s *Server) secure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return s.cfg.BehindProxy && r.Header.Get("X-Forwarded-Proto") == "https"
}

// securityHeaders sets strict headers on every response. Our UI is server-
// rendered, styled from a single same-origin stylesheet (/static/app.css) with no
// inline CSS and no JavaScript at all, so the CSP is maximally tight:
// style-src 'self' (no 'unsafe-inline'), script-src 'none'.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'none'; style-src 'self'; img-src 'self' data:; "+
				"script-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		if s.secure(r) {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// statusWriter wraps http.ResponseWriter to capture the status code for logging.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// accessLog records each request (method, path, status, duration, user) to the
// console and the in-memory ring buffer that powers the admin "Logs" page. It
// runs after sessionLoader so the authenticated user is known. Sensitive query
// strings are dropped — only the path is recorded.
func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		dur := time.Since(start)
		user := ""
		if u := currentUser(r); u != nil {
			user = u.Login
		}
		entry := AccessEntry{
			Time: start, Method: r.Method, Path: r.URL.Path, Status: sw.status,
			DurMS: dur.Milliseconds(), IP: clientIP(r), User: user,
		}
		s.logs.add(entry)
		who := user
		if who == "" {
			who = "-"
		}
		// %q escapes CR/LF/control bytes in the (percent-decoded) path so a crafted
		// request target can't forge log lines (CWE-117). The ring buffer is safe —
		// it's rendered via html/template.
		log.Printf("egret-nest: %s %q %d %dms ip=%s user=%s",
			r.Method, r.URL.Path, sw.status, dur.Milliseconds(), entry.IP, who)
	})
}

// recoverPanic converts a handler panic into a 500 without leaking the stack.
func (s *Server) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("egret-nest: panic serving %q: %v", r.URL.Path, rec)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// sessionLoader resolves the session cookie to a user and stores it in the
// request context (nil when unauthenticated). It never rejects — requireAuth does.
func (s *Server) sessionLoader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if val, ok := s.readCookie(r, sessionCookie); ok {
			if sess, _ := s.store.GetSessionByToken(auth.HashToken(val)); sess != nil {
				if u, _ := s.store.GetUserByID(sess.UserID); u != nil {
					_ = s.store.TouchSession(sess.TokenHash)
					r = r.WithContext(context.WithValue(r.Context(), userCtxKey, u))
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// currentUser returns the authenticated user or nil.
func currentUser(r *http.Request) *model.User {
	u, _ := r.Context().Value(userCtxKey).(*model.User)
	return u
}

// requireAuth wraps a handler, redirecting anonymous users to /login.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if currentUser(r) == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

// requireAdmin wraps a handler for instance-admin-only pages (e.g. the audit
// log): anonymous users are sent to /login, authenticated non-admins get a 404 —
// not a 403 — so the page's existence isn't confirmed to a non-admin.
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := currentUser(r)
		if u == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if !u.IsAdmin {
			http.NotFound(w, r)
			return
		}
		next(w, r)
	}
}

// --- cookie helpers ---

// cookieName applies the __Host- prefix on secure connections. The prefix locks a
// cookie to host-only + Path=/ + Secure (the browser rejects it otherwise), which
// blocks subdomain/overwrite attacks. It REQUIRES Secure, so on plain-HTTP dev we
// fall back to the bare name. secure(r) is deterministic for a deployment, so the
// name used to set a cookie is the same one used to read it.
func (s *Server) cookieName(r *http.Request, base string) string {
	if s.secure(r) {
		return "__Host-" + base
	}
	return base
}

// readCookie fetches a cookie by its (possibly prefixed) name.
func (s *Server) readCookie(r *http.Request, base string) (string, bool) {
	if c, err := r.Cookie(s.cookieName(r, base)); err == nil && c.Value != "" {
		return c.Value, true
	}
	return "", false
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(r, sessionCookie),
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   s.secure(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(r, sessionCookie),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secure(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// --- CSRF (double-submit cookie, server-rendered token) ---

// csrfToken returns the request's CSRF token, minting + setting the cookie if
// absent. The token is rendered into forms and re-checked on unsafe methods.
func (s *Server) csrfToken(w http.ResponseWriter, r *http.Request) string {
	if val, ok := s.readCookie(r, csrfCookie); ok {
		return val
	}
	tok, _, err := auth.NewSecretToken()
	if err != nil {
		return ""
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(r, csrfCookie),
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secure(r),
		SameSite: http.SameSiteLaxMode,
	})
	return tok
}

// checkCSRF verifies the form token against the cookie (constant-time). Call on
// every state-changing, cookie-authenticated request. (POST /ingest is exempt:
// it is bearer-token authenticated, carries no cookies, so is not CSRF-able.)
func (s *Server) checkCSRF(r *http.Request) bool {
	cookie, ok := s.readCookie(r, csrfCookie)
	if !ok {
		return false
	}
	form := r.PostFormValue("_csrf")
	if form == "" {
		form = r.Header.Get("X-CSRF-Token")
	}
	return form != "" && auth.EqualToken(cookie, form)
}
