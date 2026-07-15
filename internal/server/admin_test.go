package server

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NX1X/Egret-Nest-Dashboard/internal/auth"
	"github.com/NX1X/Egret-Nest-Dashboard/internal/model"
	"github.com/NX1X/Egret-Nest-Dashboard/internal/store"
)

// TestCookieNamePrefix checks the __Host- prefix logic across the secure/insecure
// and behind-proxy cases (the naming must be deterministic per deployment).
func TestCookieNamePrefix(t *testing.T) {
	plain := &Server{}
	proxied := &Server{cfg: Config{BehindProxy: true}}

	httpReq := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	if got := plain.cookieName(httpReq, "egret_session"); got != "egret_session" {
		t.Errorf("plain HTTP name = %q, want unprefixed", got)
	}

	tlsReq := httptest.NewRequest(http.MethodGet, "https://x/", nil)
	tlsReq.TLS = &tls.ConnectionState{} // non-nil marks the request as TLS
	if got := plain.cookieName(tlsReq, "egret_session"); got != "__Host-egret_session" {
		t.Errorf("TLS name = %q, want __Host- prefix", got)
	}

	fwd := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	fwd.Header.Set("X-Forwarded-Proto", "https")
	if got := proxied.cookieName(fwd, "egret_session"); got != "__Host-egret_session" {
		t.Errorf("behind-proxy name = %q, want __Host- prefix", got)
	}
}

// TestHostCookiePrefixOverTLS asserts the CSRF cookie set over real TLS uses the
// __Host- prefix and the Secure attribute.
func TestHostCookiePrefixOverTLS(t *testing.T) {
	st := mustStore(t)
	srv, _ := New(st, Config{})
	ts := httptest.NewTLSServer(srv.Handler())
	defer ts.Close()

	resp, err := ts.Client().Get(ts.URL + "/setup")
	if err != nil {
		t.Fatalf("get setup over TLS: %v", err)
	}
	defer resp.Body.Close()
	var found bool
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-"+csrfCookie {
			found = true
			if !c.Secure || c.Path != "/" {
				t.Errorf("__Host- cookie missing Secure/Path=/: %+v", c)
			}
		}
		if c.Name == csrfCookie {
			t.Errorf("unprefixed csrf cookie set over TLS: %+v", c)
		}
	}
	if !found {
		t.Errorf("no __Host- csrf cookie among %v", resp.Cookies())
	}
}

func TestMetricsDisabledWithoutToken(t *testing.T) {
	ts, _ := newTestServer(t, Config{}) // no MetricsToken
	resp, _ := http.Get(ts.URL + "/metrics")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("metrics without token config = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestMetricsTokenGate(t *testing.T) {
	ts, _ := newTestServer(t, Config{MetricsToken: "m-secret-token-at-least-32-chars-long"})

	// No / wrong token -> 401.
	resp, _ := http.Get(ts.URL + "/metrics")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no token = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// Correct token -> 200 with prometheus text.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer m-secret-token-at-least-32-chars-long")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics with token = %d, want 200", resp.StatusCode)
	}
	body := readAll(t, resp)
	if !strings.Contains(body, "egret_nest_users") || !strings.Contains(body, "egret_nest_runs") {
		t.Errorf("metrics body missing series:\n%s", body)
	}
}

func TestAuditRequiresAdmin(t *testing.T) {
	ts, _ := newTestServer(t, Config{})

	// Anonymous -> redirect to /login.
	noRedir := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, _ := noRedir.Get(ts.URL + "/audit")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Errorf("anon /audit = %d -> %q, want 303 -> /login", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp.Body.Close()

	// Admin (from setup) -> 200 and sees the log page.
	admin := authedClient(t, ts)
	if body := getBody(t, admin, ts.URL+"/audit"); !strings.Contains(body, "audit log") {
		t.Errorf("admin /audit missing page:\n%s", body)
	}
}

func TestAuditNonAdminNotFound(t *testing.T) {
	ts, st := newTestServer(t, Config{})
	authedClient(t, ts) // creates the bootstrap admin + default org

	// Create a non-admin local user and log in as them.
	member := loginAsNewMember(t, ts, st, "member", "memberpassword1")
	resp, _ := member.Get(ts.URL + "/audit")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("non-admin /audit = %d, want 404 (existence hidden)", resp.StatusCode)
	}
	resp.Body.Close()
}

// --- helpers ---

func mustStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

// loginAsNewMember creates a non-admin local account and returns a client logged
// in as them via the real /login flow.
func loginAsNewMember(t *testing.T, ts *httptest.Server, st *store.Store, login, password string) *http.Client {
	t.Helper()
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if _, err := st.CreateUser(&model.User{Login: login, PasswordHash: hash}); err != nil {
		t.Fatalf("create member: %v", err)
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	if _, err := client.Get(ts.URL + "/login"); err != nil {
		t.Fatalf("get login: %v", err)
	}
	form := url.Values{"_csrf": {csrfFrom(t, jar, ts.URL)}, "login": {login}, "password": {password}}
	resp, err := client.PostForm(ts.URL+"/login", form)
	if err != nil {
		t.Fatalf("post login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member login landed on %d, want 200", resp.StatusCode)
	}
	return client
}
