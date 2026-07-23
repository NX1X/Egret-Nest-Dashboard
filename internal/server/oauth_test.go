package server

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/NX1X/Egret-Nest-Dashboard/internal/store"
)

func newOAuthServer(t *testing.T, cfg Config) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	srv, err := New(st, cfg)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return srv, st
}

// mockGitHub returns an httptest server standing in for github.com +
// api.github.com. member controls the org-membership endpoint result.
func mockGitHub(t *testing.T, userJSON string, member bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login/oauth/access_token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"gho_test"}`))
	})
	mux.HandleFunc("GET /user", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(userJSON))
	})
	mux.HandleFunc("GET /user/memberships/orgs/{org}", func(w http.ResponseWriter, _ *http.Request) {
		if member {
			w.Write([]byte(`{"state":"active"}`))
		} else {
			http.Error(w, "not found", http.StatusNotFound)
		}
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

const testBaseURL = "https://dash.example"

func pointOAuthAt(srv *Server, gh *httptest.Server) {
	o := srv.oauth.Load()
	o.tokenURL = gh.URL + "/login/oauth/access_token"
	o.apiURL = gh.URL
	o.authorizeURL = gh.URL + "/authorize"
}

func noRedirectClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

// beginLogin performs GET /auth/github/login and returns the CSRF state param.
func beginLogin(t *testing.T, c *http.Client, base string) string {
	t.Helper()
	resp, err := c.Get(base + "/auth/github/login")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login status = %d, want 303", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	return loc.Query().Get("state")
}

func TestGitHubOAuthProvisionsAndLogsIn(t *testing.T) {
	gh := mockGitHub(t, `{"login":"alice","id":12345,"email":"a@x"}`, true)
	srv, st := newOAuthServer(t, Config{GitHubClientID: "id", GitHubClientSecret: "sec", GitHubAllowedOrg: "acme", BaseURL: testBaseURL})
	// The instance must be bootstrapped before SSO auto-provisioning is allowed.
	if err := st.SetSetting("bootstrapped", "1"); err != nil {
		t.Fatalf("mark bootstrapped: %v", err)
	}
	pointOAuthAt(srv, gh)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	c := noRedirectClient()
	state := beginLogin(t, c, ts.URL)
	if state == "" {
		t.Fatal("no state in authorize redirect")
	}

	resp, err := c.Get(ts.URL + "/auth/github/callback?code=abc&state=" + state)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("callback = %d loc %q body %s", resp.StatusCode, resp.Header.Get("Location"), body)
	}
	resp.Body.Close()

	// User is provisioned and linked by GitHub id.
	u, _ := st.GetUserByExternalID("github:12345")
	if u == nil || u.Login != "alice" || u.PasswordHash != "" {
		t.Fatalf("user not provisioned as expected: %+v", u)
	}

	// Fail-closed authorization: passing the GitHub-org gate is authentication,
	// not access to any tenant. A freshly-provisioned SSO user must have ZERO org
	// memberships until an instance admin grants one - otherwise every org member
	// could read every connected repo's telemetry (N7 cross-tenant blocker).
	mships, err := st.MembershipsForUser(u.ID)
	if err != nil {
		t.Fatalf("memberships: %v", err)
	}
	if len(mships) != 0 {
		t.Fatalf("provisioned SSO user has %d memberships, want 0 (cross-tenant leak): %+v", len(mships), mships)
	}

	// The session works: authenticated index returns 200.
	resp, err = c.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("index: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("authenticated index = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestGitHubOAuthRejectedBeforeBootstrap: a brand-new GitHub account must NOT be
// auto-provisioned before first-run setup completes. After setup, it works.
func TestGitHubOAuthRejectedBeforeBootstrap(t *testing.T) {
	gh := mockGitHub(t, `{"login":"newbie","id":54321,"email":"n@x"}`, true)
	srv, st := newOAuthServer(t, Config{GitHubClientID: "id", GitHubClientSecret: "sec", GitHubAllowedOrg: "acme", BaseURL: testBaseURL})
	pointOAuthAt(srv, gh)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	c := noRedirectClient()
	state := beginLogin(t, c, ts.URL)
	resp, _ := c.Get(ts.URL + "/auth/github/callback?code=abc&state=" + state)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("SSO login before bootstrap = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
	if u, _ := st.GetUserByExternalID("github:54321"); u != nil {
		t.Fatalf("SSO user was provisioned before bootstrap: %+v", u)
	}

	// Complete first-run setup, then the same login provisions and succeeds.
	if _, ok, err := st.BootstrapAdmin("admin", "hash"); err != nil || !ok {
		t.Fatalf("bootstrap admin: ok=%v err=%v", ok, err)
	}
	c2 := noRedirectClient()
	state2 := beginLogin(t, c2, ts.URL)
	resp2, _ := c2.Get(ts.URL + "/auth/github/callback?code=abc&state=" + state2)
	if resp2.StatusCode != http.StatusSeeOther {
		t.Fatalf("SSO login after bootstrap = %d, want 303", resp2.StatusCode)
	}
	resp2.Body.Close()
	if u, _ := st.GetUserByExternalID("github:54321"); u == nil {
		t.Fatal("SSO user not provisioned after bootstrap")
	}
}

func TestGitHubOAuthDeniedWhenNotInOrg(t *testing.T) {
	gh := mockGitHub(t, `{"login":"eve","id":999}`, false)
	srv, _ := newOAuthServer(t, Config{GitHubClientID: "id", GitHubClientSecret: "sec", GitHubAllowedOrg: "acme", BaseURL: testBaseURL})
	pointOAuthAt(srv, gh)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	c := noRedirectClient()
	state := beginLogin(t, c, ts.URL)
	resp, _ := c.Get(ts.URL + "/auth/github/callback?code=c&state=" + state)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-member should be 403, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestGitHubCallbackRejectsBadState(t *testing.T) {
	srv, _ := newOAuthServer(t, Config{GitHubClientID: "id", GitHubClientSecret: "sec", BaseURL: testBaseURL})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	// No state cookie set -> reject.
	resp, _ := http.Get(ts.URL + "/auth/github/callback?code=x&state=y")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad state = %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestGitHubDisabledWhenUnconfigured(t *testing.T) {
	srv, _ := newOAuthServer(t, Config{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	resp, _ := http.Get(ts.URL + "/auth/github/login")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unconfigured login = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()
}
