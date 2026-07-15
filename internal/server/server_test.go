package server

import (
	"bytes"
	"encoding/json"
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

// testSetupToken is the fixed first-run setup token used by the test helpers.
const testSetupToken = "test-setup-token-0123456789"

func newTestServer(t *testing.T, cfg Config) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if cfg.SetupToken == "" {
		cfg.SetupToken = testSetupToken
	}
	srv, err := New(st, cfg)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); st.Close() })
	return ts, st
}

func sampleBody() []byte {
	env := model.Envelope{
		SchemaVersion: model.SchemaVersion,
		Producer:      "egret",
		Run:           model.RunMeta{Repository: "a/b", SHA: "abcdef1234567890", Workflow: "CI"},
		Session: &model.Session{
			Mode:        "block",
			Connections: []model.Connection{{Comm: "curl", Domain: "github.com", Daddr: "1.1.1.1", Dport: 443, Proto: "tcp"}},
			Violations:  []model.Violation{{Kind: "connection", Reason: "raw-ip egress", Detail: "8.8.8.8", Blocked: true}},
		},
	}
	b, _ := json.Marshal(env)
	return b
}

// csrfFrom returns the current CSRF cookie value the server set in the jar.
func csrfFrom(t *testing.T, jar http.CookieJar, base string) string {
	t.Helper()
	u, _ := url.Parse(base)
	for _, c := range jar.Cookies(u) {
		if c.Name == csrfCookie {
			return c.Value
		}
	}
	t.Fatal("no csrf cookie set")
	return ""
}

// authedClient completes first-run setup and returns a logged-in client.
func authedClient(t *testing.T, ts *httptest.Server) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	// GET /setup to receive the CSRF cookie.
	if _, err := client.Get(ts.URL + "/setup"); err != nil {
		t.Fatalf("get setup: %v", err)
	}
	form := url.Values{
		"_csrf":       {csrfFrom(t, jar, ts.URL)},
		"setup_token": {testSetupToken},
		"login":       {"admin"},
		"password":    {"supersecretpassword"},
	}
	resp, err := client.PostForm(ts.URL+"/setup", form)
	if err != nil {
		t.Fatalf("post setup: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK { // followed redirect to /
		t.Fatalf("setup landed on %d, want 200 (index)", resp.StatusCode)
	}
	return client
}

func TestUnauthenticatedRedirectsToLogin(t *testing.T) {
	ts, _ := newTestServer(t, Config{})
	// Don't follow redirects.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, _ := client.Get(ts.URL + "/")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Errorf("anon GET / = %d loc %q, want 303 -> /login", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp.Body.Close()
}

func TestSetupLoginAndRender(t *testing.T) {
	ts, _ := newTestServer(t, Config{OpenIngest: true})
	client := authedClient(t, ts)

	// Ingest a run (OpenIngest dev mode, no token needed).
	resp, err := client.Post(ts.URL+"/ingest", "application/json", bytes.NewReader(sampleBody()))
	if err != nil {
		t.Fatalf("post ingest: %v", err)
	}
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("ingest = %d, want 202", resp.StatusCode)
	}
	resp.Body.Close()

	// Authenticated index shows the repo.
	if body := getBody(t, client, ts.URL+"/"); !strings.Contains(body, "a/b") {
		t.Errorf("index missing repo:\n%s", body)
	}
	// Detail shows the violation.
	if body := getBody(t, client, ts.URL+"/runs/1"); !strings.Contains(body, "raw-ip egress") {
		t.Errorf("detail missing violation")
	}
	// Repos list + repo detail (N4 depth).
	if body := getBody(t, client, ts.URL+"/repos"); !strings.Contains(body, "a/b") {
		t.Errorf("repos page missing repo")
	}
	if body := getBody(t, client, ts.URL+"/repos/a/b"); !strings.Contains(body, "github.com") {
		t.Errorf("repo detail missing endpoint inventory")
	}
	// Security headers present.
	resp, _ = client.Get(ts.URL + "/")
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" ||
		resp.Header.Get("X-Frame-Options") != "DENY" ||
		resp.Header.Get("Content-Security-Policy") == "" {
		t.Errorf("missing security headers: %v", resp.Header)
	}
	resp.Body.Close()
}

func TestSecondSetupForbidden(t *testing.T) {
	ts, _ := newTestServer(t, Config{})
	authedClient(t, ts) // completes setup once

	// A second setup attempt is refused.
	jar, _ := cookiejar.New(nil)
	c2 := &http.Client{Jar: jar}
	c2.Get(ts.URL + "/setup") // gets redirected to /login now
	resp, _ := c2.PostForm(ts.URL+"/setup", url.Values{"_csrf": {"x"}, "login": {"eve"}, "password": {"supersecretpassword"}})
	if resp.StatusCode == http.StatusOK {
		t.Error("second setup should not succeed")
	}
	resp.Body.Close()
}

func TestIngestScopedToken(t *testing.T) {
	ts, st := newTestServer(t, Config{}) // no open ingest, no shared token
	orgID, _ := st.CreateOrg("acme")
	// Create a token scoped to repo a/b.
	pt := "tok_plain_value_123"
	hash := auth.HashToken(pt)
	if _, err := st.CreateIngestToken(&model.IngestToken{OrgID: orgID, Repository: "a/b", Name: "ci", TokenHash: hash}); err != nil {
		t.Fatalf("create token: %v", err)
	}

	// No token -> 401.
	resp, _ := http.Post(ts.URL+"/ingest", "application/json", bytes.NewReader(sampleBody()))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no token = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// Correct token -> 202.
	if code := postWithToken(t, ts.URL+"/ingest", pt, sampleBody()); code != http.StatusAccepted {
		t.Errorf("scoped token = %d, want 202", code)
	}

	// Token scoped to a/b, run for c/d -> 401.
	other := strings.Replace(string(sampleBody()), `"repository":"a/b"`, `"repository":"c/d"`, 1)
	if code := postWithToken(t, ts.URL+"/ingest", pt, []byte(other)); code != http.StatusUnauthorized {
		t.Errorf("wrong-repo token = %d, want 401", code)
	}
}

func TestIngestRejectsBadSchema(t *testing.T) {
	ts, _ := newTestServer(t, Config{OpenIngest: true})
	resp, _ := http.Post(ts.URL+"/ingest", "application/json", strings.NewReader(`{"schema_version":2}`))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()
}

func getBody(t *testing.T, c *http.Client, url string) string {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("get %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func postWithToken(t *testing.T, url, token string, body []byte) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}
