package server

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NX1X/Egret-Nest-Dashboard/internal/auth"
	"github.com/NX1X/Egret-Nest-Dashboard/internal/store"
)

// TestGuardedOIDCClientRefusesInternalIP: the OIDC client used for UI-configured
// issuers refuses to dial any host that resolves to an internal address (the DNS
// rebind / attacker-declared-token_endpoint SSRF guard), re-checking the resolved
// IP at dial time, while still allowing an external host through.
func TestGuardedOIDCClientRefusesInternalIP(t *testing.T) {
	tr := guardedOIDCClient().Transport.(*http.Transport)

	// A host that resolves to loopback (the cloud-metadata IP and any internal
	// service resolve the same way) is refused - even though a listener is up.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	if _, err := tr.DialContext(context.Background(), "tcp", "localhost:"+port); err == nil {
		t.Error("guarded client must refuse a dial that resolves to loopback")
	}

	// A literal internal IP is refused directly (no lookup needed).
	if _, err := tr.DialContext(context.Background(), "tcp", "169.254.169.254:80"); err == nil {
		t.Error("guarded client must refuse the link-local cloud-metadata IP")
	}
}

// newAuthCfgServer builds a server with at-rest encryption enabled (so UI secret
// storage works) and a BaseURL (required to enable SSO).
func newAuthCfgServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	box, err := auth.NewSecretBox("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff") // 32 bytes
	if err != nil {
		t.Fatalf("secretbox: %v", err)
	}
	st.UseSecretBox(box)
	srv, err := New(st, Config{BaseURL: "https://dash.example", SetupToken: testSetupToken})
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); st.Close() })
	return ts, st
}

// TestAuthConfigStoresSecretEncrypted: saving a GitHub client secret via the UI
// stores it ENCRYPTED (never plaintext) and enables the provider (login button).
func TestAuthConfigStoresSecretEncrypted(t *testing.T) {
	ts, st := newAuthCfgServer(t)
	admin := authedClient(t, ts)

	resp := post(t, admin, ts, "/admin/auth", url.Values{
		"action": {"github_save"}, "client_id": {"gh-client"},
		"client_secret": {"s3cr3t-value"}, "allowed_org": {"acme"},
	})
	resp.Body.Close()

	// The raw setting is ciphertext, not the plaintext secret.
	raw, _ := st.GetSetting(keyGHClientSecret)
	if raw == "" || strings.Contains(raw, "s3cr3t-value") {
		t.Fatalf("secret not stored encrypted: %q", raw)
	}
	// It decrypts back to the original.
	got, err := st.GetSecretSetting(keyGHClientSecret)
	if err != nil || got != "s3cr3t-value" {
		t.Fatalf("decrypt = %q, %v", got, err)
	}
	// The provider is now live: the login page (fetched anonymously - a logged-in
	// client would be redirected away from the form) offers the GitHub button.
	anon := &http.Client{}
	if body := getBody(t, anon, ts.URL+"/login"); !strings.Contains(body, "/auth/github/login") {
		t.Errorf("GitHub login not enabled after UI save")
	}
	// The page never reflects the secret back.
	if body := getBody(t, admin, ts.URL+"/admin/auth"); strings.Contains(body, "s3cr3t-value") {
		t.Errorf("secret leaked into the auth config page")
	}
}

// TestAuthConfigEnvPrecedence: a provider set via env is authoritative and can't
// be edited/overwritten from the UI.
func TestAuthConfigEnvPrecedence(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	box, _ := auth.NewSecretBox("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	st.UseSecretBox(box)
	srv, err := New(st, Config{
		BaseURL: "https://dash.example", SetupToken: testSetupToken,
		GitHubClientID: "env-id", GitHubClientSecret: "env-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer func() { ts.Close(); st.Close() }()
	admin := authedClient(t, ts)

	// Attempt to overwrite via UI - must be refused, nothing written to the DB.
	resp := post(t, admin, ts, "/admin/auth", url.Values{
		"action": {"github_save"}, "client_id": {"ui-id"}, "client_secret": {"ui-secret"},
	})
	resp.Body.Close()
	if v, _ := st.GetSetting(keyGHClientID); v != "" {
		t.Fatalf("UI overwrote env-managed provider: stored %q", v)
	}
	if body := getBody(t, admin, ts.URL+"/admin/auth"); !strings.Contains(body, "env") {
		t.Errorf("auth page should mark GitHub as env-managed")
	}
}

// TestAuthConfigRefusesSecretWithoutKey: without EGRET_NEST_SECRET_KEY the UI must
// refuse to store a secret (never plaintext) and not enable the provider.
func TestAuthConfigRefusesSecretWithoutKey(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	// NOTE: no UseSecretBox → secrets can't be stored.
	srv, err := New(st, Config{BaseURL: "https://dash.example", SetupToken: testSetupToken})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer func() { ts.Close(); st.Close() }()
	admin := authedClient(t, ts)

	resp := post(t, admin, ts, "/admin/auth", url.Values{
		"action": {"github_save"}, "client_id": {"gh"}, "client_secret": {"nope"},
	})
	body := readAll(t, resp)
	resp.Body.Close()
	if raw, _ := st.GetSetting(keyGHClientSecret); raw != "" {
		t.Fatalf("secret stored without an encryption key: %q", raw)
	}
	if !strings.Contains(body, "EGRET_NEST_SECRET_KEY") {
		t.Errorf("expected a message about EGRET_NEST_SECRET_KEY, got:\n%s", body)
	}
}

// TestAuthConfigRequiresAdmin: non-admins can't reach the auth config page (GET or POST).
func TestAuthConfigRequiresAdmin(t *testing.T) {
	ts, st := newAuthCfgServer(t)
	authedClient(t, ts)
	member := loginAsNewMember(t, ts, st, "authmember", "authmember-pass1")
	for _, method := range []string{"GET", "POST"} {
		req, _ := http.NewRequest(method, ts.URL+"/admin/auth", nil)
		resp, err := member.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("non-admin %s /admin/auth = %d, want 404", method, resp.StatusCode)
		}
	}
}

// TestGitHubClearActuallyDisables is the regression test for the pentest's HIGH
// fail-open finding: disabling a provider must actually take the live login
// endpoint down (and clear the DB), never silently no-op while claiming success.
func TestGitHubClearActuallyDisables(t *testing.T) {
	ts, st := newAuthCfgServer(t)
	admin := authedClient(t, ts)

	// Enable via UI, confirm the login button appears (anon client).
	post(t, admin, ts, "/admin/auth", url.Values{
		"action": {"github_save"}, "client_id": {"gh"}, "client_secret": {"sec"},
	}).Body.Close()
	anon := &http.Client{}
	if b := getBody(t, anon, ts.URL+"/login"); !strings.Contains(b, "/auth/github/login") {
		t.Fatal("setup: GitHub login should be enabled")
	}

	// Disable; the button must be gone AND the stored config cleared.
	post(t, admin, ts, "/admin/auth", url.Values{"action": {"github_clear"}}).Body.Close()
	if b := getBody(t, anon, ts.URL+"/login"); strings.Contains(b, "/auth/github/login") {
		t.Error("GitHub login still live after clear (fail-open disable)")
	}
	if v, _ := st.GetSetting(keyGHClientID); v != "" {
		t.Errorf("GitHub config not cleared: %q", v)
	}
}

// TestOIDCSaveBlocksSSRFAndRollsBack: a UI-supplied issuer that resolves to an
// internal/loopback address is rejected (SSRF guard), and the attempted save is
// rolled back - nothing is stored and OIDC stays disabled.
func TestOIDCSaveBlocksSSRFAndRollsBack(t *testing.T) {
	ts, st := newAuthCfgServer(t)
	admin := authedClient(t, ts)

	resp := post(t, admin, ts, "/admin/auth", url.Values{
		"action": {"oidc_save"}, "issuer": {"https://127.0.0.1/oidc"},
		"client_id": {"oi"}, "client_secret": {"sec"},
	})
	body := readAll(t, resp)
	resp.Body.Close()

	if !strings.Contains(body, "internal") && !strings.Contains(body, "loopback") {
		t.Errorf("expected an SSRF/loopback rejection message, got:\n%s", body)
	}
	// Rolled back: no OIDC settings persisted.
	if v, _ := st.GetSetting(keyOIDCIssuer); v != "" {
		t.Errorf("issuer persisted despite SSRF block: %q", v)
	}
	if set, _ := st.HasSetting(keyOIDCClientSecret); set {
		t.Error("client secret persisted despite SSRF block")
	}
	// OIDC stays disabled on the login page.
	anon := &http.Client{}
	if b := getBody(t, anon, ts.URL+"/login"); strings.Contains(b, "/auth/oidc/login") {
		t.Error("OIDC login enabled despite a blocked issuer")
	}
}

// TestOIDCSaveRejectsNonHTTPSIssuer: http:// issuer is refused (scheme guard).
func TestOIDCSaveRejectsNonHTTPSIssuer(t *testing.T) {
	ts, st := newAuthCfgServer(t)
	admin := authedClient(t, ts)
	resp := post(t, admin, ts, "/admin/auth", url.Values{
		"action": {"oidc_save"}, "issuer": {"http://accounts.example.com"},
		"client_id": {"oi"}, "client_secret": {"sec"},
	})
	body := readAll(t, resp)
	resp.Body.Close()
	if !strings.Contains(body, "https") {
		t.Errorf("expected an https-required message, got:\n%s", body)
	}
	if v, _ := st.GetSetting(keyOIDCIssuer); v != "" {
		t.Errorf("non-https issuer persisted: %q", v)
	}
}

// TestAuthConfigRejectsBadCSRF: a POST without a valid CSRF token is 403 and does
// not change state.
func TestAuthConfigRejectsBadCSRF(t *testing.T) {
	ts, st := newAuthCfgServer(t)
	admin := authedClient(t, ts)
	resp, err := admin.PostForm(ts.URL+"/admin/auth", url.Values{
		"_csrf": {"wrong"}, "action": {"github_save"}, "client_id": {"x"}, "client_secret": {"y"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("bad-CSRF POST = %d, want 403", resp.StatusCode)
	}
	if v, _ := st.GetSetting(keyGHClientID); v != "" {
		t.Errorf("state changed despite bad CSRF: %q", v)
	}
}
