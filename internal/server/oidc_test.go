package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"golang.org/x/oauth2"
)

// fakeOIDC builds an OIDC provider whose authenticate step returns preset claims
// (nonce echoed back), so the handler flow is tested without a real IdP/JWT.
func fakeOIDC(name, allowedDomain string, claims *oidcClaims, authErr error) *oidcProvider {
	return &oidcProvider{
		name:          name,
		clientID:      "cid",
		allowedDomain: allowedDomain,
		oauth2: &oauth2.Config{
			ClientID:    "cid",
			Endpoint:    oauth2.Endpoint{AuthURL: "https://idp.example/authorize", TokenURL: "https://idp.example/token"},
			RedirectURL: "https://dash.example/auth/oidc/callback",
			Scopes:      []string{"openid", "email"},
		},
		authenticate: func(_ context.Context, _, nonce, _ string) (*oidcClaims, error) {
			if authErr != nil {
				return nil, authErr
			}
			c := *claims
			c.Nonce = nonce
			return &c, nil
		},
	}
}

func beginOIDC(t *testing.T, c *http.Client, base string) string {
	t.Helper()
	resp, err := c.Get(base + "/auth/oidc/login")
	if err != nil {
		t.Fatalf("oidc login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("oidc login status = %d, want 303", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Host != "idp.example" {
		t.Errorf("authorize redirect host = %q, want idp.example", loc.Host)
	}
	return loc.Query().Get("state")
}

func TestOIDCProvisionAndLogin(t *testing.T) {
	srv, st := newOAuthServer(t, Config{BaseURL: testBaseURL})
	srv.oidc.Store(fakeOIDC("Okta", "acme.com",
		&oidcClaims{Subject: "sub-1", Email: "alice@acme.com", EmailVerified: true}, nil))
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	c := noRedirectClient()
	state := beginOIDC(t, c, ts.URL)
	if state == "" {
		t.Fatal("no state in authorize redirect")
	}

	resp, err := c.Get(ts.URL + "/auth/oidc/callback?code=abc&state=" + state)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("callback = %d loc %q body %s", resp.StatusCode, resp.Header.Get("Location"), body)
	}
	resp.Body.Close()

	u, _ := st.GetUserByExternalID("oidc:sub-1")
	if u == nil || u.Login != "alice" || u.Email != "alice@acme.com" || u.PasswordHash != "" {
		t.Fatalf("user not provisioned as expected: %+v", u)
	}

	resp, _ = c.Get(ts.URL + "/")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("authenticated index = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestOIDCDeniedByDomain(t *testing.T) {
	srv, _ := newOAuthServer(t, Config{BaseURL: testBaseURL})
	srv.oidc.Store(fakeOIDC("Okta", "acme.com",
		&oidcClaims{Subject: "sub-2", Email: "eve@evil.example"}, nil))
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	c := noRedirectClient()
	state := beginOIDC(t, c, ts.URL)
	resp, _ := c.Get(ts.URL + "/auth/oidc/callback?code=c&state=" + state)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("wrong-domain email should be 403, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

// An in-domain email that the IdP has NOT verified must be rejected when a
// domain allowlist is configured (can't spoof an in-domain address you don't own).
func TestOIDCDeniedUnverifiedEmail(t *testing.T) {
	srv, _ := newOAuthServer(t, Config{BaseURL: testBaseURL})
	srv.oidc.Store(fakeOIDC("Okta", "acme.com",
		&oidcClaims{Subject: "sub-3", Email: "mallory@acme.com", EmailVerified: false}, nil))
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	c := noRedirectClient()
	state := beginOIDC(t, c, ts.URL)
	resp, _ := c.Get(ts.URL + "/auth/oidc/callback?code=c&state=" + state)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("unverified in-domain email should be 403, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestOIDCRejectsBadState(t *testing.T) {
	srv, _ := newOAuthServer(t, Config{BaseURL: testBaseURL})
	srv.oidc.Store(fakeOIDC("Okta", "", &oidcClaims{Subject: "x"}, nil))
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/auth/oidc/callback?code=x&state=y") // no state cookie
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad state = %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestOIDCDisabledWhenUnconfigured(t *testing.T) {
	srv, _ := newOAuthServer(t, Config{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	resp, _ := http.Get(ts.URL + "/auth/oidc/login")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unconfigured oidc login = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestOIDCLoginFromEmail(t *testing.T) {
	cases := map[string]string{
		"alice@acme.com":     "alice",
		"bob.smith@acme.com": "bob.smith",
		"weird+tag@x.io":     "weirdtag",
		"+++@x.io":           "sso-user", // sanitizes to empty -> fallback
	}
	for in, want := range cases {
		if got := oidcLoginFromEmail(in); got != want {
			t.Errorf("oidcLoginFromEmail(%q) = %q, want %q", in, got, want)
		}
	}
}
