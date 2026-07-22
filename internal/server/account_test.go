package server

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/NX1X/Egret-Nest-Dashboard/internal/auth"
	"github.com/NX1X/Egret-Nest-Dashboard/internal/store"
)

// TestTOTPEnrollmentLifecycle drives begin → confirm → disable for a local user
// and asserts the store state + the disable-requires-a-code guard.
func TestTOTPEnrollmentLifecycle(t *testing.T) {
	ts, st := newTestServer(t, Config{})
	authedClient(t, ts) // bootstrap admin (unused here)
	c := loginAsNewMember(t, ts, st, "totpuser", "totpuser-password1")
	uid := mustUserID(t, st, "totpuser")

	// begin: a pending secret is stored, not yet enabled.
	post(t, c, ts, "/account", url.Values{"action": {"begin"}}).Body.Close()
	u, _ := st.GetUserByID(uid)
	if u.TOTPSecret == "" || u.TOTPEnabled {
		t.Fatalf("after begin: want pending secret, enabled=false; got secret=%q enabled=%v", u.TOTPSecret, u.TOTPEnabled)
	}

	// confirm with a WRONG code: stays pending.
	post(t, c, ts, "/account", url.Values{"action": {"confirm"}, "code": {"000000"}}).Body.Close()
	if u, _ := st.GetUserByID(uid); u.TOTPEnabled {
		t.Fatal("bad code should not enable TOTP")
	}

	// confirm with the RIGHT code: enabled.
	code, _ := auth.TOTPCodeAt(u.TOTPSecret, time.Now())
	post(t, c, ts, "/account", url.Values{"action": {"confirm"}, "code": {code}}).Body.Close()
	u, _ = st.GetUserByID(uid)
	if !u.TOTPEnabled {
		t.Fatal("correct code should enable TOTP")
	}

	// disable WITHOUT a code: refused (2FA stays on).
	post(t, c, ts, "/account", url.Values{"action": {"disable"}, "code": {"000000"}}).Body.Close()
	if u, _ := st.GetUserByID(uid); !u.TOTPEnabled {
		t.Fatal("disable without a valid code must be refused")
	}

	// disable WITH a valid code: off, secret cleared.
	code, _ = auth.TOTPCodeAt(u.TOTPSecret, time.Now())
	post(t, c, ts, "/account", url.Values{"action": {"disable"}, "code": {code}}).Body.Close()
	u, _ = st.GetUserByID(uid)
	if u.TOTPEnabled || u.TOTPSecret != "" {
		t.Fatalf("after disable: want off + cleared; got secret=%q enabled=%v", u.TOTPSecret, u.TOTPEnabled)
	}
}

// TestBeginCannotStripEnabledTOTP is the regression test for the appsec CRITICAL:
// once TOTP is enabled, action=begin must NOT overwrite the secret or disable the
// factor without a code - a session-only attacker must not be able to strip 2FA.
func TestBeginCannotStripEnabledTOTP(t *testing.T) {
	ts, st := newTestServer(t, Config{})
	authedClient(t, ts)
	c := loginAsNewMember(t, ts, st, "totpuser2", "totpuser2-password1")
	uid := mustUserID(t, st, "totpuser2")

	// Enrol fully.
	post(t, c, ts, "/account", url.Values{"action": {"begin"}}).Body.Close()
	u, _ := st.GetUserByID(uid)
	secret := u.TOTPSecret
	code, _ := auth.TOTPCodeAt(secret, time.Now())
	post(t, c, ts, "/account", url.Values{"action": {"confirm"}, "code": {code}}).Body.Close()
	if u, _ := st.GetUserByID(uid); !u.TOTPEnabled {
		t.Fatal("setup: TOTP should be enabled")
	}

	// Attacker with the session POSTs begin (no code): must be refused, factor intact.
	post(t, c, ts, "/account", url.Values{"action": {"begin"}}).Body.Close()
	u, _ = st.GetUserByID(uid)
	if !u.TOTPEnabled {
		t.Fatal("begin stripped an enabled TOTP factor (2FA bypass)")
	}
	if u.TOTPSecret != secret {
		t.Fatal("begin overwrote the confirmed secret while enabled")
	}
}

// TestDisableIsRateLimited: repeated bad disable codes get throttled (per-user),
// so a stolen session can't brute-force the 6-digit code.
func TestDisableIsRateLimited(t *testing.T) {
	ts, st := newTestServer(t, Config{})
	authedClient(t, ts)
	c := loginAsNewMember(t, ts, st, "totpuser3", "totpuser3-password1")
	uid := mustUserID(t, st, "totpuser3")
	post(t, c, ts, "/account", url.Values{"action": {"begin"}}).Body.Close()
	u, _ := st.GetUserByID(uid)
	code, _ := auth.TOTPCodeAt(u.TOTPSecret, time.Now())
	post(t, c, ts, "/account", url.Values{"action": {"confirm"}, "code": {code}}).Body.Close()

	// Hammer with bad codes to trip the per-user limiter (5 failures / window).
	for i := 0; i < 6; i++ {
		post(t, c, ts, "/account", url.Values{"action": {"disable"}, "code": {"000000"}}).Body.Close()
	}
	// Now even the CORRECT code is blocked (limiter checked before verification),
	// so 2FA cannot be disabled - proving the throttle actually gates the action.
	good, _ := auth.TOTPCodeAt(u.TOTPSecret, time.Now())
	post(t, c, ts, "/account", url.Values{"action": {"disable"}, "code": {good}}).Body.Close()
	if u, _ := st.GetUserByID(uid); !u.TOTPEnabled {
		t.Fatal("throttle failed: TOTP was disabled while rate-limited")
	}
}

// TestAccountPostRejectsBadCSRF: state-changing POST without a valid token is 403.
func TestAccountPostRejectsBadCSRF(t *testing.T) {
	ts, st := newTestServer(t, Config{})
	authedClient(t, ts)
	c := loginAsNewMember(t, ts, st, "csrfuser", "csrfuser-password1")
	resp, err := c.PostForm(ts.URL+"/account", url.Values{"action": {"begin"}, "_csrf": {"wrong"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("bad CSRF POST /account = %d, want 403", resp.StatusCode)
	}
}

// TestAccountRequiresAuth: anonymous users are redirected to /login.
func TestAccountRequiresAuth(t *testing.T) {
	ts, _ := newTestServer(t, Config{})
	noRedir := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, _ := noRedir.Get(ts.URL + "/account")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Errorf("anon /account = %d -> %q, want 303 -> /login", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp.Body.Close()
}

func mustUserID(t *testing.T, st *store.Store, login string) int64 {
	t.Helper()
	u, err := st.GetUserByLogin(login)
	if err != nil || u == nil {
		t.Fatalf("lookup %s: %v", login, err)
	}
	return u.ID
}
