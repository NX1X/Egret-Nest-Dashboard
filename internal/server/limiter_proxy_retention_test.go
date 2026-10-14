package server

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NX1X/Egret-Nest-Dashboard/internal/store"
)

// Regression: the limiter checked the ceiling before the slow password hash and
// counted the failure after it, so parallel requests all passed the check. reserve
// must hand out exactly max attempts, however many requests race for them.
func TestLimiterReserveIsAtomicUnderConcurrency(t *testing.T) {
	l := newFailLimiter(5, time.Minute)
	now := time.Now()
	var granted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.reserve("ip|alice", now) {
				granted.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := granted.Load(); got != 5 {
		t.Fatalf("reserve granted %d attempts, want exactly 5", got)
	}
	l.release("ip|alice")
	if !l.reserve("ip|alice", now) {
		t.Error("release did not give an attempt back")
	}
}

// The same property end to end: 20 parallel wrong-password logins for one login
// from one IP. At most 5 may reach the password check; the rest must get 429.
func TestParallelLoginsCannotExceedTheLimiter(t *testing.T) {
	ts, st := newTestServer(t, Config{})
	loginAsNewMember(t, ts, st, "alice", "a-long-enough-password")
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	if _, err := c.Get(ts.URL + "/login"); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"_csrf": {csrfFrom(t, jar, ts.URL)}, "login": {"alice"}, "password": {"wrong-password-123"}}
	var limited, checked atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := c.PostForm(ts.URL+"/login", form)
			if err != nil {
				t.Error(err)
				return
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusTooManyRequests {
				limited.Add(1)
			} else {
				checked.Add(1)
			}
		}()
	}
	wg.Wait()
	// alice's successful login above reset her key, so the full 5 are available.
	if checked.Load() > 5 {
		t.Errorf("%d attempts reached the password check, want at most 5 (429s: %d)", checked.Load(), limited.Load())
	}
}

func TestClientIPHonorsTheProxyOnlyWhenTrusted(t *testing.T) {
	req := func(remote string, hdr map[string]string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		return r
	}
	direct := &Server{cfg: Config{BehindProxy: false}}
	proxied := &Server{cfg: Config{BehindProxy: true}}
	for _, tc := range []struct {
		name string
		s    *Server
		r    *http.Request
		want string
	}{
		{"direct: forged X-Real-IP is ignored", direct, req("203.0.113.9:4000", map[string]string{"X-Real-IP": "198.51.100.1"}), "203.0.113.9"},
		{"proxy: X-Real-IP set by nginx", proxied, req("10.0.0.2:4000", map[string]string{"X-Real-IP": "198.51.100.1"}), "198.51.100.1"},
		{"proxy: right-most X-Forwarded-For, not the client's", proxied, req("10.0.0.2:4000", map[string]string{"X-Forwarded-For": "1.2.3.4, 198.51.100.7"}), "198.51.100.7"},
		{"proxy: garbage headers fall back to RemoteAddr", proxied, req("10.0.0.2:4000", map[string]string{"X-Real-IP": "not-an-ip"}), "10.0.0.2"},
		{"proxy: IPv6", proxied, req("[::1]:4000", map[string]string{"X-Real-IP": "2001:db8::1"}), "2001:db8::1"},
	} {
		if got := tc.s.clientIP(tc.r); got != tc.want {
			t.Errorf("%s: clientIP = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func newServerForTest(t *testing.T, cfg Config) *Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if cfg.SetupToken == "" {
		cfg.SetupToken = testSetupToken
	}
	srv, err := New(st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

// Regression: any non-negative integer was accepted. A huge value made AddDate
// overflow and wrap the cutoff to about "now", so the janitor deleted every run
// and the whole audit log.
func TestRetentionIsBoundedOnSaveAndOnRead(t *testing.T) {
	huge := strconv.Itoa(1 << 62)
	s := newServerForTest(t, Config{RetentionDays: 30})

	s.saveIntSetting(settingRetentionDays, huge)
	if v, _ := s.store.GetSetting(settingRetentionDays); v != "" {
		t.Errorf("an out-of-range retention was stored: %q", v)
	}
	s.saveIntSetting(settingRetentionDays, strconv.Itoa(maxRetentionDays))
	if got := s.retentionDays(); got != maxRetentionDays {
		t.Errorf("retentionDays = %d, want the maximum %d", got, maxRetentionDays)
	}

	// A huge value stored BEFORE the bound existed must not be used either.
	if err := s.store.SetSetting(settingRetentionDays, huge); err != nil {
		t.Fatal(err)
	}
	if got := s.retentionDays(); got != 30 {
		t.Errorf("retentionDays with a stored huge value = %d, want the env fallback 30", got)
	}
	if err := s.store.SetSetting(settingAuditRetention, huge); err != nil {
		t.Fatal(err)
	}
	if got := s.auditRetentionDays(); got != 30 {
		t.Errorf("auditRetentionDays with a stored huge value = %d, want 30", got)
	}

	// And through the environment.
	envHuge := newServerForTest(t, Config{RetentionDays: 1 << 62, AuditRetentionDays: 1 << 62})
	if got := envHuge.retentionDays(); got != 0 {
		t.Errorf("retentionDays with a huge env value = %d, want 0 (keep)", got)
	}
	if got := envHuge.auditRetentionDays(); got != 0 {
		t.Errorf("auditRetentionDays with a huge env value = %d, want 0 (keep)", got)
	}
}
