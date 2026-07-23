package server

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync"
	"testing"
)

// TestSetupRequiresToken: an attacker who reaches /setup without the one-time
// token cannot bootstrap the admin, and no user is created.
func TestSetupRequiresToken(t *testing.T) {
	ts, st := newTestServer(t, Config{})
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	c.Get(ts.URL + "/setup") // csrf cookie

	// Wrong token -> refused, no user created.
	bad := url.Values{
		"_csrf": {csrfFrom(t, jar, ts.URL)}, "setup_token": {"wrong-token"},
		"login": {"attacker"}, "password": {"supersecretpassword"},
	}
	resp, _ := c.PostForm(ts.URL+"/setup", bad)
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Error("setup succeeded with a wrong token")
	}
	if n, _ := st.CountUsers(); n != 0 {
		t.Fatalf("a user was created despite a bad setup token (%d users)", n)
	}

	// Correct token -> bootstrap succeeds.
	good := url.Values{
		"_csrf": {csrfFrom(t, jar, ts.URL)}, "setup_token": {testSetupToken},
		"login": {"admin"}, "password": {"supersecretpassword"},
	}
	resp, _ = c.PostForm(ts.URL+"/setup", good)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("setup with correct token = %d, want 200", resp.StatusCode)
	}
	if n, _ := st.CountUsers(); n != 1 {
		t.Errorf("want 1 user after bootstrap, got %d", n)
	}
}

// TestSetupConcurrentSingleAdmin fires many /setup POSTs with the correct token
// at once: exactly one must create the admin, the rest fail closed, and the DB
// ends with exactly one user. It also exercises the concurrent read + burn of the
// server's setup token under the race detector (go test -race).
func TestSetupConcurrentSingleAdmin(t *testing.T) {
	ts, st := newTestServer(t, Config{})

	const n = 12
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	wg.Add(n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			jar, _ := cookiejar.New(nil)
			c := &http.Client{Jar: jar}
			c.Get(ts.URL + "/setup") // per-client CSRF cookie
			form := url.Values{
				"_csrf": {csrfFrom(t, jar, ts.URL)}, "setup_token": {testSetupToken},
				"login": {"admin"}, "password": {"supersecretpassword"},
			}
			<-start // release all goroutines together to maximize contention
			resp, err := c.PostForm(ts.URL+"/setup", form)
			if err != nil {
				return
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	if successes != 1 {
		t.Errorf("want exactly 1 successful /setup, got %d", successes)
	}
	if cnt, _ := st.CountUsers(); cnt != 1 {
		t.Errorf("want exactly 1 user after concurrent setup, got %d", cnt)
	}
}

// TestBootstrapAdminIsAtomicAndOnce: the store-level claim only succeeds once.
func TestBootstrapAdminOnce(t *testing.T) {
	st := mustStore(t)
	id1, ok1, err := st.BootstrapAdmin("admin", "hash1")
	if err != nil || !ok1 || id1 == 0 {
		t.Fatalf("first bootstrap: id=%d ok=%v err=%v", id1, ok1, err)
	}
	id2, ok2, err := st.BootstrapAdmin("attacker", "hash2")
	if err != nil {
		t.Fatalf("second bootstrap err: %v", err)
	}
	if ok2 || id2 != 0 {
		t.Errorf("second bootstrap should fail closed, got id=%d ok=%v", id2, ok2)
	}
	if n, _ := st.CountUsers(); n != 1 {
		t.Errorf("want exactly 1 admin after two bootstrap attempts, got %d", n)
	}
}
