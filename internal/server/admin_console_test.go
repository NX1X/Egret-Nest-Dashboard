package server

import (
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var secretRe = regexp.MustCompile(`secretbox">([^<]+)<`)

// adminPost submits an authenticated, CSRF-carrying form as the given client.
func adminPost(t *testing.T, c *http.Client, base, path string, form url.Values) *http.Response {
	t.Helper()
	form.Set("_csrf", csrfFrom(t, c.Jar, base))
	resp, err := c.PostForm(base+path, form)
	if err != nil {
		t.Fatalf("post %s: %v", path, err)
	}
	return resp
}

func TestAdminPagesRequireAdmin(t *testing.T) {
	ts, st := newTestServer(t, Config{})
	authedClient(t, ts) // bootstrap admin
	member := loginAsNewMember(t, ts, st, "member", "memberpassword1")
	for _, p := range []string{"/admin/settings", "/admin/tokens", "/admin/logs"} {
		resp, _ := member.Get(ts.URL + p)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("non-admin GET %s = %d, want 404", p, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

func TestSettingsInstanceNameFromGUI(t *testing.T) {
	ts, _ := newTestServer(t, Config{})
	admin := authedClient(t, ts)

	resp := adminPost(t, admin, ts.URL, "/admin/settings", url.Values{
		"action": {"save"}, "instance_name": {"Acme Security"}, "retention_days": {"30"},
	})
	resp.Body.Close()

	// The new name shows on the dashboard.
	if body := getBody(t, admin, ts.URL+"/"); !strings.Contains(body, "Acme Security") {
		t.Errorf("index did not pick up GUI instance name:\n%s", body)
	}
}

func TestSettingsMetricsTokenLifecycle(t *testing.T) {
	ts, _ := newTestServer(t, Config{}) // no env metrics token
	admin := authedClient(t, ts)

	// Disabled initially -> /metrics 404.
	resp, _ := http.Get(ts.URL + "/metrics")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("metrics before config = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()

	// Generate a token via the GUI; it's shown once in the response.
	resp = adminPost(t, admin, ts.URL, "/admin/settings", url.Values{"action": {"metrics_generate"}})
	body := readAll(t, resp)
	resp.Body.Close()
	m := secretRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no metrics token shown in response:\n%s", body)
	}
	token := m[1]

	// The generated token authorizes /metrics.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("metrics with GUI token = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// A wrong token is rejected.
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer not-the-token")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("metrics with wrong token = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// Disable -> back to 404.
	adminPost(t, admin, ts.URL, "/admin/settings", url.Values{"action": {"metrics_clear"}}).Body.Close()
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("metrics after clear = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestConnectRepoTokenFlow(t *testing.T) {
	ts, st := newTestServer(t, Config{})
	admin := authedClient(t, ts)

	// Create an org via the GUI.
	adminPost(t, admin, ts.URL, "/admin/tokens", url.Values{
		"action": {"create_org"}, "org_name": {"acme"},
	}).Body.Close()
	org, _ := st.GetOrgByName("acme")
	if org == nil {
		t.Fatal("org not created")
	}

	// Generate an ingest token for it (any repo).
	resp := adminPost(t, admin, ts.URL, "/admin/tokens", url.Values{
		"action": {"create_token"}, "org_id": {strconv.FormatInt(org.ID, 10)}, "token_name": {"ci"},
	})
	body := readAll(t, resp)
	resp.Body.Close()
	m := secretRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no ingest token shown:\n%s", body)
	}
	token := m[1]
	if !strings.Contains(body, "EGRET_INGEST_URL") {
		t.Error("CI snippet missing from response")
	}

	// The token authorizes POST /ingest.
	if code := postWithToken(t, ts.URL+"/ingest", token, sampleBody()); code != http.StatusAccepted {
		t.Errorf("ingest with GUI token = %d, want 202", code)
	}

	// Revoke it -> ingest now 401.
	tokens, _ := st.ListIngestTokens()
	if len(tokens) != 1 {
		t.Fatalf("want 1 token listed, got %d", len(tokens))
	}
	adminPost(t, admin, ts.URL, "/admin/tokens", url.Values{
		"action": {"revoke"}, "id": {strconv.FormatInt(tokens[0].ID, 10)},
	}).Body.Close()
	if code := postWithToken(t, ts.URL+"/ingest", token, sampleBody()); code != http.StatusUnauthorized {
		t.Errorf("ingest after revoke = %d, want 401", code)
	}
}

func TestAccessLogCaptured(t *testing.T) {
	ts, _ := newTestServer(t, Config{})
	admin := authedClient(t, ts)

	// Make a distinctive request.
	admin.Get(ts.URL + "/repos")

	if body := getBody(t, admin, ts.URL+"/admin/logs"); !strings.Contains(body, "/repos") {
		t.Errorf("access log did not capture /repos visit:\n%s", body)
	}
}

// ringLog unit test: newest-first, capacity-bounded.
func TestRingLogRecent(t *testing.T) {
	rl := newRingLog(3)
	for i := 0; i < 5; i++ {
		rl.add(AccessEntry{Path: "/p" + strconv.Itoa(i)})
	}
	got := rl.recent(10)
	if len(got) != 3 {
		t.Fatalf("recent len = %d, want 3 (capacity)", len(got))
	}
	if got[0].Path != "/p4" || got[2].Path != "/p2" {
		t.Errorf("newest-first wrong: %s .. %s", got[0].Path, got[2].Path)
	}
}
