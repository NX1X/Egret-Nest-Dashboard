package server

import (
	"strings"
	"testing"
)

// TestNavConsistentAcrossPages is the regression test for the "tabs disappear"
// bug: every authenticated page must render the SAME top navigation (via the
// shared topnav partial), so an admin never loses the admin links by visiting
// /orgs or /account, and a non-admin never sees them anywhere.
func TestNavConsistentAcrossPages(t *testing.T) {
	ts, st := newTestServer(t, Config{})
	admin := authedClient(t, ts) // instance admin

	adminPages := []string{"/", "/repos", "/orgs", "/account", "/admin/settings", "/admin/users", "/audit", "/admin/logs"}
	// Links that must appear on EVERY page for an instance admin.
	wantAll := []string{`href="/"`, `href="/repos"`, `href="/orgs"`, `href="/account"`,
		`href="/admin/settings"`, `href="/admin/users"`, `href="/audit"`, `href="/admin/logs"`}
	for _, p := range adminPages {
		body := getBody(t, admin, ts.URL+p)
		for _, link := range wantAll {
			if !strings.Contains(body, link) {
				t.Errorf("admin page %s missing nav link %s", p, link)
			}
		}
	}

	// A non-admin member sees the core tabs but NEVER the admin ones.
	member := loginAsNewMember(t, ts, st, "navmember", "navmember-pass1")
	for _, p := range []string{"/", "/repos", "/orgs", "/account"} {
		body := getBody(t, member, ts.URL+p)
		for _, core := range []string{`href="/"`, `href="/repos"`, `href="/orgs"`, `href="/account"`} {
			if !strings.Contains(body, core) {
				t.Errorf("member page %s missing core link %s", p, core)
			}
		}
		for _, adminLink := range []string{`href="/admin/settings"`, `href="/admin/users"`, `href="/audit"`, `href="/admin/logs"`} {
			if strings.Contains(body, adminLink) {
				t.Errorf("member page %s leaks admin link %s", p, adminLink)
			}
		}
	}
}
