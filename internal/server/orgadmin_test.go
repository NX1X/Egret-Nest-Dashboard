package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/NX1X/Egret-Nest-Dashboard/internal/model"
	"github.com/NX1X/Egret-Nest-Dashboard/internal/store"
)

// memberClientWithRole creates a local user, logs them in, and gives them a
// membership role in orgID. Returns the client and the new user's id.
func memberClientWithRole(t *testing.T, ts *httptest.Server, st *store.Store, login string, orgID int64, role model.Role) (*http.Client, int64) {
	t.Helper()
	c := loginAsNewMember(t, ts, st, login, login+"-password1")
	u, err := st.GetUserByLogin(login)
	if err != nil || u == nil {
		t.Fatalf("lookup %s: %v", login, err)
	}
	if err := st.AddMembership(orgID, u.ID, role); err != nil {
		t.Fatalf("add membership: %v", err)
	}
	return c, u.ID
}

func post(t *testing.T, c *http.Client, ts *httptest.Server, path string, form url.Values) *http.Response {
	t.Helper()
	form.Set("_csrf", csrfFrom(t, c.Jar, ts.URL))
	resp, err := c.PostForm(ts.URL+path, form)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

// TestOrgManagerScoping: an org admin manages THEIR org, but a different org is
// invisible (404), and a viewer/member cannot manage at all.
func TestOrgManagerScoping(t *testing.T) {
	ts, st := newTestServer(t, Config{})
	authedClient(t, ts) // instance admin + default org (id 1)
	acme, _ := st.CreateOrg("acme")
	other, _ := st.CreateOrg("other")

	admin, _ := memberClientWithRole(t, ts, st, "orgadmin", acme, model.RoleAdmin)

	// Can reach own org's pages.
	for _, p := range []string{"/org/" + i64(acme) + "/tokens", "/org/" + i64(acme) + "/members"} {
		if code := getStatus(t, admin, ts.URL+p); code != http.StatusOK {
			t.Errorf("own org %s = %d, want 200", p, code)
		}
	}
	// Cannot reach a different org (existence hidden).
	if code := getStatus(t, admin, ts.URL+"/org/"+i64(other)+"/tokens"); code != http.StatusNotFound {
		t.Errorf("foreign org tokens = %d, want 404", code)
	}
	// A viewer cannot manage.
	viewer, _ := memberClientWithRole(t, ts, st, "orgviewer", acme, model.RoleViewer)
	if code := getStatus(t, viewer, ts.URL+"/org/"+i64(acme)+"/members"); code != http.StatusNotFound {
		t.Errorf("viewer manage = %d, want 404", code)
	}
}

// TestOrgAdminCannotEscalateAboveSelf: an admin cannot grant the owner role.
func TestOrgAdminCannotEscalateAboveSelf(t *testing.T) {
	ts, st := newTestServer(t, Config{})
	authedClient(t, ts)
	acme, _ := st.CreateOrg("acme")
	admin, _ := memberClientWithRole(t, ts, st, "orgadmin", acme, model.RoleAdmin)
	// A target account to be granted.
	target := loginAsNewMember(t, ts, st, "victim", "victim-password1")
	_ = target
	tu, _ := st.GetUserByLogin("victim")

	// Admin tries to grant OWNER - must be refused (can't assign above own role).
	resp := post(t, admin, ts, "/org/"+i64(acme)+"/members", url.Values{
		"action": {"add"}, "login": {"victim"}, "role": {"owner"},
	})
	resp.Body.Close()
	if m, _ := st.GetMembership(acme, tu.ID); m != nil {
		t.Fatalf("admin escalated victim to %s - must have zero membership", m.Role)
	}

	// Granting member (<= admin) is allowed.
	resp = post(t, admin, ts, "/org/"+i64(acme)+"/members", url.Values{
		"action": {"add"}, "login": {"victim"}, "role": {"member"},
	})
	resp.Body.Close()
	if m, _ := st.GetMembership(acme, tu.ID); m == nil || m.Role != model.RoleMember {
		t.Fatalf("admin should grant member; got %+v", m)
	}
}

// TestLastOwnerGuard: the last owner of an org cannot be removed or downgraded,
// even by an instance admin.
func TestLastOwnerGuard(t *testing.T) {
	ts, st := newTestServer(t, Config{})
	admin := authedClient(t, ts) // instance admin
	acme, _ := st.CreateOrg("acme")
	owner := loginAsNewMember(t, ts, st, "soleowner", "soleowner-password1")
	_ = owner
	ou, _ := st.GetUserByLogin("soleowner")
	if err := st.AddMembership(acme, ou.ID, model.RoleOwner); err != nil {
		t.Fatal(err)
	}

	// Instance admin tries to revoke the sole owner - refused.
	resp := post(t, admin, ts, "/org/"+i64(acme)+"/members", url.Values{
		"action": {"revoke"}, "user_id": {i64(ou.ID)},
	})
	resp.Body.Close()
	if m, _ := st.GetMembership(acme, ou.ID); m == nil || m.Role != model.RoleOwner {
		t.Fatalf("sole owner was removed/changed: %+v", m)
	}

	// Downgrade the sole owner - also refused.
	resp = post(t, admin, ts, "/org/"+i64(acme)+"/members", url.Values{
		"action": {"setrole"}, "user_id": {i64(ou.ID)}, "role": {"admin"},
	})
	resp.Body.Close()
	if m, _ := st.GetMembership(acme, ou.ID); m == nil || m.Role != model.RoleOwner {
		t.Fatalf("sole owner downgraded: %+v", m)
	}

	// With a SECOND owner present, downgrading the first is allowed.
	second := loginAsNewMember(t, ts, st, "coowner", "coowner-password1")
	_ = second
	su, _ := st.GetUserByLogin("coowner")
	st.AddMembership(acme, su.ID, model.RoleOwner)
	resp = post(t, admin, ts, "/org/"+i64(acme)+"/members", url.Values{
		"action": {"setrole"}, "user_id": {i64(ou.ID)}, "role": {"admin"},
	})
	resp.Body.Close()
	if m, _ := st.GetMembership(acme, ou.ID); m == nil || m.Role != model.RoleAdmin {
		t.Fatalf("owner should downgrade when a co-owner exists: %+v", m)
	}
}

// TestAddCannotOrphanLastOwner is the regression test for the appsec/pentest
// finding: the "add" (upsert) action must honour the last-owner guard too - a
// sole owner cannot demote themselves (or a co-owner down to zero owners) through
// the "Add / update a member" form, only through setrole/revoke.
func TestAddCannotOrphanLastOwner(t *testing.T) {
	ts, st := newTestServer(t, Config{})
	authedClient(t, ts)
	acme, _ := st.CreateOrg("acme")
	owner, ownerID := memberClientWithRole(t, ts, st, "soleowner", acme, model.RoleOwner)

	// Sole owner tries to demote THEMSELVES to member via action=add - must fail.
	resp := post(t, owner, ts, "/org/"+i64(acme)+"/members", url.Values{
		"action": {"add"}, "login": {"soleowner"}, "role": {"member"},
	})
	resp.Body.Close()
	if m, _ := st.GetMembership(acme, ownerID); m == nil || m.Role != model.RoleOwner {
		t.Fatalf("add orphaned the last owner: %+v", m)
	}

	// Add a second owner, then demoting the first via add is allowed.
	co, coID := memberClientWithRole(t, ts, st, "coowner", acme, model.RoleOwner)
	_ = co
	resp = post(t, owner, ts, "/org/"+i64(acme)+"/members", url.Values{
		"action": {"add"}, "login": {"soleowner"}, "role": {"admin"},
	})
	resp.Body.Close()
	if m, _ := st.GetMembership(acme, ownerID); m == nil || m.Role != model.RoleAdmin {
		t.Fatalf("owner should demote when a co-owner exists: %+v", m)
	}
	if m, _ := st.GetMembership(acme, coID); m == nil || m.Role != model.RoleOwner {
		t.Fatalf("co-owner unexpectedly changed: %+v", m)
	}
}

// TestCrossOrgTokenRevokeBlocked: an org admin cannot revoke a token that belongs
// to a different org, even by guessing its id.
func TestCrossOrgTokenRevokeBlocked(t *testing.T) {
	ts, st := newTestServer(t, Config{})
	authedClient(t, ts)
	acme, _ := st.CreateOrg("acme")
	other, _ := st.CreateOrg("other")
	// A token owned by "other".
	otherTok, err := st.CreateIngestToken(&model.IngestToken{OrgID: other, Name: "x", TokenHash: "hash-other"})
	if err != nil {
		t.Fatal(err)
	}
	admin, _ := memberClientWithRole(t, ts, st, "orgadmin", acme, model.RoleAdmin)

	// acme admin tries to revoke other's token by id - must be a no-op.
	resp := post(t, admin, ts, "/org/"+i64(acme)+"/tokens", url.Values{
		"action": {"revoke"}, "id": {i64(otherTok)},
	})
	resp.Body.Close()
	toks, _ := st.ListIngestTokensForOrg(other)
	if len(toks) != 1 || toks[0].Revoked {
		t.Fatalf("cross-org token was revoked: %+v", toks)
	}
}

// TestOrgAdminManagesOwnTokens: create + revoke within the org works.
func TestOrgAdminManagesOwnTokens(t *testing.T) {
	ts, st := newTestServer(t, Config{})
	authedClient(t, ts)
	acme, _ := st.CreateOrg("acme")
	admin, _ := memberClientWithRole(t, ts, st, "orgadmin", acme, model.RoleAdmin)

	resp := post(t, admin, ts, "/org/"+i64(acme)+"/tokens", url.Values{
		"action": {"create_token"}, "repository": {"acme/app"}, "token_name": {"ci"},
	})
	body := readAll(t, resp)
	resp.Body.Close()
	if !strings.Contains(body, "shown once") {
		t.Fatalf("token not shown after create:\n%s", body)
	}
	toks, _ := st.ListIngestTokensForOrg(acme)
	if len(toks) != 1 {
		t.Fatalf("want 1 token in acme, got %d", len(toks))
	}
	// Revoke it.
	resp = post(t, admin, ts, "/org/"+i64(acme)+"/tokens", url.Values{
		"action": {"revoke"}, "id": {i64(toks[0].ID)},
	})
	resp.Body.Close()
	toks, _ = st.ListIngestTokensForOrg(acme)
	if len(toks) != 1 || !toks[0].Revoked {
		t.Fatalf("token not revoked: %+v", toks)
	}
}

func i64(v int64) string { return strconv.FormatInt(v, 10) }

func getStatus(t *testing.T, c *http.Client, url string) int {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	resp.Body.Close()
	return resp.StatusCode
}
