package server

import (
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"github.com/NX1X/Egret-Nest-Dashboard/internal/model"
)

// TestAdminGrantsAndRevokesMembership proves the fail-closed access model's
// escape hatch: an instance admin can explicitly grant a provisioned (but
// access-less) SSO/local user membership in a specific org, and revoke it. This
// is the authorization half of the N7 cross-tenant fix - SSO grants
// authentication only; access to a tenant is always an explicit admin action.
func TestAdminGrantsAndRevokesMembership(t *testing.T) {
	ts, st := newTestServer(t, Config{})
	admin := authedClient(t, ts) // bootstrap admin + default org

	// A user with zero memberships (the fail-closed default for SSO users).
	uid, err := st.CreateUser(&model.User{Login: "provisioned", ExternalID: "github:777"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	orgID, err := st.CreateOrg("acme")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	if m, _ := st.MembershipsForUser(uid); len(m) != 0 {
		t.Fatalf("new user starts with %d memberships, want 0", len(m))
	}

	csrf := csrfFrom(t, admin.Jar, ts.URL)

	// Grant: admin adds the user to the org as a viewer.
	resp, err := admin.PostForm(ts.URL+"/admin/users", url.Values{
		"_csrf":   {csrf},
		"action":  {"grant"},
		"user_id": {strconv.FormatInt(uid, 10)},
		"org_id":  {strconv.FormatInt(orgID, 10)},
		"role":    {"viewer"},
	})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	resp.Body.Close()
	m, _ := st.MembershipsForUser(uid)
	if len(m) != 1 || m[0].OrgID != orgID || m[0].Role != "viewer" {
		t.Fatalf("after grant, memberships = %+v, want one viewer in org %d", m, orgID)
	}

	// Revoke: admin removes it, returning the user to no-access.
	resp, err = admin.PostForm(ts.URL+"/admin/users", url.Values{
		"_csrf":   {csrf},
		"action":  {"revoke"},
		"user_id": {strconv.FormatInt(uid, 10)},
		"org_id":  {strconv.FormatInt(orgID, 10)},
	})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	resp.Body.Close()
	if m, _ := st.MembershipsForUser(uid); len(m) != 0 {
		t.Fatalf("after revoke, memberships = %+v, want 0", m)
	}
}

// TestUsersPageRequiresAdmin confirms the membership console is admin-gated:
// a non-admin member gets 404 (existence hidden), never the grant/revoke UI.
func TestUsersPageRequiresAdmin(t *testing.T) {
	ts, st := newTestServer(t, Config{})
	authedClient(t, ts) // bootstrap admin
	member := loginAsNewMember(t, ts, st, "plainmember", "memberpassword1")

	resp, err := member.Get(ts.URL + "/admin/users")
	if err != nil {
		t.Fatalf("get users: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("non-admin /admin/users = %d, want 404", resp.StatusCode)
	}
}
