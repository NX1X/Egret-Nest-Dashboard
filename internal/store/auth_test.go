package store

import (
	"testing"
	"time"

	"github.com/NX1X/Egret-Nest-Dashboard/internal/model"
)

func TestUsersAndBootstrap(t *testing.T) {
	st := testStore(t)

	if n, _ := st.CountUsers(); n != 0 {
		t.Fatalf("fresh store has %d users, want 0", n)
	}
	id, err := st.CreateUser(&model.User{Login: "Admin", Email: "a@x", PasswordHash: "h", IsAdmin: true})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if n, _ := st.CountUsers(); n != 1 {
		t.Errorf("users = %d, want 1", n)
	}

	// Login lookup is case-insensitive.
	u, err := st.GetUserByLogin("admin")
	if err != nil || u == nil {
		t.Fatalf("GetUserByLogin: %v / %v", u, err)
	}
	if u.ID != id || !u.IsAdmin || u.PasswordHash != "h" {
		t.Errorf("user = %+v", u)
	}
	// Unknown user -> (nil, nil).
	if got, err := st.GetUserByLogin("nobody"); got != nil || err != nil {
		t.Errorf("unknown user = %v, %v; want nil,nil", got, err)
	}

	if err := st.SetUserTOTP(id, "SECRET", true); err != nil {
		t.Fatalf("SetUserTOTP: %v", err)
	}
	u, _ = st.GetUserByID(id)
	if !u.TOTPEnabled || u.TOTPSecret != "SECRET" {
		t.Errorf("totp not set: %+v", u)
	}
}

func TestExternalIDLink(t *testing.T) {
	st := testStore(t)

	// A local user has no external id.
	local, _ := st.CreateUser(&model.User{Login: "local"})
	_ = local
	if got, _ := st.GetUserByExternalID(""); got != nil {
		t.Error("empty external id must not match any user")
	}

	// A linked user is found by external id.
	id, err := st.CreateUser(&model.User{Login: "alice", ExternalID: "github:12345"})
	if err != nil {
		t.Fatalf("CreateUser linked: %v", err)
	}
	u, err := st.GetUserByExternalID("github:12345")
	if err != nil || u == nil || u.ID != id || u.ExternalID != "github:12345" {
		t.Fatalf("GetUserByExternalID = %+v, %v", u, err)
	}
	// Multiple local (NULL external_id) users coexist (partial unique index).
	if _, err := st.CreateUser(&model.User{Login: "local2"}); err != nil {
		t.Errorf("second local user should be allowed: %v", err)
	}
}

func TestOrgsMemberships(t *testing.T) {
	st := testStore(t)
	uid, _ := st.CreateUser(&model.User{Login: "u"})
	orgID, err := st.CreateOrg("acme")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	if err := st.AddMembership(orgID, uid, model.RoleAdmin); err != nil {
		t.Fatalf("AddMembership: %v", err)
	}
	m, err := st.GetMembership(orgID, uid)
	if err != nil || m == nil || m.Role != model.RoleAdmin {
		t.Fatalf("membership = %+v, %v", m, err)
	}
	// Upsert changes the role.
	st.AddMembership(orgID, uid, model.RoleOwner)
	m, _ = st.GetMembership(orgID, uid)
	if m.Role != model.RoleOwner {
		t.Errorf("role after upsert = %q, want owner", m.Role)
	}
	// Non-member -> nil.
	if got, _ := st.GetMembership(orgID, 999); got != nil {
		t.Errorf("non-member = %+v, want nil", got)
	}
}

func TestSessions(t *testing.T) {
	st := testStore(t)
	uid, _ := st.CreateUser(&model.User{Login: "u"})

	if err := st.CreateSession(uid, "hash1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	sess, err := st.GetSessionByToken("hash1")
	if err != nil || sess == nil || sess.UserID != uid {
		t.Fatalf("GetSessionByToken = %+v, %v", sess, err)
	}

	// Expired session is treated as absent (and pruned).
	st.CreateSession(uid, "expired", time.Now().Add(-time.Minute))
	if got, _ := st.GetSessionByToken("expired"); got != nil {
		t.Errorf("expired session returned: %+v", got)
	}

	if err := st.DeleteSession("hash1"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if got, _ := st.GetSessionByToken("hash1"); got != nil {
		t.Error("session not deleted")
	}
}

func TestIngestTokens(t *testing.T) {
	st := testStore(t)
	orgID, _ := st.CreateOrg("acme")

	id, err := st.CreateIngestToken(&model.IngestToken{OrgID: orgID, Repository: "a/b", Name: "ci", TokenHash: "th"})
	if err != nil {
		t.Fatalf("CreateIngestToken: %v", err)
	}
	tok, err := st.GetIngestTokenByHash("th")
	if err != nil || tok == nil || tok.Repository != "a/b" {
		t.Fatalf("GetIngestTokenByHash = %+v, %v", tok, err)
	}
	// Revoked token is not returned.
	if err := st.RevokeIngestToken(id); err != nil {
		t.Fatalf("RevokeIngestToken: %v", err)
	}
	if got, _ := st.GetIngestTokenByHash("th"); got != nil {
		t.Errorf("revoked token returned: %+v", got)
	}
}

func TestAudit(t *testing.T) {
	st := testStore(t)
	if err := st.Audit(model.AuditEvent{ActorLogin: "admin", Action: "login", IP: "127.0.0.1"}); err != nil {
		t.Errorf("Audit: %v", err)
	}
}

func TestClaimTOTPCode(t *testing.T) {
	st := testStore(t)
	uid, _ := st.CreateUser(&model.User{Login: "u"})

	// First use of a counter is claimed; replay of the same counter is rejected.
	ok, err := st.ClaimTOTPCode(uid, 12345)
	if err != nil || !ok {
		t.Fatalf("first claim: ok=%v err=%v", ok, err)
	}
	ok, err = st.ClaimTOTPCode(uid, 12345)
	if err != nil || ok {
		t.Errorf("replay claim should return false: ok=%v err=%v", ok, err)
	}
	// A different counter is still claimable.
	if ok, _ := st.ClaimTOTPCode(uid, 12346); !ok {
		t.Error("new counter should be claimable")
	}
}
