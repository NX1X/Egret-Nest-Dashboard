package store

import (
	"database/sql"
	"errors"

	"github.com/NX1X/Egret-Nest-Dashboard/internal/model"
)

// This file backs org-scoped self-service management (an org owner/admin managing
// their OWN org's ingest tokens and members without being an instance admin).
// Every read here is already narrowed to a single orgID by the caller's authz
// check in the server layer; these methods do not themselves enforce authority.

// GetOrgByID returns the org, or (nil, nil) if it does not exist.
func (s *Store) GetOrgByID(id int64) (*model.Organization, error) {
	var o model.Organization
	var created string
	err := s.db.QueryRow(`SELECT id, name, created_at FROM organizations WHERE id = ?`, id).
		Scan(&o.ID, &o.Name, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	o.CreatedAt = parseTime(created)
	return &o, nil
}

// OrgRoleView is one org a user belongs to, with the user's role in it.
type OrgRoleView struct {
	OrgID   int64
	OrgName string
	Role    model.Role
}

// OrgsForUser returns the orgs a user is a member of, with their role, newest
// first. Used to render the org picker and decide which orgs a non-instance-admin
// may manage.
func (s *Store) OrgsForUser(userID int64) ([]OrgRoleView, error) {
	rows, err := s.db.Query(`
SELECT o.id, o.name, m.role
FROM memberships m JOIN organizations o ON o.id = m.org_id
WHERE m.user_id = ? ORDER BY o.id DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OrgRoleView
	for rows.Next() {
		var v OrgRoleView
		var role string
		if err := rows.Scan(&v.OrgID, &v.OrgName, &role); err != nil {
			return nil, err
		}
		v.Role = model.Role(role)
		out = append(out, v)
	}
	return out, rows.Err()
}

// OrgMemberView is one member of an org, for the org-members management page.
type OrgMemberView struct {
	UserID int64
	Login  string
	Email  string
	Role   model.Role
}

// ListOrgMembers returns the members of a single org with their role and login.
// Scoped to one orgID so an org admin never sees users outside their own org.
func (s *Store) ListOrgMembers(orgID int64) ([]OrgMemberView, error) {
	rows, err := s.db.Query(`
SELECT u.id, u.login, u.email, m.role
FROM memberships m JOIN users u ON u.id = m.user_id
WHERE m.org_id = ? ORDER BY u.login`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OrgMemberView
	for rows.Next() {
		var v OrgMemberView
		var role string
		if err := rows.Scan(&v.UserID, &v.Login, &v.Email, &role); err != nil {
			return nil, err
		}
		v.Role = model.Role(role)
		out = append(out, v)
	}
	return out, rows.Err()
}

// CountOrgOwners returns how many members hold the owner role in an org. Used to
// refuse an action that would remove the last owner (which would orphan the org).
func (s *Store) CountOrgOwners(orgID int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM memberships WHERE org_id = ? AND role = ?`,
		orgID, string(model.RoleOwner)).Scan(&n)
	return n, err
}

// ListIngestTokensForOrg returns the ingest tokens scoped to a single org. The
// token_hash column is deliberately never selected.
func (s *Store) ListIngestTokensForOrg(orgID int64) ([]TokenListItem, error) {
	rows, err := s.db.Query(`
SELECT t.id, t.org_id, o.name, t.repository, t.name, t.created_at, t.last_used, t.revoked
FROM ingest_tokens t JOIN organizations o ON o.id = t.org_id
WHERE t.org_id = ? ORDER BY t.id DESC LIMIT 500`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TokenListItem
	for rows.Next() {
		var it TokenListItem
		var created, lastUsed string
		var revoked int
		if err := rows.Scan(&it.ID, &it.OrgID, &it.OrgName, &it.Repository, &it.Name,
			&created, &lastUsed, &revoked); err != nil {
			return nil, err
		}
		it.CreatedAt = parseTime(created)
		it.LastUsed = parseTime(lastUsed)
		it.Revoked = revoked != 0
		out = append(out, it)
	}
	return out, rows.Err()
}

// RevokeIngestTokenInOrg revokes a token ONLY if it belongs to orgID, in a single
// atomic statement (no check-then-act race, no cross-org revocation). Reports
// whether a row was actually revoked.
func (s *Store) RevokeIngestTokenInOrg(id, orgID int64) (bool, error) {
	res, err := s.db.Exec(`UPDATE ingest_tokens SET revoked=1 WHERE id=? AND org_id=?`, id, orgID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ErrLastOwner is returned when a membership change would leave an org with no
// owner. It is the single source of truth for the "an org always has >= 1 owner"
// invariant, enforced atomically below so no code path (add/setrole/revoke) and
// no concurrent request can bypass or race it.
var ErrLastOwner = errors.New("store: change would remove the org's last owner")

// SetMembershipRole upserts (org, user) -> role. If the target is currently the
// org's only owner and the new role is not owner, it refuses with ErrLastOwner.
// The read of the current role, the owner count, and the write all run in one
// transaction, so two concurrent managers cannot both pass the check and race the
// org to zero owners. Safe for brand-new members (no owner concern on insert).
func (s *Store) SetMembershipRole(orgID, userID int64, newRole model.Role) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	var cur string
	err = tx.QueryRow(`SELECT role FROM memberships WHERE org_id=? AND user_id=?`, orgID, userID).Scan(&cur)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// new membership — no last-owner concern
	case err != nil:
		return err
	case model.Role(cur) == model.RoleOwner && newRole != model.RoleOwner:
		var owners int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM memberships WHERE org_id=? AND role=?`,
			orgID, string(model.RoleOwner)).Scan(&owners); err != nil {
			return err
		}
		if owners <= 1 {
			return ErrLastOwner
		}
	}
	if _, err := tx.Exec(`
INSERT INTO memberships (org_id, user_id, role) VALUES (?,?,?)
ON CONFLICT(org_id, user_id) DO UPDATE SET role=excluded.role`,
		orgID, userID, string(newRole)); err != nil {
		return err
	}
	return tx.Commit()
}

// RemoveMembershipGuarded deletes a membership, refusing with ErrLastOwner if it
// is the org's last owner. Atomic (check + delete in one transaction). Removing a
// non-existent membership is a no-op.
func (s *Store) RemoveMembershipGuarded(orgID, userID int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	var cur string
	err = tx.QueryRow(`SELECT role FROM memberships WHERE org_id=? AND user_id=?`, orgID, userID).Scan(&cur)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if model.Role(cur) == model.RoleOwner {
		var owners int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM memberships WHERE org_id=? AND role=?`,
			orgID, string(model.RoleOwner)).Scan(&owners); err != nil {
			return err
		}
		if owners <= 1 {
			return ErrLastOwner
		}
	}
	if _, err := tx.Exec(`DELETE FROM memberships WHERE org_id=? AND user_id=?`, orgID, userID); err != nil {
		return err
	}
	return tx.Commit()
}
