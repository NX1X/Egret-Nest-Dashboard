package server

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/NX1X/Egret-Nest-Dashboard/internal/auth"
	"github.com/NX1X/Egret-Nest-Dashboard/internal/model"
	"github.com/NX1X/Egret-Nest-Dashboard/internal/store"
)

// Org-scoped self-service management: an org owner/admin manages THEIR OWN org's
// ingest tokens and members without being an instance admin. Instance admins
// (is_admin) retain full access to every org here as well.
//
// The privilege model is deliberately conservative:
//   - A manager needs role >= admin in the org (or the instance is_admin flag).
//   - A manager can never grant a role above their own effective role, and can
//     never act on a member whose current role outranks their own (so an admin
//     cannot touch an owner). Instance admins act with effective role = owner.
//   - The last owner of an org can never be removed or downgraded.

// orgAuthority resolves the caller's authority over orgID. It loads the org (so a
// missing org is reported), and returns the caller's *effective* role, whether
// they are an instance admin, and whether they may manage this org at all.
func (s *Server) orgAuthority(r *http.Request, orgID int64) (org *model.Organization, eff model.Role, instanceAdmin bool, canManage bool) {
	o, err := s.store.GetOrgByID(orgID)
	if err != nil || o == nil {
		return nil, "", false, false
	}
	u := currentUser(r)
	if u == nil {
		return o, "", false, false
	}
	if u.IsAdmin {
		return o, model.RoleOwner, true, true // instance admin acts as owner everywhere
	}
	m, err := s.store.GetMembership(orgID, u.ID)
	if err != nil || m == nil {
		return o, "", false, false
	}
	return o, m.Role, false, m.Role.AtLeast(model.RoleAdmin)
}

// orgIDFromPath parses the {id} path segment; 0 on any error.
func orgIDFromPath(r *http.Request) int64 {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id
}

// requireOrgManager guards org-scoped management routes. Anonymous users go to
// /login; anyone who cannot manage the org (non-member, viewer, member, or a
// non-existent org) gets a 404 — existence is never confirmed, matching
// requireAdmin. On success the handler can trust orgAuthority again cheaply.
func (s *Server) requireOrgManager(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if currentUser(r) == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		_, _, _, canManage := s.orgAuthority(r, orgIDFromPath(r))
		if !canManage {
			http.NotFound(w, r)
			return
		}
		next(w, r)
	}
}

// canAssign reports whether a manager with effective role eff may assign newRole.
func canAssign(eff, newRole model.Role) bool {
	return newRole.Valid() && eff.AtLeast(newRole)
}

// canActOn reports whether a manager with effective role eff may modify a member
// who currently holds targetRole (can't touch someone who outranks you).
func canActOn(eff, targetRole model.Role) bool {
	return eff.AtLeast(targetRole)
}

// --- org picker ---

// handleOrgList shows the orgs the caller may manage. Instance admins see all
// orgs; everyone else sees only orgs where they are admin/owner.
func (s *Server) handleOrgList(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	var manageable []store0OrgRow
	if u.IsAdmin {
		orgs, err := s.store.ListOrgs()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		for _, o := range orgs {
			manageable = append(manageable, store0OrgRow{ID: o.ID, Name: o.Name, Role: "instance-admin"})
		}
	} else {
		mine, err := s.store.OrgsForUser(u.ID)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		for _, m := range mine {
			if m.Role.AtLeast(model.RoleAdmin) {
				manageable = append(manageable, store0OrgRow{ID: m.OrgID, Name: m.OrgName, Role: string(m.Role)})
			}
		}
	}
	s.render(w, "org_list.html", map[string]any{
		"Instance": s.instanceName(), "User": u, "CSRF": s.csrfToken(w, r), "Active": "orgs",
		"Orgs": manageable,
	})
}

// store0OrgRow is a tiny view for the org picker (avoids leaking store types into
// the template with an ambiguous name).
type store0OrgRow struct {
	ID   int64
	Name string
	Role string
}

// --- org ingest tokens ---

func (s *Server) handleOrgTokens(w http.ResponseWriter, r *http.Request) {
	s.renderOrgTokens(w, r, "", "")
}

func (s *Server) renderOrgTokens(w http.ResponseWriter, r *http.Request, newToken, snippetRepo string) {
	org, eff, instanceAdmin, _ := s.orgAuthority(r, orgIDFromPath(r))
	if newToken != "" {
		w.Header().Set("Cache-Control", "no-store")
	}
	tokens, err := s.store.ListIngestTokensForOrg(org.ID)
	if err != nil {
		log.Printf("egret-nest: listing org tokens: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.render(w, "org_tokens.html", map[string]any{
		"Instance": s.instanceName(), "User": currentUser(r), "CSRF": s.csrfToken(w, r), "Active": "orgs",
		"Org": org, "Role": string(eff), "InstanceAdmin": instanceAdmin,
		"Tokens": tokens, "IngestURL": s.externalURL(r) + "/ingest",
		"IngestURLDerived": s.cfg.BaseURL == "",
		"NewToken":         newToken, "SnippetRepo": snippetRepo,
	})
}

func (s *Server) handleOrgTokensPost(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	org, _, _, _ := s.orgAuthority(r, orgIDFromPath(r))
	actor := ""
	if u := currentUser(r); u != nil {
		actor = u.Login
	}
	switch r.PostFormValue("action") {
	case "create_token":
		repo := cap140(strings.ToLower(strings.TrimSpace(r.PostFormValue("repository"))))
		name := cap64(strings.TrimSpace(r.PostFormValue("token_name")))
		token, hash, err := auth.NewSecretToken()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if _, err := s.store.CreateIngestToken(&model.IngestToken{
			OrgID: org.ID, Repository: repo, Name: name, TokenHash: hash,
		}); err != nil {
			log.Printf("egret-nest: create org token: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		s.audit(r, actor, "token.create", fmt.Sprintf("org=%d repo=%q", org.ID, repo))
		s.renderOrgTokens(w, r, token, repo) // show once
		return
	case "revoke":
		id, _ := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
		if id != 0 {
			// Atomic cross-org guard: revoke only if the token belongs to THIS org.
			revoked, err := s.store.RevokeIngestTokenInOrg(id, org.ID)
			if err != nil {
				log.Printf("egret-nest: revoke org token %d: %v", id, err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if revoked {
				s.audit(r, actor, "token.revoke", fmt.Sprintf("org=%d id=%d", org.ID, id))
			}
		}
	}
	http.Redirect(w, r, fmt.Sprintf("/org/%d/tokens", org.ID), http.StatusSeeOther)
}

// --- org members ---

// orgMemberRow decorates a member with whether the current manager may act on it
// (so the template doesn't have to reason about role ranks).
type orgMemberRow struct {
	UserID    int64
	Login     string
	Email     string
	Role      model.Role
	CanManage bool
}

// memberErr maps the ?e= redirect code to a user-facing message.
func memberErr(code string) string {
	switch code {
	case "nouser":
		return "No account with that login exists. The user must sign in once before you can add them."
	case "denied":
		return "You can't modify a member who outranks you, or assign a role above your own."
	case "lastowner":
		return "That would remove the organization's last owner. Promote another owner first."
	default:
		return ""
	}
}

func (s *Server) handleOrgMembers(w http.ResponseWriter, r *http.Request) {
	org, eff, instanceAdmin, _ := s.orgAuthority(r, orgIDFromPath(r))
	members, err := s.store.ListOrgMembers(org.ID)
	if err != nil {
		log.Printf("egret-nest: listing org members: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	rows := make([]orgMemberRow, 0, len(members))
	for _, m := range members {
		rows = append(rows, orgMemberRow{
			UserID: m.UserID, Login: m.Login, Email: m.Email, Role: m.Role,
			CanManage: canActOn(eff, m.Role),
		})
	}
	// Only offer roles the manager may actually assign (<= their effective role).
	var assignable []string
	for _, role := range []model.Role{model.RoleOwner, model.RoleAdmin, model.RoleMember, model.RoleViewer} {
		if canAssign(eff, role) {
			assignable = append(assignable, string(role))
		}
	}
	s.render(w, "org_members.html", map[string]any{
		"Instance": s.instanceName(), "User": currentUser(r), "CSRF": s.csrfToken(w, r), "Active": "orgs",
		"Org": org, "Role": string(eff), "InstanceAdmin": instanceAdmin,
		"Members": rows, "AssignableRoles": assignable, "Err": memberErr(r.URL.Query().Get("e")),
	})
}

func (s *Server) handleOrgMembersPost(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	org, eff, _, _ := s.orgAuthority(r, orgIDFromPath(r))
	actor := ""
	if u := currentUser(r); u != nil {
		actor = u.Login
	}
	redirect := fmt.Sprintf("/org/%d/members", org.ID)

	// setMembership routes every grant/role-change through the store's atomic,
	// last-owner-guarded upsert, after checking the actor may act on the target's
	// current role and assign the new one. Centralizing it means no action
	// (add/setrole) can forget the guard — the bug the reviewers caught in `add`.
	setMembership := func(userID int64, newRole model.Role, auditAction string) {
		if !canAssign(eff, newRole) {
			http.Redirect(w, r, redirect+"?e=denied", http.StatusSeeOther)
			return
		}
		cur, err := s.store.GetMembership(org.ID, userID)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if cur != nil && !canActOn(eff, cur.Role) {
			http.Redirect(w, r, redirect+"?e=denied", http.StatusSeeOther)
			return
		}
		if err := s.store.SetMembershipRole(org.ID, userID, newRole); err != nil {
			if errors.Is(err, store.ErrLastOwner) {
				http.Redirect(w, r, redirect+"?e=lastowner", http.StatusSeeOther)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		s.audit(r, actor, auditAction, fmt.Sprintf("user=%d org=%d role=%s", userID, org.ID, newRole))
		http.Redirect(w, r, redirect, http.StatusSeeOther)
	}

	switch r.PostFormValue("action") {
	case "add":
		login := strings.TrimSpace(r.PostFormValue("login"))
		role := model.Role(r.PostFormValue("role"))
		if login == "" || !role.Valid() {
			http.Redirect(w, r, redirect, http.StatusSeeOther)
			return
		}
		u, err := s.store.GetUserByLogin(login)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if u == nil {
			http.Redirect(w, r, redirect+"?e=nouser", http.StatusSeeOther)
			return
		}
		setMembership(u.ID, role, "membership.grant")

	case "setrole":
		userID, _ := strconv.ParseInt(r.PostFormValue("user_id"), 10, 64)
		if userID == 0 {
			http.Redirect(w, r, redirect, http.StatusSeeOther)
			return
		}
		// setrole only changes an EXISTING member's role; it is never a covert
		// "add". Requiring the row here keeps the semantics tight and avoids an
		// insert with a bogus user_id (which would trip a foreign-key error).
		if cur, err := s.store.GetMembership(org.ID, userID); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		} else if cur == nil {
			http.Redirect(w, r, redirect+"?e=denied", http.StatusSeeOther)
			return
		}
		setMembership(userID, model.Role(r.PostFormValue("role")), "membership.setrole")

	case "revoke":
		userID, _ := strconv.ParseInt(r.PostFormValue("user_id"), 10, 64)
		if userID == 0 {
			http.Redirect(w, r, redirect, http.StatusSeeOther)
			return
		}
		cur, err := s.store.GetMembership(org.ID, userID)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if cur == nil || !canActOn(eff, cur.Role) {
			http.Redirect(w, r, redirect+"?e=denied", http.StatusSeeOther)
			return
		}
		if err := s.store.RemoveMembershipGuarded(org.ID, userID); err != nil {
			if errors.Is(err, store.ErrLastOwner) {
				http.Redirect(w, r, redirect+"?e=lastowner", http.StatusSeeOther)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		s.audit(r, actor, "membership.revoke", fmt.Sprintf("user=%d org=%d", userID, org.ID))
		http.Redirect(w, r, redirect, http.StatusSeeOther)
	default:
		http.Redirect(w, r, redirect, http.StatusSeeOther)
	}
}
