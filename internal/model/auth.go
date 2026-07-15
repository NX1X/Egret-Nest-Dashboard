package model

import "time"

// Role is an organization-scoped permission level (owner > admin > member > viewer).
type Role string

const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
	RoleViewer Role = "viewer"
)

// rank orders roles for comparison; higher is more privileged.
func (r Role) rank() int {
	switch r {
	case RoleOwner:
		return 4
	case RoleAdmin:
		return 3
	case RoleMember:
		return 2
	case RoleViewer:
		return 1
	default:
		return 0
	}
}

// AtLeast reports whether r is at least as privileged as min.
func (r Role) AtLeast(min Role) bool { return r.rank() >= min.rank() && r.rank() > 0 }

// Valid reports whether r is a known role.
func (r Role) Valid() bool { return r.rank() > 0 }

// User is a dashboard account. PasswordHash/TOTPSecret are empty for users that
// only authenticate via an external IdP (GitHub/OIDC).
type User struct {
	ID           int64
	Login        string
	Email        string
	PasswordHash string `json:"-"` // argon2id; never serialized
	TOTPSecret   string `json:"-"` // base32 seed; never serialized
	TOTPEnabled  bool
	IsAdmin      bool   // instance admin (bootstrap)
	ExternalID   string // IdP link, e.g. "github:12345"; empty for local accounts
	CreatedAt    time.Time
}

// Organization groups repositories and members.
type Organization struct {
	ID        int64
	Name      string
	CreatedAt time.Time
}

// Membership binds a user to an organization with a role.
type Membership struct {
	OrgID  int64
	UserID int64
	Role   Role
}

// LoginSession is a server-side authentication session; only TokenHash is
// stored. (Named LoginSession to avoid colliding with the ingest model.Session.)
type LoginSession struct {
	ID        int64
	TokenHash string `json:"-"`
	UserID    int64
	CreatedAt time.Time
	ExpiresAt time.Time
	LastSeen  time.Time
}

// IngestToken is a scoped, revocable credential for POST /ingest. Only TokenHash
// is stored. Scope: an org, optionally narrowed to a single repository.
type IngestToken struct {
	ID         int64
	OrgID      int64
	Repository string // empty = any repo in the org
	Name       string
	TokenHash  string `json:"-"` // sha256 of the token; never serialized
	CreatedAt  time.Time
	LastUsed   time.Time
	Revoked    bool
}

// AuditEvent is an append-only security-relevant record.
type AuditEvent struct {
	ID         int64
	At         time.Time
	ActorLogin string
	Action     string // e.g. "login", "login.failed", "token.create", "role.change"
	Detail     string
	IP         string
}
