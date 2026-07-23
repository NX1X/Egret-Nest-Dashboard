package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/NX1X/Egret-Nest-Dashboard/internal/model"
)

// migrateAuth creates the identity/authz/audit tables. All parameterized queries
// go through database/sql placeholders - no string-built SQL
func (s *Store) migrateAuth() error {
	const schema = `
CREATE TABLE IF NOT EXISTS users (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	login         TEXT NOT NULL UNIQUE COLLATE NOCASE,
	email         TEXT NOT NULL DEFAULT '',
	password_hash TEXT NOT NULL DEFAULT '',
	totp_secret   TEXT NOT NULL DEFAULT '',
	totp_enabled  INTEGER NOT NULL DEFAULT 0,
	is_admin      INTEGER NOT NULL DEFAULT 0,
	external_id   TEXT,   -- e.g. "github:12345" for IdP-linked accounts; NULL for local
	created_at    TEXT NOT NULL
);
-- Uniqueness enforced only for linked accounts (multiple NULLs allowed).
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_extid ON users(external_id) WHERE external_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS organizations (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT NOT NULL UNIQUE COLLATE NOCASE,
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS memberships (
	org_id  INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
	user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	role    TEXT NOT NULL,
	PRIMARY KEY (org_id, user_id)
);
CREATE TABLE IF NOT EXISTS sessions (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	token_hash TEXT NOT NULL UNIQUE,
	user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	last_seen  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS ingest_tokens (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	org_id     INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
	repository TEXT NOT NULL DEFAULT '',
	name       TEXT NOT NULL DEFAULT '',
	token_hash TEXT NOT NULL UNIQUE,
	created_at TEXT NOT NULL,
	last_used  TEXT NOT NULL DEFAULT '',
	revoked    INTEGER NOT NULL DEFAULT 0,
	UNIQUE (org_id, name)
);
CREATE TABLE IF NOT EXISTS audit_log (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	at          TEXT NOT NULL,
	actor_login TEXT NOT NULL DEFAULT '',
	action      TEXT NOT NULL,
	detail      TEXT NOT NULL DEFAULT '',
	ip          TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_login);
CREATE TABLE IF NOT EXISTS totp_used (
	user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	counter INTEGER NOT NULL,
	at      TEXT NOT NULL,
	PRIMARY KEY (user_id, counter)
);
CREATE TABLE IF NOT EXISTS settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);`
	_, err := s.db.Exec(schema)
	return err
}

// --- users ---

// CountUsers returns the number of users (used to detect first-run bootstrap).
func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// Bootstrapped reports whether first-run setup has completed. The dedicated
// `bootstrapped` settings flag is the source of truth (set atomically inside
// BootstrapAdmin), so a squatting non-admin account created by another path (e.g.
// SSO auto-provisioning) can't retire /setup just by making CountUsers() > 0. As a
// fallback for databases created before the flag existed, any existing user also
// counts as bootstrapped.
func (s *Store) Bootstrapped() (bool, error) {
	v, err := s.GetSetting("bootstrapped")
	if err != nil {
		return false, err
	}
	if v == "1" {
		return true, nil
	}
	n, err := s.CountUsers()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// CreateUser inserts a user and returns its id. ExternalID, when set, links the
// account to an IdP identity (e.g. "github:12345"); empty is stored as NULL.
//
// The TOTP seed (encrypted at rest, AES-GCM-bound to the user id) is written in a
// second step: the id it's bound to doesn't exist until the row does. Most callers
// create accounts without a TOTP seed (it's set later at enrollment).
func (s *Store) CreateUser(u *model.User) (int64, error) {
	res, err := s.db.Exec(`
INSERT INTO users (login, email, password_hash, totp_secret, totp_enabled, is_admin, external_id, created_at)
VALUES (?,?,?,?,?,?,?,?)`,
		u.Login, u.Email, u.PasswordHash, "", boolInt(u.TOTPEnabled),
		boolInt(u.IsAdmin), nullIfEmpty(u.ExternalID), rfc3339(time.Now().UTC()))
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if u.TOTPSecret != "" {
		if err := s.SetUserTOTP(id, u.TOTPSecret, u.TOTPEnabled); err != nil {
			return 0, fmt.Errorf("setting totp secret: %w", err)
		}
	}
	return id, nil
}

const userCols = `id, login, email, password_hash, totp_secret, totp_enabled, is_admin, external_id, created_at`

// GetUserByLogin returns the user or (nil, nil) if none.
func (s *Store) GetUserByLogin(login string) (*model.User, error) {
	return s.scanUser(s.db.QueryRow(
		`SELECT `+userCols+` FROM users WHERE login = ? COLLATE NOCASE`, login))
}

// GetUserByID returns the user or (nil, nil) if none.
func (s *Store) GetUserByID(id int64) (*model.User, error) {
	return s.scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

// GetUserByExternalID returns the IdP-linked user or (nil, nil) if none.
func (s *Store) GetUserByExternalID(extID string) (*model.User, error) {
	if extID == "" {
		return nil, nil
	}
	return s.scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE external_id = ?`, extID))
}

func (s *Store) scanUser(row *sql.Row) (*model.User, error) {
	var u model.User
	var created string
	var extID sql.NullString
	var totpEnabled, isAdmin int
	err := row.Scan(&u.ID, &u.Login, &u.Email, &u.PasswordHash, &u.TOTPSecret,
		&totpEnabled, &isAdmin, &extID, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.TOTPEnabled = totpEnabled != 0
	u.IsAdmin = isAdmin != 0
	u.ExternalID = extID.String
	u.CreatedAt = parseTime(created)
	if u.TOTPSecret, err = s.decTOTP(u.ID, u.TOTPSecret); err != nil {
		return nil, fmt.Errorf("decrypting totp secret: %w", err)
	}
	return &u, nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// SetUserTOTP updates a user's TOTP secret and enabled flag. The seed is
// encrypted at rest when a secret box is configured.
func (s *Store) SetUserTOTP(userID int64, secret string, enabled bool) error {
	sealed, err := s.encTOTP(userID, secret)
	if err != nil {
		return fmt.Errorf("encrypting totp secret: %w", err)
	}
	_, err = s.db.Exec(`UPDATE users SET totp_secret=?, totp_enabled=? WHERE id=?`,
		sealed, boolInt(enabled), userID)
	return err
}

// BootstrapAdmin atomically creates the first admin (+ a "default" org they own)
// IFF no bootstrap has happened yet. The claim is a single INSERT into `settings`
// gated by its PRIMARY KEY, in the SAME transaction as the user/org creation, so
// two concurrent /setup requests cannot both succeed (closes the check-then-create
// TOCTOU). Returns ok=false when the instance is already bootstrapped.
func (s *Store) BootstrapAdmin(login, passwordHash string) (id int64, ok bool, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback() //nolint:errcheck

	res, err := tx.Exec(`INSERT OR IGNORE INTO settings (key, value) VALUES ('bootstrapped','1')`)
	if err != nil {
		return 0, false, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, false, nil // already bootstrapped - lose the race, fail closed
	}

	now := rfc3339(time.Now().UTC())
	ur, err := tx.Exec(`
INSERT INTO users (login, email, password_hash, totp_secret, totp_enabled, is_admin, external_id, created_at)
VALUES (?, '', ?, '', 0, 1, NULL, ?)`, login, passwordHash, now)
	if err != nil {
		return 0, false, err
	}
	if id, err = ur.LastInsertId(); err != nil {
		return 0, false, err
	}
	or, err := tx.Exec(`INSERT INTO organizations (name, created_at) VALUES ('default', ?)`, now)
	if err != nil {
		return 0, false, err
	}
	orgID, err := or.LastInsertId()
	if err != nil {
		return 0, false, err
	}
	if _, err = tx.Exec(`INSERT INTO memberships (org_id, user_id, role) VALUES (?, ?, ?)`,
		orgID, id, string(model.RoleOwner)); err != nil {
		return 0, false, err
	}
	if err = tx.Commit(); err != nil {
		return 0, false, err
	}
	return id, true, nil
}

// --- orgs & memberships ---

func (s *Store) CreateOrg(name string) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO organizations (name, created_at) VALUES (?,?)`,
		name, rfc3339(time.Now().UTC()))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetOrgByName returns the org or (nil, nil) if none.
func (s *Store) GetOrgByName(name string) (*model.Organization, error) {
	var o model.Organization
	var created string
	err := s.db.QueryRow(`SELECT id, name, created_at FROM organizations WHERE name = ? COLLATE NOCASE`, name).
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

func (s *Store) AddMembership(orgID, userID int64, role model.Role) error {
	_, err := s.db.Exec(`
INSERT INTO memberships (org_id, user_id, role) VALUES (?,?,?)
ON CONFLICT(org_id, user_id) DO UPDATE SET role=excluded.role`,
		orgID, userID, string(role))
	return err
}

// GetMembership returns the user's role in an org, or (nil, nil) if not a member.
func (s *Store) GetMembership(orgID, userID int64) (*model.Membership, error) {
	var m model.Membership
	var role string
	err := s.db.QueryRow(`SELECT org_id, user_id, role FROM memberships WHERE org_id=? AND user_id=?`,
		orgID, userID).Scan(&m.OrgID, &m.UserID, &role)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	m.Role = model.Role(role)
	return &m, nil
}

// --- sessions ---

func (s *Store) CreateSession(userID int64, tokenHash string, expiresAt time.Time) error {
	now := rfc3339(time.Now().UTC())
	_, err := s.db.Exec(`
INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_seen)
VALUES (?,?,?,?,?)`, tokenHash, userID, now, rfc3339(expiresAt), now)
	return err
}

// GetSessionByToken returns a non-expired session for the token hash, or nil.
// Expiry is enforced in SQL so an expired token is never returned (avoids the
// fetch-then-check race).
func (s *Store) GetSessionByToken(tokenHash string) (*model.LoginSession, error) {
	var sess model.LoginSession
	var created, expires, lastSeen string
	err := s.db.QueryRow(`
SELECT id, token_hash, user_id, created_at, expires_at, last_seen
FROM sessions WHERE token_hash = ? AND expires_at > ?`,
		tokenHash, rfc3339(time.Now().UTC())).Scan(
		&sess.ID, &sess.TokenHash, &sess.UserID, &created, &expires, &lastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sess.CreatedAt, sess.ExpiresAt, sess.LastSeen = parseTime(created), parseTime(expires), parseTime(lastSeen)
	return &sess, nil
}

// PruneExpiredSessions removes sessions past their expiry (call periodically).
func (s *Store) PruneExpiredSessions() error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at <= ?`, rfc3339(time.Now().UTC()))
	return err
}

func (s *Store) TouchSession(tokenHash string) error {
	_, err := s.db.Exec(`UPDATE sessions SET last_seen=? WHERE token_hash=?`,
		rfc3339(time.Now().UTC()), tokenHash)
	return err
}

func (s *Store) DeleteSession(tokenHash string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token_hash=?`, tokenHash)
	return err
}

func (s *Store) DeleteUserSessions(userID int64) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE user_id=?`, userID)
	return err
}

// --- ingest tokens ---

func (s *Store) CreateIngestToken(t *model.IngestToken) (int64, error) {
	res, err := s.db.Exec(`
INSERT INTO ingest_tokens (org_id, repository, name, token_hash, created_at)
VALUES (?,?,?,?,?)`, t.OrgID, t.Repository, t.Name, t.TokenHash, rfc3339(time.Now().UTC()))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetIngestTokenByHash returns a non-revoked token by hash, or nil.
func (s *Store) GetIngestTokenByHash(tokenHash string) (*model.IngestToken, error) {
	var t model.IngestToken
	var created, lastUsed string
	var revoked int
	err := s.db.QueryRow(`
SELECT id, org_id, repository, name, token_hash, created_at, last_used, revoked
FROM ingest_tokens WHERE token_hash = ?`, tokenHash).Scan(
		&t.ID, &t.OrgID, &t.Repository, &t.Name, &t.TokenHash, &created, &lastUsed, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if revoked != 0 {
		return nil, nil
	}
	t.CreatedAt, t.LastUsed = parseTime(created), parseTime(lastUsed)
	return &t, nil
}

func (s *Store) TouchIngestToken(id int64) error {
	_, err := s.db.Exec(`UPDATE ingest_tokens SET last_used=? WHERE id=?`,
		rfc3339(time.Now().UTC()), id)
	return err
}

func (s *Store) RevokeIngestToken(id int64) error {
	_, err := s.db.Exec(`UPDATE ingest_tokens SET revoked=1 WHERE id=?`, id)
	return err
}

// ClaimTOTPCode atomically marks a (user, time-counter) pair as consumed. It
// returns true if the code was newly claimed, false if it was already used -
// which is a replay and must be rejected. INSERT OR IGNORE makes the check and
// the claim a single atomic step.
func (s *Store) ClaimTOTPCode(userID, counter int64) (bool, error) {
	res, err := s.db.Exec(
		`INSERT OR IGNORE INTO totp_used (user_id, counter, at) VALUES (?,?,?)`,
		userID, counter, rfc3339(time.Now().UTC()))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// PruneTOTPUsed removes consumed-code records older than the given cutoff (their
// window has long passed). Call periodically.
func (s *Store) PruneTOTPUsed(before time.Time) error {
	_, err := s.db.Exec(`DELETE FROM totp_used WHERE at < ?`, rfc3339(before.UTC()))
	return err
}

// --- audit ---

// Audit appends a security event. Best-effort: callers log but don't fail on error.
func (s *Store) Audit(ev model.AuditEvent) error {
	_, err := s.db.Exec(`
INSERT INTO audit_log (at, actor_login, action, detail, ip) VALUES (?,?,?,?,?)`,
		rfc3339(time.Now().UTC()), ev.ActorLogin, ev.Action, ev.Detail, ev.IP)
	return err
}

// ListAuditLog returns the most recent audit events, newest first. Bounded by
// limit (capped at 1000) so a huge table can't blow up a page render. The audit
// log is instance-wide, so callers MUST gate this on an instance admin.
func (s *Store) ListAuditLog(limit int) ([]model.AuditEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.Query(`
SELECT id, at, actor_login, action, detail, ip
FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.AuditEvent
	for rows.Next() {
		var e model.AuditEvent
		var at string
		if err := rows.Scan(&e.ID, &at, &e.ActorLogin, &e.Action, &e.Detail, &e.IP); err != nil {
			return nil, err
		}
		e.At = parseTime(at)
		out = append(out, e)
	}
	return out, rows.Err()
}

// PruneAuditBefore deletes audit events older than the cutoff. Returns the number
// removed. Retention is opt-in (RetentionDays); the audit log is otherwise kept.
func (s *Store) PruneAuditBefore(cutoff time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM audit_log WHERE at < ?`, rfc3339(cutoff.UTC()))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
