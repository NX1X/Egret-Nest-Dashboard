package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/NX1X/Egret-Nest-Dashboard/internal/model"
)

// --- settings (key/value app config, GUI-managed) ---

// GetSetting returns a setting value, or "" (not an error) when unset.
func (s *Store) GetSetting(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// SetSetting upserts a setting.
func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(
		`INSERT INTO settings (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// DeleteSetting removes a setting (used to "clear"/disable a value).
func (s *Store) DeleteSetting(key string) error {
	_, err := s.db.Exec(`DELETE FROM settings WHERE key = ?`, key)
	return err
}

// settingAAD binds an encrypted setting's ciphertext to its key, so a value can't
// be transplanted to a different setting even with DB write access.
func settingAAD(key string) []byte { return []byte("setting:" + key) }

// ErrNoSecretKey is returned when a secret would be stored but no at-rest
// encryption key (EGRET_NEST_SECRET_KEY) is configured. Secrets are never written
// in plaintext.
var ErrNoSecretKey = errors.New("store: EGRET_NEST_SECRET_KEY must be set to store a secret in the database")

// SecretsEnabled reports whether at-rest encryption is configured (so secret
// settings can be stored).
func (s *Store) SecretsEnabled() bool { return s.enc != nil }

// SealSecret returns the encrypted (enc:v1:) form of a secret bound to its key,
// WITHOUT writing it — the caller includes the result in a WriteSettingsTx batch.
// It refuses when no encryption key is configured (secrets are never stored
// plaintext). An empty plaintext returns "" (caller deletes the row).
func (s *Store) SealSecret(key, plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	if s.enc == nil {
		return "", ErrNoSecretKey
	}
	return s.enc.Encrypt(plaintext, settingAAD(key))
}

// GetSecretSetting returns the decrypted secret, or "" when unset. It uses STRICT
// decryption: a stored value that isn't a proper sealed secret is rejected (these
// keys are always encrypted — there is no legacy-plaintext state to support), so a
// plaintext value injected by another path can't be accepted as a live secret.
func (s *Store) GetSecretSetting(key string) (string, error) {
	v, err := s.GetSetting(key)
	if err != nil || v == "" {
		return "", err
	}
	if s.enc == nil {
		return "", errors.New("store: encrypted setting present but no EGRET_NEST_SECRET_KEY configured")
	}
	return s.enc.DecryptStrict(v, settingAAD(key))
}

// WriteSettings applies a batch of setting writes ATOMICALLY in one transaction:
// each entry with a non-empty value is upserted, each empty value deletes its key.
// Secret values must already be sealed (via SealSecret) by the caller. Used so a
// multi-key auth-provider update can't half-apply (e.g. persist the client id but
// silently drop the allowed-org restriction).
func (s *Store) WriteSettings(kv map[string]string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	for k, v := range kv {
		if v == "" {
			if _, err := tx.Exec(`DELETE FROM settings WHERE key = ?`, k); err != nil {
				return err
			}
			continue
		}
		if _, err := tx.Exec(
			`INSERT INTO settings (key, value) VALUES (?, ?)
			 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, k, v); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// HasSetting reports whether a (non-empty) setting exists, without returning its
// value — used to show a "secret is set" indicator without exposing it.
func (s *Store) HasSetting(key string) (bool, error) {
	v, err := s.GetSetting(key)
	return v != "", err
}

// --- org & token listing for the admin console ---

// ListOrgs returns all organizations, newest first.
func (s *Store) ListOrgs() ([]model.Organization, error) {
	rows, err := s.db.Query(`SELECT id, name, created_at FROM organizations ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Organization
	for rows.Next() {
		var o model.Organization
		var created string
		if err := rows.Scan(&o.ID, &o.Name, &created); err != nil {
			return nil, err
		}
		o.CreatedAt = parseTime(created)
		out = append(out, o)
	}
	return out, rows.Err()
}

// --- users & memberships (admin console) ---

// UserListItem is a user row for the admin Users page, with their org memberships.
type UserListItem struct {
	ID         int64
	Login      string
	Email      string
	IsAdmin    bool
	Source     string // "local", or the IdP prefix (github/oidc) from external_id
	Membership []MembershipView
}

// MembershipView is one (org, role) a user belongs to.
type MembershipView struct {
	OrgID   int64
	OrgName string
	Role    string
}

// ListUsers returns all users (newest first) each with their org memberships. The
// admin Users page uses this to grant/revoke access — SSO users are provisioned
// with NO membership and see nothing until an admin assigns them here.
func (s *Store) ListUsers() ([]UserListItem, error) {
	rows, err := s.db.Query(`SELECT id, login, email, is_admin, COALESCE(external_id,'') FROM users ORDER BY id DESC LIMIT 500`)
	if err != nil {
		return nil, err
	}
	var out []UserListItem
	for rows.Next() {
		var u UserListItem
		var isAdmin int
		var ext string
		if err := rows.Scan(&u.ID, &u.Login, &u.Email, &isAdmin, &ext); err != nil {
			rows.Close()
			return nil, err
		}
		u.IsAdmin = isAdmin != 0
		u.Source = "local"
		if i := strings.IndexByte(ext, ':'); i > 0 {
			u.Source = ext[:i] // "github" / "oidc"
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	// Close the users cursor BEFORE issuing the per-user membership queries: the
	// SQLite pool serializes on a single connection, so a nested Query while these
	// rows are still open would deadlock (the second query waits for a connection
	// the first will not release until iteration completes).
	rows.Close()
	for i := range out {
		if out[i].Membership, err = s.MembershipsForUser(out[i].ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// MembershipsForUser returns the (org, role) pairs a user belongs to.
func (s *Store) MembershipsForUser(userID int64) ([]MembershipView, error) {
	rows, err := s.db.Query(`
SELECT m.org_id, o.name, m.role
FROM memberships m JOIN organizations o ON o.id = m.org_id
WHERE m.user_id = ? ORDER BY o.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MembershipView
	for rows.Next() {
		var m MembershipView
		if err := rows.Scan(&m.OrgID, &m.OrgName, &m.Role); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// RemoveMembership revokes a user's access to an org.
func (s *Store) RemoveMembership(orgID, userID int64) error {
	_, err := s.db.Exec(`DELETE FROM memberships WHERE org_id = ? AND user_id = ?`, orgID, userID)
	return err
}

// TokenListItem is a token row for the management UI — never includes the hash
// or the plaintext token (which is shown once, at creation, and never stored).
type TokenListItem struct {
	ID         int64
	OrgID      int64
	OrgName    string
	Repository string
	Name       string
	CreatedAt  time.Time
	LastUsed   time.Time
	Revoked    bool
}

// ListIngestTokens returns all ingest tokens with their org name for the admin
// console. The token_hash column is deliberately not selected.
func (s *Store) ListIngestTokens() ([]TokenListItem, error) {
	rows, err := s.db.Query(`
SELECT t.id, t.org_id, o.name, t.repository, t.name, t.created_at, t.last_used, t.revoked
FROM ingest_tokens t JOIN organizations o ON o.id = t.org_id
ORDER BY t.id DESC LIMIT 500`)
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
