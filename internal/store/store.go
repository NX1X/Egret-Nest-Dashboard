// Package store persists ingested runs in SQLite (pure-Go modernc.org/sqlite,
// no CGO - keeps the dashboard a single static binary). A run is stored as
// summary columns for listing plus the full session JSON for the detail view;
// observed endpoints are tracked per-repo for allowlist drift.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/NX1X/Egret-Nest-Dashboard/internal/auth"
	"github.com/NX1X/Egret-Nest-Dashboard/internal/model"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

// Store is a SQLite-backed run store.
type Store struct {
	db  *sql.DB
	enc *auth.SecretBox // optional at-rest encryption for TOTP seeds (nil = plaintext)
}

// UseSecretBox enables AES-256-GCM encryption of TOTP secrets at rest. Call once
// after Open, before serving. A nil box (no key configured) leaves seeds in
// plaintext - the caller warns on startup.
func (s *Store) UseSecretBox(b *auth.SecretBox) { s.enc = b }

// encTOTP/decTOTP transparently seal/open the TOTP seed when a box is configured.
// The user id is bound as AES-GCM associated data, so a sealed seed copied to
// another user's row fails to decrypt (no ciphertext-swap). With no box they are
// identity functions, and Decrypt passes through legacy plaintext, so enabling a
// key on an existing DB is a clean upgrade.
func totpAAD(userID int64) []byte {
	return []byte("totp:user:" + strconv.FormatInt(userID, 10))
}

func (s *Store) encTOTP(userID int64, secret string) (string, error) {
	if s.enc == nil {
		return secret, nil
	}
	return s.enc.Encrypt(secret, totpAAD(userID))
}

func (s *Store) decTOTP(userID int64, stored string) (string, error) {
	if s.enc == nil {
		return stored, nil
	}
	return s.enc.Decrypt(stored, totpAAD(userID))
}

// Open opens (creating if needed) the SQLite database at path and runs
// migrations. Use ":memory:" for tests that don't need persistence.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite %q: %w", path, err)
	}
	// modernc/sqlite is fine with a small pool; keep it simple and safe.
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("pinging sqlite: %w", err)
	}
	// The live DB holds password/session/token hashes, audit PII, and (without a
	// key) plaintext TOTP seeds - restrict it to the owner rather than trusting
	// the process umask. Best-effort: a real file only (":memory:" has no path).
	if path != ":memory:" && path != "" {
		if err := os.Chmod(path, 0o600); err != nil && !os.IsNotExist(err) {
			log.Printf("egret-nest: could not restrict permissions on %q: %v", path, err)
		}
	}
	// SQLite disables FK enforcement by default (modernc included), so
	// ON DELETE CASCADE would be a no-op without this. Safe with the single
	// connection above.
	if _, err := db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		db.Close()
		return nil, fmt.Errorf("enabling foreign keys: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Ping reports whether the database is reachable (cheap; used by /healthz).
func (s *Store) Ping() error { return s.db.Ping() }

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS runs (
	id               INTEGER PRIMARY KEY AUTOINCREMENT,
	received_at      TEXT NOT NULL,
	org_id           INTEGER NOT NULL DEFAULT 0,
	schema_version   INTEGER NOT NULL,
	producer         TEXT,
	producer_version TEXT,
	generated_at     TEXT,
	repository       TEXT,
	sha              TEXT,
	ref              TEXT,
	workflow         TEXT,
	run_id           TEXT,
	run_attempt      TEXT,
	actor            TEXT,
	mode             TEXT,
	exit_code        INTEGER,
	num_connections  INTEGER NOT NULL DEFAULT 0,
	num_violations   INTEGER NOT NULL DEFAULT 0,
	num_new_endpoints INTEGER NOT NULL DEFAULT 0,
	session_json     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_repo ON runs(repository);
CREATE INDEX IF NOT EXISTS idx_runs_org ON runs(org_id);

CREATE TABLE IF NOT EXISTS endpoints_seen (
	repository TEXT NOT NULL,
	org_id     INTEGER NOT NULL DEFAULT 0,
	endpoint   TEXT NOT NULL,
	first_seen TEXT NOT NULL,
	last_seen  TEXT NOT NULL,
	PRIMARY KEY (repository, org_id, endpoint)
);`
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("migrating: %w", err)
	}
	if err := s.migrateSchema(); err != nil {
		return fmt.Errorf("migrating schema: %w", err)
	}
	if err := s.migrateAuth(); err != nil {
		return fmt.Errorf("migrating auth: %w", err)
	}
	return nil
}

// migrateSchema brings a pre-existing database up to the current schema with
// idempotent ALTERs - `CREATE TABLE IF NOT EXISTS` does NOT add columns to an
// existing table, so column additions must be applied explicitly here.
func (s *Store) migrateSchema() error {
	// N4: per-run drift count.
	if has, err := s.hasColumn("runs", "num_new_endpoints"); err != nil {
		return err
	} else if !has {
		if _, err := s.db.Exec(`ALTER TABLE runs ADD COLUMN num_new_endpoints INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("adding runs.num_new_endpoints: %w", err)
		}
	}
	// N4: org-scope endpoints_seen (changing the PK requires a table rebuild).
	if has, err := s.hasColumn("endpoints_seen", "org_id"); err != nil {
		return err
	} else if !has {
		const rebuild = `
CREATE TABLE endpoints_seen_new (
	repository TEXT NOT NULL, org_id INTEGER NOT NULL DEFAULT 0, endpoint TEXT NOT NULL,
	first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
	PRIMARY KEY (repository, org_id, endpoint));
INSERT INTO endpoints_seen_new (repository, org_id, endpoint, first_seen, last_seen)
	SELECT repository, 0, endpoint, first_seen, last_seen FROM endpoints_seen;
DROP TABLE endpoints_seen;
ALTER TABLE endpoints_seen_new RENAME TO endpoints_seen;`
		if _, err := s.db.Exec(rebuild); err != nil {
			return fmt.Errorf("rebuilding endpoints_seen: %w", err)
		}
	}
	return nil
}

// hasColumn reports whether table has a column named col. table is always a
// compile-time constant here (never user input).
func (s *Store) hasColumn(table, col string) (bool, error) {
	rows, err := s.db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return false, err
		}
		if name == col {
			return true, nil
		}
	}
	return false, rows.Err()
}

// RunSummary is a row for the run list.
type RunSummary struct {
	ID              int64
	ReceivedAt      time.Time
	Repository      string
	SHA             string
	Ref             string
	Mode            string
	NumConnections  int
	NumViolations   int
	NumNewEndpoints int // endpoints seen for the first time in this repo (drift)
}

// RepoSummary aggregates a repository's runs for the repo list.
type RepoSummary struct {
	Repository    string
	Runs          int
	NumViolations int
	LastSeen      time.Time
}

// EndpointRow is one observed endpoint's history for a repository.
type EndpointRow struct {
	Endpoint  string
	FirstSeen time.Time
	LastSeen  time.Time
}

// Run is a full run for the detail view.
type Run struct {
	RunSummary
	Producer        string
	ProducerVersion string
	Workflow        string
	RunID           string
	Actor           string
	ExitCode        int
	GeneratedAt     time.Time
	Session         *model.Session
}

// InsertEnvelope stores a run and updates the per-repo endpoint history.
// Returns the new run id and the endpoints that were seen for the first time
// (allowlist drift).
// orgID scopes the run to an organization (0 = unassigned; only instance admins
// see unassigned runs). It comes from the authenticated ingest token.
func (s *Store) InsertEnvelope(env *model.Envelope, orgID int64) (id int64, newEndpoints []string, err error) {
	sess := env.Session
	if sess == nil {
		sess = &model.Session{}
	}
	sessionJSON, err := json.Marshal(sess)
	if err != nil {
		return 0, nil, fmt.Errorf("marshalling session: %w", err)
	}
	now := time.Now().UTC()
	// Canonicalize the repo name (GitHub full names are case-insensitive) so a
	// case variant can't create a second, distinct repository record.
	repo := strings.ToLower(env.Run.Repository)

	tx, err := s.db.Begin()
	if err != nil {
		return 0, nil, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit

	res, err := tx.Exec(`
INSERT INTO runs (received_at, org_id, schema_version, producer, producer_version,
	generated_at, repository, sha, ref, workflow, run_id, run_attempt, actor,
	mode, exit_code, num_connections, num_violations, session_json)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		rfc3339(now), orgID, env.SchemaVersion, env.Producer, env.ProducerVersion,
		rfc3339(env.GeneratedAt), repo, env.Run.SHA, env.Run.Ref,
		env.Run.Workflow, env.Run.RunID, env.Run.RunAttempt, env.Run.Actor,
		sess.Mode, sess.ExitCode, len(sess.Connections), len(sess.Violations),
		string(sessionJSON))
	if err != nil {
		return 0, nil, fmt.Errorf("inserting run: %w", err)
	}
	id, err = res.LastInsertId()
	if err != nil {
		return 0, nil, err
	}

	seen := map[string]bool{}
	for _, c := range sess.Connections {
		ep := c.Endpoint()
		if ep == "" || seen[ep] {
			continue
		}
		seen[ep] = true
		isNew, err := upsertEndpoint(tx, orgID, repo, ep, now)
		if err != nil {
			return 0, nil, err
		}
		if isNew {
			newEndpoints = append(newEndpoints, ep)
		}
	}

	if _, err := tx.Exec(`UPDATE runs SET num_new_endpoints=? WHERE id=?`, len(newEndpoints), id); err != nil {
		return 0, nil, err
	}
	if err := tx.Commit(); err != nil {
		return 0, nil, err
	}
	return id, newEndpoints, nil
}

// upsertEndpoint inserts or updates last_seen for (repo, org, endpoint), scoped
// per-organization so one org can neither read nor poison another's drift history.
func upsertEndpoint(tx *sql.Tx, orgID int64, repo, endpoint string, now time.Time) (bool, error) {
	var existing string
	err := tx.QueryRow(
		`SELECT first_seen FROM endpoints_seen WHERE repository=? AND org_id=? AND endpoint=?`,
		repo, orgID, endpoint).Scan(&existing)
	switch err {
	case sql.ErrNoRows:
		_, err = tx.Exec(
			`INSERT INTO endpoints_seen (repository, org_id, endpoint, first_seen, last_seen) VALUES (?,?,?,?,?)`,
			repo, orgID, endpoint, rfc3339(now), rfc3339(now))
		return true, err
	case nil:
		_, err = tx.Exec(
			`UPDATE endpoints_seen SET last_seen=? WHERE repository=? AND org_id=? AND endpoint=?`,
			rfc3339(now), repo, orgID, endpoint)
		return false, err
	default:
		return false, err
	}
}

const runSummaryCols = `id, received_at, repository, sha, ref, mode, num_connections, num_violations, num_new_endpoints`

// orgScope returns a WHERE clause (empty for admins) plus args that restrict rows
// to organizations the viewer belongs to - the query-layer authz boundary.
func orgScope(viewerID int64, isAdmin bool) (string, []any) {
	if isAdmin {
		return "", nil
	}
	return "WHERE org_id IN (SELECT org_id FROM memberships WHERE user_id = ?)", []any{viewerID}
}

func scanRunSummaries(rows *sql.Rows) ([]RunSummary, error) {
	defer rows.Close()
	var out []RunSummary
	for rows.Next() {
		var r RunSummary
		var received string
		if err := rows.Scan(&r.ID, &received, &r.Repository, &r.SHA, &r.Ref,
			&r.Mode, &r.NumConnections, &r.NumViolations, &r.NumNewEndpoints); err != nil {
			return nil, err
		}
		r.ReceivedAt = parseTime(received)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListRuns returns the most recent runs visible to the viewer, newest first.
// Instance admins see every run; other users see only runs in organizations they
// belong to (prevents IDOR).
func (s *Store) ListRuns(viewerID int64, isAdmin bool, limit int) ([]RunSummary, error) {
	if limit <= 0 {
		limit = 50
	}
	where, args := orgScope(viewerID, isAdmin)
	args = append(args, limit)
	rows, err := s.db.Query(`SELECT `+runSummaryCols+` FROM runs `+where+` ORDER BY id DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	return scanRunSummaries(rows)
}

// RunsForRepo returns the viewer-visible runs for a single repository.
func (s *Store) RunsForRepo(repo string, viewerID int64, isAdmin bool, limit int) ([]RunSummary, error) {
	if limit <= 0 {
		limit = 50
	}
	repo = strings.ToLower(repo)
	where, args := orgScope(viewerID, isAdmin)
	if where == "" {
		where = "WHERE repository = ?"
	} else {
		where += " AND repository = ?"
	}
	args = append(args, repo, limit)
	rows, err := s.db.Query(`SELECT `+runSummaryCols+` FROM runs `+where+` ORDER BY id DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	return scanRunSummaries(rows)
}

// ListRepos aggregates the viewer-visible runs by repository, newest activity first.
func (s *Store) ListRepos(viewerID int64, isAdmin bool) ([]RepoSummary, error) {
	where, args := orgScope(viewerID, isAdmin)
	rows, err := s.db.Query(`
SELECT repository, COUNT(*), COALESCE(SUM(num_violations),0), MAX(received_at)
FROM runs `+where+`
GROUP BY repository ORDER BY MAX(received_at) DESC LIMIT 500`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RepoSummary
	for rows.Next() {
		var r RepoSummary
		var last string
		if err := rows.Scan(&r.Repository, &r.Runs, &r.NumViolations, &last); err != nil {
			return nil, err
		}
		r.LastSeen = parseTime(last)
		out = append(out, r)
	}
	return out, rows.Err()
}

// RepoVisible reports whether the viewer may see a repository (has a run for it
// in one of their orgs; admins always may). Callers must gate EndpointsForRepo
// on this, since endpoints_seen is keyed only by repository.
func (s *Store) RepoVisible(repo string, viewerID int64, isAdmin bool) (bool, error) {
	if isAdmin {
		return true, nil
	}
	var n int
	err := s.db.QueryRow(`
SELECT COUNT(*) FROM runs
WHERE repository = ? AND org_id IN (SELECT org_id FROM memberships WHERE user_id = ?)`,
		strings.ToLower(repo), viewerID).Scan(&n)
	return n > 0, err
}

// EndpointsForRepo returns the observed-endpoint history for a repository within
// the viewer's organizations (admins see all orgs), most-recently-seen first.
// Org-scoped so one org's endpoint history never leaks to another.
func (s *Store) EndpointsForRepo(repo string, viewerID int64, isAdmin bool) ([]EndpointRow, error) {
	repo = strings.ToLower(repo)
	where, args := orgScope(viewerID, isAdmin)
	if where == "" {
		where = "WHERE repository = ?"
	} else {
		where += " AND repository = ?"
	}
	args = append(args, repo)
	// GROUP BY endpoint so an admin viewing across orgs sees each endpoint once,
	// with the earliest first_seen and latest last_seen.
	rows, err := s.db.Query(`
SELECT endpoint, MIN(first_seen), MAX(last_seen) FROM endpoints_seen `+where+`
GROUP BY endpoint ORDER BY MAX(last_seen) DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EndpointRow
	for rows.Next() {
		var e EndpointRow
		var fs, ls string
		if err := rows.Scan(&e.Endpoint, &fs, &ls); err != nil {
			return nil, err
		}
		e.FirstSeen, e.LastSeen = parseTime(fs), parseTime(ls)
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetRun returns a run visible to the viewer, or (nil, nil) if absent OR not
// authorized - returning "not found" for both avoids confirming the existence of
// a run in another organization (no IDOR, no enumeration oracle).
func (s *Store) GetRun(id, viewerID int64, isAdmin bool) (*Run, error) {
	var r Run
	var received, generated, sessionJSON string
	query := `
SELECT id, received_at, generated_at, repository, sha, ref, mode,
	num_connections, num_violations, num_new_endpoints, producer, producer_version,
	workflow, run_id, actor, exit_code, session_json
FROM runs WHERE id = ?`
	args := []any{id}
	if !isAdmin {
		query += ` AND org_id IN (SELECT org_id FROM memberships WHERE user_id = ?)`
		args = append(args, viewerID)
	}
	err := s.db.QueryRow(query, args...).Scan(
		&r.ID, &received, &generated, &r.Repository, &r.SHA, &r.Ref, &r.Mode,
		&r.NumConnections, &r.NumViolations, &r.NumNewEndpoints, &r.Producer, &r.ProducerVersion,
		&r.Workflow, &r.RunID, &r.Actor, &r.ExitCode, &sessionJSON)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.ReceivedAt = parseTime(received)
	r.GeneratedAt = parseTime(generated)
	if err := json.Unmarshal([]byte(sessionJSON), &r.Session); err != nil {
		return nil, fmt.Errorf("parsing stored session: %w", err)
	}
	return &r, nil
}

// PruneRunsBefore deletes runs received before the cutoff and any endpoint
// history whose last sighting predates it (retention). Returns runs removed.
// Called by the janitor only when RetentionDays > 0.
func (s *Store) PruneRunsBefore(cutoff time.Time) (int64, error) {
	c := rfc3339(cutoff.UTC())
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	res, err := tx.Exec(`DELETE FROM runs WHERE received_at < ?`, c)
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`DELETE FROM endpoints_seen WHERE last_seen < ?`, c); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Metrics is a point-in-time snapshot for the /metrics endpoint.
type Metrics struct {
	Users          int64
	Orgs           int64
	Runs           int64
	ActiveSessions int64 // non-expired
	IngestTokens   int64 // non-revoked
	AuditEvents    int64
	Endpoints      int64
}

// Snapshot returns aggregate counts. Cheap COUNT(*) queries; the DB is small.
func (s *Store) Snapshot() (Metrics, error) {
	var m Metrics
	now := rfc3339(time.Now().UTC())
	q := func(dst *int64, query string, args ...any) error {
		return s.db.QueryRow(query, args...).Scan(dst)
	}
	if err := q(&m.Users, `SELECT COUNT(*) FROM users`); err != nil {
		return m, err
	}
	if err := q(&m.Orgs, `SELECT COUNT(*) FROM organizations`); err != nil {
		return m, err
	}
	if err := q(&m.Runs, `SELECT COUNT(*) FROM runs`); err != nil {
		return m, err
	}
	if err := q(&m.ActiveSessions, `SELECT COUNT(*) FROM sessions WHERE expires_at > ?`, now); err != nil {
		return m, err
	}
	if err := q(&m.IngestTokens, `SELECT COUNT(*) FROM ingest_tokens WHERE revoked = 0`); err != nil {
		return m, err
	}
	if err := q(&m.AuditEvents, `SELECT COUNT(*) FROM audit_log`); err != nil {
		return m, err
	}
	if err := q(&m.Endpoints, `SELECT COUNT(*) FROM endpoints_seen`); err != nil {
		return m, err
	}
	return m, nil
}

// Backup writes a consistent copy of the database to dest using SQLite's online
// `VACUUM INTO`, which snapshots without blocking writers and compacts the file.
// dest must not already exist (SQLite refuses to overwrite). The path is passed
// as a bound parameter, so it is not string-concatenated into SQL.
//
// The copy carries the full secrets-bearing schema (password/session/token
// hashes and TOTP seeds), so it is chmod'd to 0600 - don't rely on umask for a
// credential-bearing file.
func (s *Store) Backup(dest string) error {
	if _, err := s.db.Exec(`VACUUM INTO ?`, dest); err != nil {
		return fmt.Errorf("backup to %q: %w", dest, err)
	}
	if err := os.Chmod(dest, 0o600); err != nil {
		return fmt.Errorf("restricting backup permissions on %q: %w", dest, err)
	}
	return nil
}

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}
