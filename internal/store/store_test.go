package store

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/NX1X/Egret-Nest-Dashboard/internal/model"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func sampleEnvelope(repo string, endpoints ...string) *model.Envelope {
	conns := make([]model.Connection, 0, len(endpoints))
	for _, e := range endpoints {
		conns = append(conns, model.Connection{Comm: "curl", Domain: e, Daddr: "1.1.1.1", Dport: 443, Proto: "tcp"})
	}
	return &model.Envelope{
		SchemaVersion: model.SchemaVersion,
		Producer:      "egret",
		Run:           model.RunMeta{Repository: repo, SHA: "abcdef123456", Workflow: "CI"},
		Session: &model.Session{
			Mode:        "block",
			Connections: conns,
			Violations:  []model.Violation{{Kind: "connection", Reason: "raw-ip egress", Blocked: true}},
		},
	}
}

func TestInsertAndList(t *testing.T) {
	st := testStore(t)

	id, newEps, err := st.InsertEnvelope(sampleEnvelope("a/b", "github.com", "api.github.com"), 0)
	if err != nil {
		t.Fatalf("InsertEnvelope: %v", err)
	}
	if id != 1 {
		t.Errorf("first id = %d, want 1", id)
	}
	if len(newEps) != 2 {
		t.Errorf("new endpoints = %v, want 2", newEps)
	}

	runs, err := st.ListRuns(0, true, 10) // as instance admin
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(runs))
	}
	if runs[0].Repository != "a/b" || runs[0].NumConnections != 2 || runs[0].NumViolations != 1 {
		t.Errorf("summary = %+v", runs[0])
	}
}

func TestGetRun(t *testing.T) {
	st := testStore(t)
	id, _, _ := st.InsertEnvelope(sampleEnvelope("a/b", "github.com"), 0)

	run, err := st.GetRun(id, 0, true)
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if run == nil {
		t.Fatal("run not found")
	}
	if run.Session == nil || len(run.Session.Connections) != 1 {
		t.Fatalf("session not restored: %+v", run.Session)
	}
	if run.Session.Connections[0].Domain != "github.com" {
		t.Errorf("connection domain = %q", run.Session.Connections[0].Domain)
	}

	// Missing run returns (nil, nil).
	missing, err := st.GetRun(9999, 0, true)
	if err != nil || missing != nil {
		t.Errorf("GetRun(missing) = %v, %v; want nil, nil", missing, err)
	}
}

func TestEndpointDrift(t *testing.T) {
	st := testStore(t)

	// First run establishes the baseline.
	_, new1, _ := st.InsertEnvelope(sampleEnvelope("a/b", "github.com"), 0)
	if len(new1) != 1 {
		t.Fatalf("first run new endpoints = %v", new1)
	}
	// Second run: github.com is known, tracker.io is new.
	_, new2, _ := st.InsertEnvelope(sampleEnvelope("a/b", "github.com", "tracker.io"), 0)
	if len(new2) != 1 || new2[0] != "tracker.io" {
		t.Errorf("drift = %v, want [tracker.io]", new2)
	}
	// A different repo sees its own endpoints as new.
	_, new3, _ := st.InsertEnvelope(sampleEnvelope("c/d", "github.com"), 0)
	if len(new3) != 1 {
		t.Errorf("per-repo drift = %v, want [github.com]", new3)
	}
}

func TestReposAndEndpoints(t *testing.T) {
	st := testStore(t)
	st.InsertEnvelope(sampleEnvelope("a/b", "github.com", "api.github.com"), 0) // 2 new
	st.InsertEnvelope(sampleEnvelope("a/b", "github.com", "tracker.io"), 0)     // 1 new (tracker)
	st.InsertEnvelope(sampleEnvelope("c/d", "github.com"), 0)                   // 1 new

	// Repo list (as admin).
	repos, err := st.ListRepos(0, true)
	if err != nil {
		t.Fatalf("ListRepos: %v", err)
	}
	if len(repos) != 2 {
		t.Fatalf("repos = %d, want 2", len(repos))
	}
	var ab *RepoSummary
	for i := range repos {
		if repos[i].Repository == "a/b" {
			ab = &repos[i]
		}
	}
	if ab == nil || ab.Runs != 2 || ab.NumViolations != 2 {
		t.Errorf("a/b summary = %+v", ab)
	}

	// Runs for a repo carry the drift count (newest first).
	runs, err := st.RunsForRepo("a/b", 0, true, 10)
	if err != nil || len(runs) != 2 {
		t.Fatalf("RunsForRepo = %d, %v", len(runs), err)
	}
	if runs[0].NumNewEndpoints != 1 {
		t.Errorf("latest a/b run drift = %d, want 1 (tracker.io)", runs[0].NumNewEndpoints)
	}

	// Endpoint inventory.
	eps, err := st.EndpointsForRepo("a/b", 0, true)
	if err != nil || len(eps) != 3 {
		t.Fatalf("EndpointsForRepo = %d, %v (want github.com, api.github.com, tracker.io)", len(eps), err)
	}

	// Visibility: admin yes; a non-member no.
	if ok, _ := st.RepoVisible("a/b", 0, true); !ok {
		t.Error("admin should see a/b")
	}
	if ok, _ := st.RepoVisible("a/b", 999, false); ok {
		t.Error("non-member must not see a/b (IDOR guard)")
	}
}

// Two orgs ingesting the SAME repo string must not see each other's endpoint
// history or runs (regression for the org-agnostic endpoints_seen leak).
func TestCrossTenantEndpointIsolation(t *testing.T) {
	st := testStore(t)
	orgA, _ := st.CreateOrg("org-a")
	orgB, _ := st.CreateOrg("org-b")
	uA, _ := st.CreateUser(&model.User{Login: "usera"})
	uB, _ := st.CreateUser(&model.User{Login: "userb"})
	st.AddMembership(orgA, uA, model.RoleMember)
	st.AddMembership(orgB, uB, model.RoleMember)

	st.InsertEnvelope(sampleEnvelope("x/y", "alpha.example"), orgA)
	st.InsertEnvelope(sampleEnvelope("x/y", "beta.example"), orgB)

	epsA, _ := st.EndpointsForRepo("x/y", uA, false)
	if len(epsA) != 1 || epsA[0].Endpoint != "alpha.example" {
		t.Errorf("org A endpoints = %+v, want only alpha.example", epsA)
	}
	epsB, _ := st.EndpointsForRepo("x/y", uB, false)
	if len(epsB) != 1 || epsB[0].Endpoint != "beta.example" {
		t.Errorf("org B endpoints = %+v, want only beta.example", epsB)
	}
	if runs, _ := st.RunsForRepo("x/y", uA, false, 10); len(runs) != 1 {
		t.Errorf("org A runs for x/y = %d, want 1 (not org B's)", len(runs))
	}

	// A user in neither org sees nothing.
	uC, _ := st.CreateUser(&model.User{Login: "userc"})
	if ok, _ := st.RepoVisible("x/y", uC, false); ok {
		t.Error("non-member must not see x/y")
	}
	if eps, _ := st.EndpointsForRepo("x/y", uC, false); len(eps) != 0 {
		t.Errorf("non-member endpoints = %+v, want none", eps)
	}
}

// A database created before N4 (no runs.num_new_endpoints, no endpoints_seen.org_id)
// must upgrade cleanly on Open - otherwise the next ingest would fail.
func TestSchemaMigrationFromPreN4(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = raw.Exec(`
CREATE TABLE runs (id INTEGER PRIMARY KEY AUTOINCREMENT, received_at TEXT NOT NULL,
  org_id INTEGER NOT NULL DEFAULT 0, schema_version INTEGER NOT NULL, producer TEXT,
  producer_version TEXT, generated_at TEXT, repository TEXT, sha TEXT, ref TEXT, workflow TEXT,
  run_id TEXT, run_attempt TEXT, actor TEXT, mode TEXT, exit_code INTEGER,
  num_connections INTEGER NOT NULL DEFAULT 0, num_violations INTEGER NOT NULL DEFAULT 0,
  session_json TEXT NOT NULL);
CREATE TABLE endpoints_seen (repository TEXT NOT NULL, endpoint TEXT NOT NULL,
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, PRIMARY KEY (repository, endpoint));
INSERT INTO runs (received_at, schema_version, repository, sha, ref, mode, num_connections, num_violations, session_json)
  VALUES ('2026-01-01T00:00:00Z', 1, 'a/b', '', '', 'block', 1, 0, '{}');
INSERT INTO endpoints_seen VALUES ('a/b','github.com','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z');`)
	if err != nil {
		t.Fatalf("seeding pre-N4 schema: %v", err)
	}
	raw.Close()

	st, err := Open(path) // runs migrations
	if err != nil {
		t.Fatalf("Open (migrate): %v", err)
	}
	defer st.Close()

	// Ingest works (would have failed on the missing num_new_endpoints column).
	if _, _, err := st.InsertEnvelope(sampleEnvelope("a/b", "registry.npmjs.org"), 0); err != nil {
		t.Fatalf("ingest after migrate: %v", err)
	}
	runs, err := st.ListRuns(0, true, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 {
		t.Errorf("runs after migrate = %d, want 2 (old + new)", len(runs))
	}
	// Old endpoint (backfilled to org 0) + the new one survive.
	if eps, _ := st.EndpointsForRepo("a/b", 0, true); len(eps) != 2 {
		t.Errorf("endpoints after migrate = %d, want 2", len(eps))
	}
}
