package store

import (
	"crypto/rand"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"github.com/NX1X/Egret-Nest-Dashboard/internal/auth"
	"github.com/NX1X/Egret-Nest-Dashboard/internal/model"
)

func testKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// TestTOTPEncryptedAtRest verifies the seed is ciphertext in the column but
// plaintext when read back through the store.
func TestTOTPEncryptedAtRest(t *testing.T) {
	st := testStore(t)
	box, err := auth.NewSecretBox(testKey(t))
	if err != nil {
		t.Fatalf("box: %v", err)
	}
	st.UseSecretBox(box)

	const seed = "JBSWY3DPEHPK3PXP"
	uid, err := st.CreateUser(&model.User{Login: "alice", TOTPSecret: seed, TOTPEnabled: true})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Raw column must NOT contain the plaintext seed.
	var raw string
	if err := st.db.QueryRow(`SELECT totp_secret FROM users WHERE id=?`, uid).Scan(&raw); err != nil {
		t.Fatalf("raw read: %v", err)
	}
	if raw == seed || raw == "" {
		t.Fatalf("totp_secret stored in plaintext: %q", raw)
	}

	// Read back through the store -> decrypted plaintext.
	u, err := st.GetUserByID(uid)
	if err != nil || u == nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if u.TOTPSecret != seed {
		t.Errorf("decrypted seed = %q, want %q", u.TOTPSecret, seed)
	}
}

// TestTOTPPlaintextWithoutKey confirms behaviour is unchanged when no box is set.
func TestTOTPPlaintextWithoutKey(t *testing.T) {
	st := testStore(t) // no UseSecretBox
	const seed = "PLAINSEED123"
	uid, _ := st.CreateUser(&model.User{Login: "bob", TOTPSecret: seed})
	var raw string
	st.db.QueryRow(`SELECT totp_secret FROM users WHERE id=?`, uid).Scan(&raw)
	if raw != seed {
		t.Errorf("without a key, seed should be plaintext, got %q", raw)
	}
}

func TestSnapshotCounts(t *testing.T) {
	st := testStore(t)
	orgID, _ := st.CreateOrg("acme")
	st.CreateUser(&model.User{Login: "u1"})
	st.CreateUser(&model.User{Login: "u2"})
	if _, _, err := st.InsertEnvelope(sampleEnvelope("a/b", "github.com"), orgID); err != nil {
		t.Fatalf("insert: %v", err)
	}
	m, err := st.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if m.Users != 2 || m.Orgs != 1 || m.Runs != 1 || m.Endpoints != 1 {
		t.Errorf("snapshot = %+v", m)
	}
}

func TestPruneRunsBefore(t *testing.T) {
	st := testStore(t)
	orgID, _ := st.CreateOrg("acme")
	st.InsertEnvelope(sampleEnvelope("a/b", "github.com"), orgID)

	// Cutoff in the past keeps the fresh run.
	if n, err := st.PruneRunsBefore(time.Now().Add(-time.Hour)); err != nil || n != 0 {
		t.Errorf("past-cutoff prune removed %d (err %v), want 0", n, err)
	}
	// Cutoff in the future removes it (and its endpoints).
	if n, err := st.PruneRunsBefore(time.Now().Add(time.Hour)); err != nil || n != 1 {
		t.Errorf("future-cutoff prune removed %d (err %v), want 1", n, err)
	}
	m, _ := st.Snapshot()
	if m.Runs != 0 || m.Endpoints != 0 {
		t.Errorf("after prune, runs=%d endpoints=%d, want 0/0", m.Runs, m.Endpoints)
	}
}

func TestBackupProducesUsableCopy(t *testing.T) {
	st := testStore(t)
	orgID, _ := st.CreateOrg("acme")
	st.InsertEnvelope(sampleEnvelope("a/b", "github.com"), orgID)

	dest := filepath.Join(t.TempDir(), "backup.db")
	if err := st.Backup(dest); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	// The copy opens and carries the run.
	cp, err := Open(dest)
	if err != nil {
		t.Fatalf("open backup: %v", err)
	}
	defer cp.Close()
	m, _ := cp.Snapshot()
	if m.Runs != 1 {
		t.Errorf("backup has %d runs, want 1", m.Runs)
	}
}

func TestPruneAuditBefore(t *testing.T) {
	st := testStore(t)
	st.Audit(model.AuditEvent{ActorLogin: "a", Action: "login"})
	if n, err := st.PruneAuditBefore(time.Now().Add(time.Hour)); err != nil || n != 1 {
		t.Errorf("prune audit removed %d (err %v), want 1", n, err)
	}
	events, _ := st.ListAuditLog(10)
	if len(events) != 0 {
		t.Errorf("audit not pruned: %d remain", len(events))
	}
}
