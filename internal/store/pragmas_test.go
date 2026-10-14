package store

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// The pragmas must hold on the connection the store actually uses.
func TestOpenSetsBusyTimeoutWALAndForeignKeys(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var mode string
	var timeout, fk int
	if err := s.db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
		t.Errorf("journal_mode = %q (err %v), want wal", mode, err)
	}
	if err := s.db.QueryRow(`PRAGMA busy_timeout`).Scan(&timeout); err != nil || timeout != 5000 {
		t.Errorf("busy_timeout = %d (err %v), want 5000", timeout, err)
	}
	if err := s.db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil || fk != 1 {
		t.Errorf("foreign_keys = %d (err %v), want 1", fk, err)
	}
}

// Regression: `egret-nest backup` runs as a second process and reads the database
// while the server keeps writing. In rollback-journal mode a reader's lock made
// the server's writes fail at once with SQLITE_BUSY (logins and ingest -> 500).
// A second connection holding an open read transaction simulates the backup.
func TestWritesSucceedWhileAnotherProcessReads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "w.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.SetSetting("k", "v1"); err != nil {
		t.Fatal(err)
	}

	backup, err := sql.Open("sqlite", path) // another process: no special pragmas
	if err != nil {
		t.Fatal(err)
	}
	defer backup.Close()
	tx, err := backup.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var v string
	if err := tx.QueryRow(`SELECT value FROM settings WHERE key = 'k'`).Scan(&v); err != nil {
		t.Fatalf("reader: %v", err)
	}

	if err := s.SetSetting("k", "v2"); err != nil {
		t.Fatalf("server write failed while another process was reading: %v", err)
	}
}
