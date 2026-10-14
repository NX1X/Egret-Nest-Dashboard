//go:build unix

package main

import "syscall"

// restrictUmask makes every file this process creates owner-only (0600 files,
// 0700 directories). The SQLite database is chmod'ed to 0600 explicitly, but in
// WAL mode SQLite also creates -wal and -shm files that hold real page data, and
// those followed the inherited umask (typically 0644, readable by every local
// user). The same applies to backup files, which were created first and
// chmod'ed to 0600 only afterwards.
func restrictUmask() { syscall.Umask(0o077) }
