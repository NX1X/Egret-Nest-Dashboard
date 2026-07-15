package server

import (
	"sync"
	"time"
)

// AccessEntry is one HTTP request as recorded by the access-log middleware.
type AccessEntry struct {
	Time   time.Time
	Method string
	Path   string
	Status int
	DurMS  int64
	IP     string
	User   string // authenticated login, or "" for anonymous
}

// ringLog is a fixed-capacity, concurrency-safe circular buffer of the most
// recent requests, so the admin "Logs" page can show browsing activity without
// persisting request logs to disk (they're transient and may contain paths).
type ringLog struct {
	mu   sync.Mutex
	buf  []AccessEntry
	next int
	full bool
}

func newRingLog(capacity int) *ringLog {
	if capacity <= 0 {
		capacity = 500
	}
	return &ringLog{buf: make([]AccessEntry, capacity)}
}

func (r *ringLog) add(e AccessEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf[r.next] = e
	r.next = (r.next + 1) % len(r.buf)
	if r.next == 0 {
		r.full = true
	}
}

// recent returns up to limit entries, newest first.
func (r *ringLog) recent(limit int) []AccessEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.next
	if r.full {
		n = len(r.buf)
	}
	if limit <= 0 || limit > n {
		limit = n
	}
	out := make([]AccessEntry, 0, limit)
	// Walk backwards from the most recently written slot.
	for i := 0; i < limit; i++ {
		idx := (r.next - 1 - i + len(r.buf)) % len(r.buf)
		out = append(out, r.buf[idx])
	}
	return out
}
