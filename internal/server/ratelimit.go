package server

import (
	"sync"
	"time"
)

// failLimiter throttles repeated authentication failures per key (IP|login). It
// counts only failures; a successful login resets the key. Purely in-memory -
// adequate for a single self-hosted instance.
type failLimiter struct {
	mu      sync.Mutex
	max     int
	window  time.Duration
	buckets map[string]*failBucket
}

type failBucket struct {
	count   int
	resetAt time.Time
}

func newFailLimiter(max int, window time.Duration) *failLimiter {
	return &failLimiter{max: max, window: window, buckets: make(map[string]*failBucket)}
}

// blocked reports whether key has reached the failure ceiling within its window.
func (l *failLimiter) blocked(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil || now.After(b.resetAt) {
		return false
	}
	return b.count >= l.max
}

// fail records a failure for key, opening a fresh window if the old one lapsed.
func (l *failLimiter) fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.buckets) > 10000 {
		l.pruneLocked(now) // bound memory against a flood of distinct keys
	}
	b := l.buckets[key]
	if b == nil || now.After(b.resetAt) {
		b = &failBucket{resetAt: now.Add(l.window)}
		l.buckets[key] = b
	}
	b.count++
}

// reset clears key's failure record (on successful auth).
func (l *failLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.buckets, key)
}

// pruneLocked drops expired buckets. Caller holds l.mu.
func (l *failLimiter) pruneLocked(now time.Time) {
	for k, b := range l.buckets {
		if now.After(b.resetAt) {
			delete(l.buckets, k)
		}
	}
}
