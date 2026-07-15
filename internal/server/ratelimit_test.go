package server

import (
	"testing"
	"time"
)

func TestFailLimiter(t *testing.T) {
	l := newFailLimiter(3, time.Minute)
	now := time.Unix(1000, 0)
	key := "1.2.3.4|alice"

	if l.blocked(key, now) {
		t.Fatal("fresh key should not be blocked")
	}
	l.fail(key, now)
	l.fail(key, now)
	if l.blocked(key, now) {
		t.Error("2 failures (< max 3) should not block")
	}
	l.fail(key, now) // 3rd failure reaches the ceiling
	if !l.blocked(key, now) {
		t.Error("3 failures (>= max) should block")
	}

	// A successful login resets the key.
	l.reset(key)
	if l.blocked(key, now) {
		t.Error("reset should clear the block")
	}

	// The window expires.
	l.fail(key, now)
	l.fail(key, now)
	l.fail(key, now)
	if !l.blocked(key, now) {
		t.Fatal("should be blocked again")
	}
	if l.blocked(key, now.Add(2*time.Minute)) {
		t.Error("block should lapse after the window")
	}

	// Distinct keys are independent.
	if l.blocked("9.9.9.9|bob", now) {
		t.Error("a different key must not inherit another's failures")
	}
}
