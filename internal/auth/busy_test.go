package auth

import (
	"errors"
	"testing"
	"time"
)

// With every argon2id slot taken, hashing and verification must give up after
// the wait with ErrBusy instead of starting another 64 MiB hash. Once the slots
// are free again, verification works as before.
func TestPasswordHashingReportsBusyWhenEverySlotIsTaken(t *testing.T) {
	const pw = "correct horse battery staple"
	h, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	release := HoldHashSlotsForTest(20 * time.Millisecond)
	if _, err := VerifyPassword(pw, h); !errors.Is(err, ErrBusy) {
		t.Errorf("VerifyPassword with all slots held: err = %v, want ErrBusy", err)
	}
	if _, err := HashPassword("another password"); !errors.Is(err, ErrBusy) {
		t.Errorf("HashPassword with all slots held: err = %v, want ErrBusy", err)
	}
	release()

	ok, err := VerifyPassword(pw, h)
	if err != nil || !ok {
		t.Errorf("VerifyPassword after release = %v, %v; want true, nil", ok, err)
	}
}
