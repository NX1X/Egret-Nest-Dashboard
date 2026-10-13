// Package auth holds the dashboard's security primitives: password hashing
// (argon2id), TOTP 2FA (RFC 6238), and secure random tokens. Everything here is
// self-contained and unit-tested; higher layers (store, middleware, handlers)
// build on it. Reviewed by security review.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
)

// ErrInvalidHash is returned when a stored password hash cannot be parsed.
var ErrInvalidHash = errors.New("invalid password hash format")

// ErrBusy is returned when no argon2id slot became free within hashWait.
var ErrBusy = errors.New("password hashing is busy")

// maxConcurrentHashes bounds concurrent argon2id work across the process. Each
// hash with the default parameters allocates 64 MiB, and login runs one even for
// an unknown user (timing equalization). Unbounded, about 4 parallel anonymous
// logins exhausted the 256 MiB container limit (measured: 8 parallel hashes
// peaked at 513 MiB). Two slots cap hashing at about 128 MiB.
const maxConcurrentHashes = 2

// defaultHashWait is how long a caller waits for a free argon2id slot.
const defaultHashWait = 3 * time.Second

var (
	hashSlots = make(chan struct{}, maxConcurrentHashes)
	// hashWaitNanos overrides defaultHashWait when non-zero (tests only).
	// Atomic, because handlers read it on other goroutines.
	hashWaitNanos atomic.Int64
)

// acquireHashSlot waits up to the hash wait for a free argon2id slot.
func acquireHashSlot() bool {
	wait := defaultHashWait
	if n := hashWaitNanos.Load(); n > 0 {
		wait = time.Duration(n)
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case hashSlots <- struct{}{}:
		return true
	case <-t.C:
		return false
	}
}

func releaseHashSlot() { <-hashSlots }

// HoldHashSlotsForTest occupies every argon2id slot and sets the wait for a free
// slot to wait, so a caller's ErrBusy handling can be tested. It returns a func
// that releases the slots and restores the default wait. Tests only; the
// production code never calls it.
func HoldHashSlotsForTest(wait time.Duration) (release func()) {
	hashWaitNanos.Store(int64(wait))
	for i := 0; i < maxConcurrentHashes; i++ {
		hashSlots <- struct{}{}
	}
	return func() {
		for i := 0; i < maxConcurrentHashes; i++ {
			<-hashSlots
		}
		hashWaitNanos.Store(0)
	}
}

// argonParams are tuned for interactive logins (~64 MiB, 1 pass). Adjust upward
// as hardware allows; parameters are stored in the hash so old hashes verify.
type argonParams struct {
	memory  uint32
	time    uint32
	threads uint8
	keyLen  uint32
	saltLen uint32
}

var defaultParams = argonParams{memory: 64 * 1024, time: 1, threads: 4, keyLen: 32, saltLen: 16}

// HashPassword returns a PHC-format argon2id hash:
//
//	$argon2id$v=19$m=65536,t=1,p=4$<salt>$<hash>
func HashPassword(password string) (string, error) {
	salt := make([]byte, defaultParams.saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating salt: %w", err)
	}
	if !acquireHashSlot() {
		return "", ErrBusy
	}
	defer releaseHashSlot()
	key := argon2.IDKey([]byte(password), salt,
		defaultParams.time, defaultParams.memory, defaultParams.threads, defaultParams.keyLen)

	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, defaultParams.memory, defaultParams.time, defaultParams.threads,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// VerifyPassword reports whether password matches the encoded argon2id hash.
// The comparison is constant-time. A malformed hash returns ErrInvalidHash.
func VerifyPassword(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	// ["", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, ErrInvalidHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, ErrInvalidHash
	}
	var mem, t uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &t, &threads); err != nil {
		return false, ErrInvalidHash
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false, ErrInvalidHash
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil {
		return false, ErrInvalidHash
	}

	if !acquireHashSlot() {
		return false, ErrBusy
	}
	defer releaseHashSlot()
	got := argon2.IDKey([]byte(password), salt, t, mem, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(want, got) == 1, nil
}
