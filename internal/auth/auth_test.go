package auth

import (
	"strings"
	"testing"
	"time"
)

func TestPasswordHashVerify(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("unexpected hash format: %s", hash)
	}

	ok, err := VerifyPassword("correct horse battery staple", hash)
	if err != nil || !ok {
		t.Errorf("correct password should verify: ok=%v err=%v", ok, err)
	}
	ok, _ = VerifyPassword("wrong", hash)
	if ok {
		t.Error("wrong password must not verify")
	}

	// Two hashes of the same password differ (random salt).
	hash2, _ := HashPassword("correct horse battery staple")
	if hash == hash2 {
		t.Error("hashes should be salted (differ)")
	}
}

func TestPasswordVerifyRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "notahash", "$argon2id$bad", "$bcrypt$x$y$z$a$b"} {
		if _, err := VerifyPassword("x", bad); err == nil {
			t.Errorf("expected error for malformed hash %q", bad)
		}
	}
}

func TestTOTP(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatalf("NewTOTPSecret: %v", err)
	}
	now := time.Unix(1_700_000_000, 0)

	code, err := TOTPCodeAt(secret, now)
	if err != nil {
		t.Fatalf("TOTPCodeAt: %v", err)
	}
	if len(code) != 6 {
		t.Errorf("code = %q, want 6 digits", code)
	}
	if !VerifyTOTP(secret, code, now, 1) {
		t.Error("current code should verify")
	}
	// Within skew window (previous period).
	if !VerifyTOTP(secret, code, now.Add(30*time.Second), 1) {
		t.Error("code should verify within +/-1 period skew")
	}
	// Outside skew window.
	if VerifyTOTP(secret, code, now.Add(5*time.Minute), 1) {
		t.Error("stale code must not verify outside skew")
	}
	// Wrong code.
	if VerifyTOTP(secret, "000000", now, 1) {
		t.Error("wrong code must not verify")
	}
}

func TestVerifyTOTPCounter(t *testing.T) {
	secret, _ := NewTOTPSecret()
	now := time.Unix(1_700_000_000, 0)
	code, _ := TOTPCodeAt(secret, now)

	c1, ok := VerifyTOTPCounter(secret, code, now, 1)
	if !ok {
		t.Fatal("current code should verify")
	}
	// The same code at the same time yields the same counter, so a caller can
	// detect and reject a replay.
	c2, ok := VerifyTOTPCounter(secret, code, now, 1)
	if !ok || c1 != c2 {
		t.Errorf("counter should be stable: %d vs %d (ok=%v)", c1, c2, ok)
	}
	if _, ok := VerifyTOTPCounter(secret, "000000", now, 1); ok {
		t.Error("wrong code must not verify")
	}
}

func TestProvisioningURI(t *testing.T) {
	uri := TOTPProvisioningURI("ABC123", "alice@example.com", "Egret Nest")
	if !strings.HasPrefix(uri, "otpauth://totp/") ||
		!strings.Contains(uri, "secret=ABC123") ||
		!strings.Contains(uri, "issuer=Egret+Nest") {
		t.Errorf("uri = %q", uri)
	}
}

func TestTokens(t *testing.T) {
	pt, hash, err := NewSecretToken()
	if err != nil {
		t.Fatalf("NewSecretToken: %v", err)
	}
	if pt == "" || hash == "" || pt == hash {
		t.Errorf("token/hash look wrong: %q / %q", pt, hash)
	}
	if HashToken(pt) != hash {
		t.Error("HashToken must be deterministic and match")
	}
	if !EqualToken(hash, HashToken(pt)) {
		t.Error("EqualToken should match equal hashes")
	}
	if EqualToken(hash, HashToken("other")) {
		t.Error("EqualToken should not match different hashes")
	}
	// Two tokens are distinct.
	pt2, _, _ := NewSecretToken()
	if pt == pt2 {
		t.Error("tokens should be random/distinct")
	}
}
