package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func newKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func TestSecretBoxRoundTrip(t *testing.T) {
	box, err := NewSecretBox(newKey(t))
	if err != nil {
		t.Fatalf("NewSecretBox: %v", err)
	}
	const secret = "JBSWY3DPEHPK3PXP"
	sealed, err := box.Encrypt(secret, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !strings.HasPrefix(sealed, secretPrefix) {
		t.Errorf("ciphertext lacks version prefix: %q", sealed)
	}
	if strings.Contains(sealed, secret) {
		t.Error("plaintext leaked into ciphertext")
	}
	got, err := box.Decrypt(sealed, nil)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != secret {
		t.Errorf("round trip = %q, want %q", got, secret)
	}
	// Two encryptions of the same value differ (random nonce).
	sealed2, _ := box.Encrypt(secret, nil)
	if sealed == sealed2 {
		t.Error("nonce reuse: identical ciphertexts for same plaintext")
	}
}

func TestSecretBoxLegacyPlaintextPassthrough(t *testing.T) {
	box, _ := NewSecretBox(newKey(t))
	// A value stored before encryption was enabled has no prefix and must pass
	// through Decrypt unchanged, so enabling a key is a clean in-place upgrade.
	got, err := box.Decrypt("PLAINTEXTSEED", nil)
	if err != nil || got != "PLAINTEXTSEED" {
		t.Errorf("legacy passthrough = %q, %v; want PLAINTEXTSEED", got, err)
	}
}

func TestSecretBoxWrongKeyFails(t *testing.T) {
	a, _ := NewSecretBox(newKey(t))
	b, _ := NewSecretBox(newKey(t))
	sealed, _ := a.Encrypt("secret", nil)
	if _, err := b.Decrypt(sealed, nil); err == nil {
		t.Error("decrypt with wrong key should fail (GCM auth)")
	}
}

func TestSecretBoxNilIsOptional(t *testing.T) {
	box, err := NewSecretBox("")
	if err != nil || box != nil {
		t.Errorf("empty key should yield (nil, nil), got %v, %v", box, err)
	}
	// A nil box safely no-ops.
	if v, _ := box.Encrypt("x", nil); v != "x" {
		t.Errorf("nil Encrypt = %q, want x", v)
	}
	if v, _ := box.Decrypt("x", nil); v != "x" {
		t.Errorf("nil Decrypt = %q, want x", v)
	}
}

func TestSecretBoxKeyEncodings(t *testing.T) {
	raw := make([]byte, 32)
	rand.Read(raw)
	for _, k := range []string{hex.EncodeToString(raw), base64.StdEncoding.EncodeToString(raw)} {
		if _, err := NewSecretBox(k); err != nil {
			t.Errorf("key %q rejected: %v", k, err)
		}
	}
	// Wrong length is rejected.
	if _, err := NewSecretBox(hex.EncodeToString(raw[:16])); err == nil {
		t.Error("16-byte key should be rejected")
	}
}

func TestSecretBoxAADMismatchFails(t *testing.T) {
	box, _ := NewSecretBox(newKey(t))
	sealed, err := box.Encrypt("JBSWY3DPEHPK3PXP", []byte("user:1"))
	if err != nil {
		t.Fatal(err)
	}
	// Same key, wrong AAD (e.g. a seed copied to another user's row) → must fail.
	if _, err := box.Decrypt(sealed, []byte("user:2")); err == nil {
		t.Error("decrypt with mismatched AAD should fail (ciphertext-swap defence)")
	}
	// Correct AAD round-trips.
	got, err := box.Decrypt(sealed, []byte("user:1"))
	if err != nil || got != "JBSWY3DPEHPK3PXP" {
		t.Errorf("round trip with correct AAD = %q, %v", got, err)
	}
}
