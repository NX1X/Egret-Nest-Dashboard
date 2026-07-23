package auth

import "testing"

// FuzzSecretBoxDecrypt feeds arbitrary stored values to the at-rest secret
// decryptor. A sealed-secret column is attacker-influenced if the DB is tampered
// with, so Decrypt must never panic - only return the legacy plaintext (for an
// unprefixed value) or an error. Exercised on a real box and on a nil box (the
// "no key configured" path).
func FuzzSecretBoxDecrypt(f *testing.F) {
	box, err := NewSecretBox("0000000000000000000000000000000000000000000000000000000000000000") // 64 hex = 32 bytes
	if err != nil {
		f.Fatalf("test box: %v", err)
	}
	sealed, err := box.Encrypt("hello", []byte("aad"))
	if err != nil {
		f.Fatalf("seed encrypt: %v", err)
	}
	type seed struct {
		stored string
		aad    []byte
	}
	for _, s := range []seed{
		{sealed, []byte("aad")},
		{"enc:v1:not!base64", nil},
		{"enc:v1:", nil},
		{"enc:v1:AAAAAAAA", nil},
		{"legacy-plaintext", nil},
		{"", nil},
	} {
		f.Add(s.stored, s.aad)
	}
	f.Fuzz(func(t *testing.T, stored string, aad []byte) {
		_, _ = box.Decrypt(stored, aad)
		_, _ = box.DecryptStrict(stored, aad)
		var nilBox *SecretBox
		_, _ = nilBox.Decrypt(stored, aad)
	})
}
