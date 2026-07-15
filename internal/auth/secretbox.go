package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// SecretBox provides authenticated encryption (AES-256-GCM) for small secrets
// stored at rest — specifically TOTP seeds, which are password-equivalent: with
// the plaintext seed an attacker who reads the database can mint valid 2FA codes.
//
// Stored form is "enc:v1:" + base64(nonce || ciphertext||tag). The version tag
// lets us rotate schemes later, and — importantly — a value WITHOUT the prefix is
// treated as legacy plaintext by Decrypt, so enabling encryption on an existing
// database is a clean, in-place upgrade (rows re-encrypt as they are rewritten).
type SecretBox struct {
	aead cipher.AEAD
}

const secretPrefix = "enc:v1:"

// NewSecretBox builds a box from a 32-byte key encoded as base64-std (44 chars)
// or hex (64 chars). An empty key returns (nil, nil): encryption is optional and
// callers treat a nil box as "store plaintext" (with a startup warning).
func NewSecretBox(key string) (*SecretBox, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, nil
	}
	raw, err := decodeKey(key)
	if err != nil {
		return nil, err
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("secret key must be 32 bytes (AES-256), got %d", len(raw))
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &SecretBox{aead: aead}, nil
}

func decodeKey(key string) ([]byte, error) {
	if b, err := hex.DecodeString(key); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(key); err == nil {
		return b, nil
	}
	return nil, errors.New("secret key must be hex (64 chars) or base64 (32 bytes)")
}

// Encrypt returns the sealed, prefixed, base64 form of plaintext. An empty
// plaintext is returned unchanged (no point encrypting "no secret").
//
// aad is authenticated-but-not-encrypted associated data bound into the tag — pass
// a stable per-row identity (e.g. the user id) so a sealed value cannot be copied
// to a different row and still decrypt (defends against ciphertext-swap).
func (b *SecretBox) Encrypt(plaintext string, aad []byte) (string, error) {
	if b == nil || plaintext == "" {
		return plaintext, nil
	}
	if strings.HasPrefix(plaintext, secretPrefix) {
		return plaintext, nil // already encrypted; don't double-wrap
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := b.aead.Seal(nonce, nonce, []byte(plaintext), aad)
	return secretPrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// DecryptStrict is Decrypt without the legacy-plaintext fallback: a value that is
// not properly sealed (missing the enc:v1: prefix) is rejected instead of returned
// as-is. Use it for fields that are ALWAYS encrypted (no migration history), so a
// plaintext value injected by another path can't be silently accepted.
func (b *SecretBox) DecryptStrict(stored string, aad []byte) (string, error) {
	if !strings.HasPrefix(stored, secretPrefix) {
		return "", errors.New("value is not encrypted (expected a sealed secret)")
	}
	return b.Decrypt(stored, aad)
}

// Decrypt reverses Encrypt and verifies aad matches what was sealed. A value
// without the prefix is legacy plaintext and is returned as-is (aad ignored), so a
// database written before encryption was enabled still works.
func (b *SecretBox) Decrypt(stored string, aad []byte) (string, error) {
	if !strings.HasPrefix(stored, secretPrefix) {
		return stored, nil // legacy plaintext
	}
	if b == nil {
		return "", errors.New("value is encrypted but no secret key is configured")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, secretPrefix))
	if err != nil {
		return "", fmt.Errorf("decoding sealed secret: %w", err)
	}
	ns := b.aead.NonceSize()
	if len(raw) < ns {
		return "", errors.New("sealed secret too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	pt, err := b.aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return "", fmt.Errorf("opening sealed secret: %w", err)
	}
	return string(pt), nil
}
