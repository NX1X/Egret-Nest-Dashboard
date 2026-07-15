package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// NewSecretToken returns a URL-safe random token (256 bits) and its SHA-256
// hash (hex). Store ONLY the hash; show the plaintext to the user exactly once.
// Used for session ids and scoped ingest tokens.
func NewSecretToken() (plaintext, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generating token: %w", err)
	}
	plaintext = base64.RawURLEncoding.EncodeToString(b)
	return plaintext, HashToken(plaintext), nil
}

// HashToken returns the hex SHA-256 of a token plaintext (for storage/lookup).
// SHA-256 is appropriate here because tokens are high-entropy random values,
// not low-entropy passwords.
func HashToken(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// EqualToken compares two token hashes in constant time.
func EqualToken(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
