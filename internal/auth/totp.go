package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	totpDigits = 6
	totpPeriod = 30 // seconds
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a base32 secret (160 bits) for enrolling an authenticator.
func NewTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating totp secret: %w", err)
	}
	return b32.EncodeToString(b), nil
}

// hotp computes the RFC 4226 HOTP value for a counter (SHA-1, 6 digits).
func hotp(secret string, counter uint64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", fmt.Errorf("decoding totp secret: %w", err)
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	return fmt.Sprintf("%0*d", totpDigits, code%1_000_000), nil
}

// TOTPCodeAt returns the expected code for secret at time t.
func TOTPCodeAt(secret string, t time.Time) (string, error) {
	return hotp(secret, uint64(t.Unix())/totpPeriod)
}

// VerifyTOTPCounter reports whether code is valid for secret at time t (allowing
// +/- skew periods of drift) and, when valid, returns the matched time-step
// counter. Callers record that counter to prevent replay of a still-valid code.
// Comparison is constant-time.
func VerifyTOTPCounter(secret, code string, t time.Time, skew int) (counter int64, ok bool) {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return 0, false
	}
	base := int64(t.Unix()) / totpPeriod
	for i := -skew; i <= skew; i++ {
		c := base + int64(i)
		want, err := hotp(secret, uint64(c))
		if err != nil {
			return 0, false
		}
		if hmac.Equal([]byte(want), []byte(code)) {
			return c, true
		}
	}
	return 0, false
}

// VerifyTOTP reports whether code is valid for secret at time t. Prefer
// VerifyTOTPCounter at login so the code can be marked used (anti-replay).
func VerifyTOTP(secret, code string, t time.Time, skew int) bool {
	_, ok := VerifyTOTPCounter(secret, code, t, skew)
	return ok
}

// TOTPProvisioningURI builds an otpauth:// URI for QR-code enrollment.
func TOTPProvisioningURI(secret, account, issuer string) string {
	label := url.PathEscape(issuer + ":" + account)
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprintf("%d", totpDigits))
	v.Set("period", fmt.Sprintf("%d", totpPeriod))
	return "otpauth://totp/" + label + "?" + v.Encode()
}
