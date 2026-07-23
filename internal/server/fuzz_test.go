package server

import "testing"

// FuzzVerifyGitHubSignature fuzzes the webhook HMAC gate with arbitrary signature
// headers - the untrusted `X-Hub-Signature-256` value on an unauthenticated POST.
// It must never panic (hostile hex / prefixes / lengths), always return a bool,
// and be deterministic for the same inputs.
func FuzzVerifyGitHubSignature(f *testing.F) {
	type seed struct {
		header string
		body   []byte
		secret string
	}
	for _, s := range []seed{
		{"sha256=00", []byte("x"), "s"},
		{"sha1=deadbeef", []byte(""), "s"},
		{"", []byte("x"), ""},
		{"sha256=", []byte("x"), "s"},
		{"sha256=zz", []byte("x"), "s"}, // invalid hex
		{"garbage", nil, "secret"},
	} {
		f.Add(s.header, s.body, s.secret)
	}
	f.Fuzz(func(t *testing.T, header string, body []byte, secret string) {
		got := verifyGitHubSignature(secret, header, body)
		if got != verifyGitHubSignature(secret, header, body) {
			t.Fatal("verifyGitHubSignature is non-deterministic")
		}
		_ = got
	})
}
