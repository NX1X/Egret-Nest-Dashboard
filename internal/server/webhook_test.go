package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
)

// signBody returns the GitHub "sha256=<hex>" signature header for body+secret.
func signBody(secret, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// postWebhook sends a raw body with the given event + signature headers.
func postWebhook(t *testing.T, base, event, sig, body string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+"/webhook/github", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if event != "" {
		req.Header.Set("X-GitHub-Event", event)
	}
	if sig != "" {
		req.Header.Set("X-Hub-Signature-256", sig)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post webhook: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestWebhookDisabledWithoutSecret(t *testing.T) {
	ts, _ := newTestServer(t, Config{}) // no WebhookSecret
	if code := postWebhook(t, ts.URL, "ping", "", "{}"); code != http.StatusNotFound {
		t.Errorf("webhook with no secret = %d, want 404", code)
	}
}

func TestWebhookValidSignature(t *testing.T) {
	const secret = "whsec_test_secret_value"
	ts, _ := newTestServer(t, Config{WebhookSecret: secret})

	body := `{"zen":"Keep it simple."}`
	if code := postWebhook(t, ts.URL, "ping", signBody(secret, body), body); code != http.StatusOK {
		t.Errorf("valid ping = %d, want 200", code)
	}

	wr := `{"action":"completed","workflow_run":{"conclusion":"success","head_sha":"abc"},"repository":{"full_name":"Acme/Build"}}`
	if code := postWebhook(t, ts.URL, "workflow_run", signBody(secret, wr), wr); code != http.StatusAccepted {
		t.Errorf("valid workflow_run = %d, want 202", code)
	}
}

func TestWebhookInvalidSignatureRejected(t *testing.T) {
	const secret = "whsec_test_secret_value"
	ts, _ := newTestServer(t, Config{WebhookSecret: secret})
	body := `{"zen":"nope"}`

	// Wrong secret used to sign.
	if code := postWebhook(t, ts.URL, "ping", signBody("wrong-secret", body), body); code != http.StatusUnauthorized {
		t.Errorf("wrong-secret signature = %d, want 401", code)
	}
	// Missing signature header.
	if code := postWebhook(t, ts.URL, "ping", "", body); code != http.StatusUnauthorized {
		t.Errorf("missing signature = %d, want 401", code)
	}
	// Tampered body (valid sig for a different body).
	if code := postWebhook(t, ts.URL, "ping", signBody(secret, body), body+"tampered"); code != http.StatusUnauthorized {
		t.Errorf("tampered body = %d, want 401", code)
	}
	// Malformed signature.
	if code := postWebhook(t, ts.URL, "ping", "sha256=not-hex", body); code != http.StatusUnauthorized {
		t.Errorf("malformed signature = %d, want 401", code)
	}
}

func TestWebhookUnknownEventAcknowledged(t *testing.T) {
	const secret = "whsec_test_secret_value"
	ts, _ := newTestServer(t, Config{WebhookSecret: secret})
	body := `{}`
	// Verified but unhandled event -> 202 (so GitHub doesn't retry).
	if code := postWebhook(t, ts.URL, "issues", signBody(secret, body), body); code != http.StatusAccepted {
		t.Errorf("unknown verified event = %d, want 202", code)
	}
}

func TestVerifyGitHubSignatureUnit(t *testing.T) {
	const secret = "s"
	body := []byte("hello")
	good := signBody(secret, "hello")
	if !verifyGitHubSignature(secret, good, body) {
		t.Error("valid signature rejected")
	}
	for _, bad := range []string{"", "sha1=deadbeef", "sha256=", "sha256=zz", good + "00"} {
		if verifyGitHubSignature(secret, bad, body) {
			t.Errorf("malformed signature accepted: %q", bad)
		}
	}
}
