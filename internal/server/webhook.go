package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

const maxWebhookBytes = 1 << 20 // 1 MiB - GitHub webhook payloads are small.

// handleGitHubWebhook receives GitHub webhook deliveries. Every delivery is
// verified by HMAC-SHA256 over the RAW request body against the configured
// secret (constant-time); unverified deliveries are rejected. The endpoint is
// disabled (404) when no webhook secret is configured.
//
// This is authentication-only (no session/cookie), so it is not CSRF-able. Pulling
// a run's report.json artifact on workflow_run.completed is a follow-up that needs
// an App installation token (see docs/AUTH.md §4).
func (s *Server) handleGitHubWebhook(w http.ResponseWriter, r *http.Request) {
	if s.cfg.WebhookSecret == "" {
		http.NotFound(w, r)
		return
	}
	// Bound and read the raw body BEFORE verifying - the signature is over the
	// exact bytes GitHub sent, so we must not decode/re-encode first.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWebhookBytes))
	if err != nil {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	if !verifyGitHubSignature(s.cfg.WebhookSecret, r.Header.Get("X-Hub-Signature-256"), body) {
		s.audit(r, "", "webhook.rejected", "invalid or missing signature")
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	switch event := r.Header.Get("X-GitHub-Event"); event {
	case "ping":
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "pong": true})
	case "workflow_run":
		var p struct {
			Action      string `json:"action"`
			WorkflowRun struct {
				Name       string `json:"name"`
				Conclusion string `json:"conclusion"`
				HeadSHA    string `json:"head_sha"`
			} `json:"workflow_run"`
			Repository struct {
				FullName string `json:"full_name"`
			} `json:"repository"`
		}
		_ = json.Unmarshal(body, &p) // body already validated; ignore shape drift
		repo := canonicalRepo(p.Repository.FullName)
		// Cap the detail: fields come from a (signed but otherwise free-form) payload.
		s.audit(r, "", "webhook.workflow_run",
			capForAudit(p.Action+" "+repo+" "+p.WorkflowRun.Conclusion))
		// Acknowledge. (Report ingestion still happens via POST /ingest with a
		// scoped token; artifact-pull-on-webhook is a tracked follow-up.)
		writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "repository": repo})
	default:
		// Verified but unhandled event - acknowledge so GitHub doesn't retry.
		writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "ignored": event})
	}
}

// verifyGitHubSignature reports whether header ("sha256=<hex>") is a valid
// HMAC-SHA256 of body keyed by secret. Constant-time; false on any malformed input.
func verifyGitHubSignature(secret, header string, body []byte) bool {
	const prefix = "sha256="
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	gotMAC, err := hex.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hmac.Equal(mac.Sum(nil), gotMAC)
}

// canonicalRepo lowercases a repo full name to match the ingest store's convention.
func canonicalRepo(fullName string) string {
	return strings.ToLower(strings.TrimSpace(fullName))
}
