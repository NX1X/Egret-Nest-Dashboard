package server

import (
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/NX1X/Egret-Nest-Dashboard/internal/auth"
)

// The account page lets a LOCAL (password) user enrol and remove TOTP two-factor
// auth themselves. SSO (GitHub/OIDC) users authenticate through their IdP, which
// owns MFA, so TOTP is not offered to them.
//
// Enrolment is a two-step, pending-secret flow:
//   1. "begin"   — generate a secret, store it with totp_enabled=0 (pending). A
//                  pending secret never affects login (login only checks TOTP
//                  when enabled), so a half-finished enrolment can't lock anyone
//                  out. The secret is encrypted at rest (AES-GCM, bound to the
//                  user id).
//   2. "confirm" — the user proves possession by entering a current code; only
//                  then is totp_enabled flipped to 1.
// Disabling requires a current code too, so a session-only attacker (who never
// had the second factor) cannot turn 2FA off.

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	data := map[string]any{
		"Instance": s.instanceName(), "User": u, "CSRF": s.csrfToken(w, r), "Active": "account",
		"IsLocal": u.PasswordHash != "", "TOTPEnabled": u.TOTPEnabled,
		"Err": accountErr(r.URL.Query().Get("e")), "Msg": accountMsg(r.URL.Query().Get("m")),
	}
	// A pending (generated but not yet confirmed) secret: show it for enrolment.
	// The page body carries the raw secret + otpauth URI, so opt out of caching
	// (matching renderSettings / renderOrgTokens for shown-once secrets).
	if u.PasswordHash != "" && !u.TOTPEnabled && u.TOTPSecret != "" {
		w.Header().Set("Cache-Control", "no-store")
		data["Pending"] = true
		data["Secret"] = u.TOTPSecret
		data["OtpauthURI"] = auth.TOTPProvisioningURI(u.TOTPSecret, u.Login, s.instanceName())
	}
	s.render(w, "account.html", data)
}

func accountErr(code string) string {
	switch code {
	case "badcode":
		return "That code didn't match. Check your authenticator's clock and try again."
	case "throttled":
		return "Too many attempts. Wait a few minutes and try again."
	case "notlocal":
		return "Two-factor auth applies to password accounts; SSO logins use your identity provider's MFA."
	default:
		return ""
	}
}

func accountMsg(code string) string {
	switch code {
	case "enabled":
		return "Two-factor authentication is now on."
	case "disabled":
		return "Two-factor authentication has been turned off."
	default:
		return ""
	}
}

func (s *Server) handleAccountPost(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	u := currentUser(r)
	// TOTP is only meaningful for local password accounts.
	if u.PasswordHash == "" {
		http.Redirect(w, r, "/account?e=notlocal", http.StatusSeeOther)
		return
	}
	// verifyCodeThrottled checks a submitted code against the user's secret, with
	// per-user rate limiting so a stolen session can't brute-force the 6-digit
	// code offline-free. Returns (counter, ok). On ok it resets the limiter; on a
	// miss it records a failure. When throttled it returns ok=false and writes the
	// response, so the caller must just return.
	// verifyCodeThrottled returns (counter, cont). cont is false when the code was
	// wrong or the user is rate-limited — in that case it has already written the
	// response and the caller must just return.
	verifyCodeThrottled := func(purpose string) (int64, bool) {
		key := "totp:" + purpose + "|" + strconv.FormatInt(u.ID, 10)
		now := time.Now()
		if s.loginLimiter.blocked(key, now) {
			s.audit(r, u.Login, "totp."+purpose+".blocked", "too many attempts")
			http.Redirect(w, r, "/account?e=throttled", http.StatusSeeOther)
			return 0, false
		}
		counter, ok := auth.VerifyTOTPCounter(u.TOTPSecret, r.PostFormValue("code"), now, 1)
		if !ok {
			s.loginLimiter.fail(key, now)
			http.Redirect(w, r, "/account?e=badcode", http.StatusSeeOther)
			return 0, false
		}
		s.loginLimiter.reset(key)
		return counter, true
	}

	switch r.PostFormValue("action") {
	case "begin":
		// Refuse to re-enrol while 2FA is already ON: overwriting the secret here
		// would silently disable the existing factor with no proof of possession
		// (a session-only 2FA strip). The user must disable first, which requires
		// a current code.
		if u.TOTPEnabled {
			http.Redirect(w, r, "/account", http.StatusSeeOther)
			return
		}
		secret, err := auth.NewTOTPSecret()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// Store as pending (enabled=0); overwrites any previous unconfirmed secret.
		if err := s.store.SetUserTOTP(u.ID, secret, false); err != nil {
			log.Printf("egret-nest: begin totp: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		s.audit(r, u.Login, "totp.enroll.begin", "")

	case "confirm":
		if u.TOTPSecret == "" || u.TOTPEnabled {
			http.Redirect(w, r, "/account", http.StatusSeeOther)
			return
		}
		counter, cont := verifyCodeThrottled("confirm")
		if !cont {
			return
		}
		if err := s.store.SetUserTOTP(u.ID, u.TOTPSecret, true); err != nil {
			log.Printf("egret-nest: confirm totp: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// Burn the code used to enrol so it can't be replayed at login this period.
		if _, err := s.store.ClaimTOTPCode(u.ID, counter); err != nil {
			log.Printf("egret-nest: claim totp enrol code: %v", err)
		}
		s.audit(r, u.Login, "totp.enroll.confirm", "")
		http.Redirect(w, r, "/account?m=enabled", http.StatusSeeOther)
		return

	case "disable":
		if !u.TOTPEnabled {
			http.Redirect(w, r, "/account", http.StatusSeeOther)
			return
		}
		// Require a current code to disable — a stolen session alone must not be
		// able to strip the second factor.
		if _, cont := verifyCodeThrottled("disable"); !cont {
			return
		}
		if err := s.store.SetUserTOTP(u.ID, "", false); err != nil {
			log.Printf("egret-nest: disable totp: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		s.audit(r, u.Login, "totp.disable", "")
		http.Redirect(w, r, "/account?m=disabled", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}
