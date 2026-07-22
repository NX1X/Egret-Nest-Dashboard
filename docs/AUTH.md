# Egret Nest Dashboard - Authentication, Authorization & Security Design

> **Why this matters:** the dashboard stores a company's **egress / supply-chain
> graph** - what every CI job connected to, which processes ran, which files were
> touched. That is among the most sensitive telemetry an org has. The dashboard is
> therefore designed and reviewed as a crown-jewel application: least privilege,
> defense in depth, and a security + pentest gate before any shared deployment.

This document is the source of truth for the dashboard's auth and security design.

---

## 1. Authentication - one core, three pluggable providers

We do **not** build three auth systems. We build one provider-agnostic core and
three swappable providers. A deployer enables any combination via config -
**environment variables** (authoritative) or the admin **Authentication** page
(`/admin/auth`), which stores GitHub/OIDC client secrets **encrypted at rest**
(`EGRET_NEST_SECRET_KEY`) and hot-reloads the provider; env always takes precedence.

```
              ┌──────────────────────────────────────────┐
  browser ──▶ │  session middleware (cookie ⇄ Session)   │
              └───────────────┬──────────────────────────┘
                              │ establishes identity via one of:
        ┌─────────────────────┼──────────────────────────┐
        ▼                     ▼                          ▼
  GitHub OAuth           Generic OIDC                Local accounts
  (Egret App)         (Okta/Entra/Google)      (argon2id + TOTP 2FA)
        └─────────────────────┴──────────────────────────┘
                              ▼
                    Users · Orgs · Memberships · Roles (shared core)
```

### Provider interface (conceptual)

```go
type Provider interface {
    ID() string                              // "github" | "oidc" | "local"
    // Begin returns a redirect URL (OAuth/OIDC) or renders a form (local).
    Begin(w, r) error
    // Complete verifies the callback/credentials and returns the external identity.
    Complete(w, r) (ExternalIdentity, error)
}

type ExternalIdentity struct {
    Provider   string
    Subject    string   // stable provider user id
    Login      string   // display handle / email
    Email      string
    // For GitHub: the orgs/repos this identity can access (for authz sync).
    GitHubOrgs []string
}
```

The core maps an `ExternalIdentity` to a local `User`, creates a `Session`, and
sets the cookie. Providers never touch sessions directly.

### 1a. GitHub OAuth (recommended default)
- OAuth via the **Egret App** (same App used for the CI-side token - one
  integration, two jobs). Needs the App's OAuth client id/secret in config.
- **Inherits GitHub's 2FA, org-enforced MFA, and SAML SSO** - we build no MFA.
- The access token is used **once at login** to verify the user is a current
  member of the configured allowed org (revoked members lose access on their next
  login), then discarded (not stored long-term). Passing this check provisions a
  local account with **no org membership** - see §2; it does not sync repo access.

### 1b. Generic OIDC
- Standard Authorization Code + PKCE against any OIDC IdP (Okta, Entra, Google
  Workspace, Keycloak…). MFA is enforced by the IdP.
- Config: issuer URL, client id/secret, scopes. Uses `coreos/go-oidc` for
  discovery + ID-token verification (vetted dependency).

### 1c. Local accounts (air-gapped)
- Username + password hashed with **argon2id** (`golang.org/x/crypto/argon2`;
  per-user random salt; tuned params). Never bcrypt-with-defaults, never sha.
- **TOTP 2FA** (RFC 6238) - enrollable + enforceable per-org. WebAuthn/passkeys
  are a later addition.
- Includes the **first-run bootstrap admin** (printed one-time setup token) so a
  fresh install is reachable before any IdP is configured.
- Protections: login rate-limiting + lockout, constant-time compares, generic
  "invalid credentials" errors (no user enumeration), password-strength check.

---

## 2. Identity & authorization model

```
Organization 1──* Membership *──1 User
Organization 1──* Repository 1──* Run
```

- **Two privilege axes.** (1) An instance-wide **`is_admin`** flag - set **only**
  on the first-run bootstrap admin (no handler ever mutates it, so there is no
  in-app escalation to it). Instance admins reach the instance console
  (`/admin/*`: users, settings, logs, audit) and act with owner-level authority
  in every org. (2) A per-org **membership role** (`owner` > `admin` > `member` >
  `viewer`), enforced by `Role.AtLeast`.
- **Org-scoped management (enforced).** An org **owner/admin** self-manages *their
  own* org at `/org/{id}/tokens` and `/org/{id}/members` - creating/revoking that
  org's ingest tokens and granting/revoking that org's memberships - **without**
  the instance `is_admin` flag. `member`/`viewer` have no management power (view
  only). The delegation is deliberately conservative and covered by tests:
  - a manager may never assign a role **above their own** effective role, nor act
    on a member who **outranks** them (an `admin` cannot touch an `owner`);
  - the **last owner** of an org can never be removed or downgraded;
  - a manager only ever sees/acts within the org in the path - token revoke
    verifies the token belongs to that org (no cross-org id-guessing), and the
    member list is scoped to that single org (no instance-wide user enumeration);
  - the `/org/{id}/*` routes 404 (existence hidden) for non-managers, like the
    instance admin routes.
  The last-owner and cross-org guards are enforced **atomically in the store**
  (`SetMembershipRole` / `RemoveMembershipGuarded` / `RevokeIngestTokenInOrg`),
  not in per-handler branches, so no code path or concurrent request can bypass
  or race them. *Accepted tradeoff:* "add member by login" reveals whether a login
  exists instance-wide (an existence oracle) - judged low risk because the caller
  is already an authenticated org owner/admin, and org-admin is itself granted by
  an instance admin.
- **Access is org membership, granted explicitly (fail-closed).** A user sees a
  run **iff they hold a membership in the org that owns the run's repo.** SSO
  (GitHub/OIDC) authenticates *who you are* - it does **not** auto-grant access to
  any tenant. A freshly-provisioned SSO user lands with **zero memberships** and
  can see nothing until an **instance admin** grants them an org on
  `/admin/users`. This is deliberate: passing the GitHub-org login gate is
  authentication, not authorization to every connected repo's egress telemetry.
  > **Not (yet) implemented:** automatic mirroring of GitHub *repo-level* access
  > onto dashboard visibility. That was specified but shipping it silently would
  > have made any org member a reader of every connected repo, so provisioning is
  > fail-closed instead. Per-repo GitHub-access mirroring is future work; until
  > then, tenant access is an explicit admin grant.
- **Enforcement:** every handler runs through an authz guard keyed on
  (user, org, action); queries are org-scoped. Default deny. No object is returned
  without an explicit access check - **no IDOR**: `/runs/{id}` verifies the run's
  repo belongs to an org the caller is a member of.

---

## 3. Sessions & CSRF

- Server-side sessions (row in SQLite), opaque random 256-bit id.
- Cookie: `HttpOnly`, `Secure`, `SameSite=Lax`, `__Host-` prefix, no domain.
- Idle timeout (e.g. 12h) + absolute lifetime (e.g. 7d); rotate id on login.
- **CSRF:** double-submit token on every state-changing request (POST/PUT/DELETE);
  `SameSite=Lax` is defense-in-depth, not the only control.
- Logout revokes the server session; "log out everywhere" clears all sessions.

---

## 4. Ingest & webhook authentication

- Today's single `EGRET_NEST_TOKEN` becomes **per-org / per-repo scoped ingest
  tokens** - created in the UI, hashed at rest, revocable, last-used tracked.
  A leaked token exposes one repo's ingest, not the whole instance.
- GitHub **webhooks** (if enabled) are verified by HMAC-SHA256 over the raw body
  using the webhook secret; unverified deliveries are rejected.
- Ingest is authn-only (no session) and rate-limited per token.

---

## 5. Hardening (defense in depth)

- **TLS-first:** native TLS (`EGRET_NEST_TLS_CERT`/`_TLS_KEY`, TLS 1.2+) **or** a
  TLS-terminating proxy (`EGRET_NEST_BEHIND_PROXY=1`); set **HSTS**. Refuse to set
  `Secure` cookies over plain HTTP except on localhost. `r.TLS`/trusted
  `X-Forwarded-Proto` drives the `Secure`/`__Host-` cookie attributes.
- **Security headers** on every response: `Content-Security-Policy`
  `default-src 'none'; style-src 'self'; script-src 'none'; img-src 'self' data:`
  (server-rendered `html/template`, no JS at all - no inline scripts, no nonce, htmx
  not yet used), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `Permissions-Policy`.
- **Audit log:** append-only record of security-relevant events (login, token
  create/revoke, role change, settings change, data export) with actor + time.
- Request size limits (already on ingest), timeouts, and panic-recovery middleware.
- **Secrets at rest:** provider client-secrets and webhook secrets read from env
  or files, never logged; token/password material stored **hashed only**.
- **No PII** beyond GitHub/OIDC logins and emails; retention/pruning configurable.
- **Supply chain:** pure-Go, pinned + `go mod verify` + `govulncheck` (see
  [DEPENDENCIES.md](DEPENDENCIES.md)).

---

## 6. New dependencies (all to be vetted per DEPENDENCIES.md)

| Dependency | For | Notes |
|---|---|---|
| `golang.org/x/crypto` | argon2id password hashing | Go team; permissive |
| `coreos/go-oidc` (+ `golang.org/x/oauth2`) | OIDC / OAuth flows | de-facto OIDC lib; add only with provider 1a/1b |
| TOTP | local 2FA | prefer a small stdlib RFC-6238 impl (crypto/hmac); else vet `pquerna/otp` |
| `go-webauthn/webauthn` | passkeys (later) | deferred |

Everything else stays stdlib (`crypto/*`, `net/http`, `database/sql`, `html/template`).

---

## 7. Build sequence

1. **Security core (no external IdP needed - buildable/testable now):** identity
   schema (users/orgs/memberships/roles/sessions/tokens/audit), session + CSRF +
   security-headers middleware, authz guard, **local provider** (argon2id + TOTP)
   + bootstrap admin, scoped ingest tokens.
2. **GitHub OAuth provider** - drops in once the Egret App exists (needs OAuth
   creds); adds repo-access authz sync.
3. **OIDC provider** - for BYO-IdP enterprises.
4. **Gate:** a full security review before
   any shared/production deployment; fix findings; only then document a public
   deploy.

Steps 1 is fully testable on any machine (no kernel, no App). Steps 2-3 add
providers behind the same interface without touching the core.
