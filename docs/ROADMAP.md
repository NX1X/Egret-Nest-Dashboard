# Egret Nest Dashboard - Roadmap

The optional, self-hosted Tier-3 dashboard for [Egret](https://github.com/NX1X/Egret).
This roadmap covers this repo only; the master product roadmap and the
"server-is-never-required" invariant live in
[Egret/docs/ROADMAP.md](https://github.com/NX1X/Egret/blob/main/docs/ROADMAP.md).

Design references: [AUTH.md](AUTH.md) (security architecture),
[ingest-contract](https://github.com/NX1X/Egret/blob/main/docs/ingest-contract.md).

> **Security posture:** this app stores a company's egress / supply-chain graph -
> its most sensitive telemetry. Every milestone is gated by the specialist review
> agents below, and nothing is exposed beyond localhost until the pre-prod gate
> passes.

---

## Components

- **C-store** - SQLite persistence (runs, endpoints_seen drift, + auth/org tables).
- **C-server** - stdlib `net/http` API + ingest + middleware (sessions, CSRF, headers).
- **C-auth** - pluggable auth core + providers (GitHub OAuth / OIDC / local+TOTP).
- **C-ui** - server-rendered `html/template` (no JS; CSP `script-src 'none'`, inline
  SVG sparklines). htmx remains an optional future nicety, not yet vendored.
- **C-ops** - packaging (Docker/compose/Helm), backup/restore, metrics, deploy docs.

---

## Milestones

1. **N0 - MVP** ✅ - ingest API (`POST /ingest`, schema-checked), SQLite store
   (runs + endpoints drift), run list/detail UI, healthz, Docker, CI.
2. **N1 - Security core + local auth** ✅ - identity schema (users/orgs/
   memberships/roles, sessions, ingest_tokens, audit_log); session + CSRF +
   security-headers + panic-recovery + rate-limiting middleware; **local
   provider** (argon2id + TOTP 2FA + replay guard + bootstrap admin); authz guard
   (no IDOR, cross-tenant scoped); scoped/revocable ingest tokens. *(security-reviewed)*
3. **N2 - GitHub OAuth provider** ✅ - "Login with GitHub" via the Egret App;
   id-based account linking; org-membership-gated provisioning, re-checked every
   login. *(hardened: no Host-header trust, no pagination gap.)*
4. **N3 - OIDC provider** ✅ (hardened) - generic BYO-IdP (Okta/Entra/Google) via `coreos/go-oidc`.
5. **N4 - Dashboard depth** ✅ - new-endpoint drift view, per-repo & org **fleet**
   views, **inline-SVG drift sparklines**, and an **HMAC-verified webhook receiver**
   (`POST /webhook/github`). *(security-reviewed)* htmx and webhook artifact-pull
   remain optional niceties.
6. **N5 - Hardening & ops** ✅ (security-reviewed) - audit-log UI (admin-only),
   retention/pruning janitor, `__Host-` cookies, TOTP-at-rest encryption
   (AES-256-GCM), CSP tightened to `style-src 'self'` (inline CSS moved to an
   embedded `/static/app.css`; no inline styles/JS), token-gated `/metrics`,
   `egret-nest backup` (SQLite `VACUUM INTO`). *(security-reviewed)*
7. **N6 - Packaging & deploy** ✅ - Docker + hardened
   `docker-compose` (+ optional **nginx** TLS profile) + a **Helm chart**
   (single-replica/Recreate, non-root, read-only, NetworkPolicy, PVC) +
   [DEPLOY.md](DEPLOY.md). Supply-chain follow-ups (image scan/sign, digest pins)
   tracked internally.
8. **N8 - Admin console** ✅ (security-reviewed) - GUI for what used to be env-only:
   **Settings** (instance name, retention, generate/rotate the `/metrics` token),
   **Connect a repo** (orgs + scoped ingest tokens + CI snippet, revoke), and a
   **Logs** page (live in-memory request access log). Instance name + retention
   now GUI-managed. *(security-reviewed; fixes applied.)*
9. **N7 - v1.0 security ship-check** ✅ (security-reviewed: pentest GO)
   - both prior CRITICAL blockers (cross-tenant SSO, unauthenticated setup takeover)
   fixed and re-attacked with no residual path. See the DoD below.

### Shipped in v0.1.0 (post-N8 hardening + UX)

The **`v0.1.0`** release - security-reviewed across auth, RBAC, 2FA, SSO config, and
CI. Full detail in [CHANGELOG.md](../CHANGELOG.md) `[0.1.0]`:

- **RBAC - org-scoped delegation** ✅ - org owner/admin self-manage their org's
  tokens + members at `/org/{id}/*`; per-org roles enforced (no-escalation,
  last-owner, cross-org guards, all atomic in the store).
- **Self-service TOTP 2FA UI** ✅ - `/account` enrol/disable (disable + re-enrol
  require a current code; rate-limited).
- **SSO login config in the UI** ✅ - `/admin/auth` configures GitHub/OIDC without a
  redeploy; client secrets encrypted at rest; env takes precedence; issuer SSRF-guarded.
- **Native TLS** ✅ - `EGRET_NEST_TLS_CERT/_KEY` serve HTTPS directly (or terminate at a proxy).
- **Visual identity pass + consistent nav + auth-status panel** ✅ - teal/navy brand,
  light+dark, Organizations as tiles, one shared top-nav.
- **Supply-chain + CI hardening + release workflow** ✅ - Trivy image scan,
  digest-pinned base images, pinned CI actions, tag-triggered release (binary + GHCR
  image + SLSA provenance).

**Branding & identity (cross-repo `branding/`)** - shared identity duplicated verbatim
in both repos (only the GitHub social preview differs per-repo). Vector identity +
**favicon (wired) + 512² marketplace app-icon + `export.sh` raster pipeline** ✅; a
polished/animated logo pass + uploading each repo's social-preview PNG remain ⬜.
Mirrors [Egret C9](https://github.com/NX1X/Egret/blob/main/docs/ROADMAP.md).

### Shipped since v0.1.0

- **v0.1.1** - egret-in-flight brand refresh; **Docker Hub distribution**
  (`nx1x/egret-nest`, floating tags, README-synced overview) alongside GHCR; Go fuzzing
  over the parsers; wider safe-harbor security policy; Go 1.26.5. See
  [CHANGELOG.md](../CHANGELOG.md).

**Remaining before the product hits v1.0:** the dashboard's own DoD is met (below);
**v1.0 is the combined product gate** - the agent's block-mode enforcer re-gate is the
last gating item (see the [agent roadmap](https://github.com/NX1X/Egret/blob/main/docs/ROADMAP.md)).
The `v0.1.0` and `v0.1.1` releases are published (GitHub Releases + **GHCR and Docker
Hub** images with SLSA provenance); the OIDC DNS-rebinding item is closed (issuer
SSRF-guard at dial time).

---

## Review gates - what gets reviewed before merge

Security-sensitive changes go through a required specialist review - this is the
app holding the crown-jewel data.

| Change area | Review focus |
|---|---|
| Auth, sessions, request handlers, `/ingest`, outbound HTTP, templates | OWASP: authn, IDOR, XSS, CSRF, SSRF, crypto |
| `internal/store/**`, SQL, migrations, cross-tenant queries | injection, IDOR, cross-tenant isolation |
| Logging, audit log, token/secret handling, PII, exports | data-handling / secrets |
| `Dockerfile`, TLS, deploy/compose/Helm, runtime hardening | infrastructure hardening |
| `.github/workflows/**` | CI/CD supply-chain security |
| `go.mod` / `go.sum` / any new dependency | dependency + supply-chain review |
| Any Go change | code review (idioms, error handling, resource cleanup) |
| Before any shared deployment | a consolidated security review + pentest |

---

## v1.0 - Definition of Done

The **dashboard's** part of the product v1.0 gate. All met as of `v0.1.0`; `v1.0.0`
is the *combined* release (see "Remaining before the product hits v1.0" above - the
agent enforcer re-gate is the outstanding item).

- [x] At least one auth provider fully working end-to-end (local + TOTP), with
      sessions, CSRF, and the authz guard enforced on every route. *(all three:
      local+TOTP / GitHub / OIDC)*
- [x] Multi-tenant: orgs + roles; a user cannot see another repo/org's runs
      (verified - **no IDOR**; org-scoped queries + security review GO).
- [x] Scoped ingest tokens; single shared token removed; webhooks HMAC-verified.
- [x] Security headers + TLS/HSTS documented (native TLS + proxy); audit log records
      auth/token/role/membership events.
- [x] Full security review (appsec + database + infra + pentest) sign-off; all
      high/critical findings fixed.
- [x] CI green: `gofmt`, `go vet`, tests (incl. auth), `go mod verify`, `govulncheck`
      - runs in CI; the tag-triggered release workflow builds + publishes the binary + image.
- [x] Deploy story: `docker compose up` + a Helm chart; backup/restore documented.
- [x] Docs: [AUTH.md](AUTH.md), [deploy guide](DEPLOY.md), config reference; LICENSE + NOTICE.

`v0.1.0` was tagged 2026-07-08 at N7-complete (pre-1.0 per SemVer); `v1.0.0` when the
combined product gate (incl. the agent enforcer) is met.

---

## Explicitly out of scope (keeps the invariant honest)

- Never required by the agent; the agent works fully standalone.
- No multi-customer SaaS control plane here - each company self-hosts one instance
  (which may serve multiple GitHub orgs it's installed on).
- No telemetry phoned home; data stays on the deployer's infrastructure.


