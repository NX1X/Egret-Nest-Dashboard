# Changelog

Notable changes to Egret Nest Dashboard, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - Security hardening (pentest remediation)

### Changed (upgrade impact)

- **The server refuses to start without `EGRET_NEST_SECRET_KEY`** when TOTP data
  would otherwise be stored unencrypted. Set the key, or explicitly opt into the
  old behavior with `EGRET_NEST_ALLOW_PLAINTEXT_TOTP=1`. This was previously a
  warning that silently continued with plaintext TOTP seeds at rest.
- **SSO login is refused until first-run setup is complete.** A brand-new SSO
  account can no longer be auto-provisioned before the instance is bootstrapped,
  closing a race where an early SSO login could permanently lock the operator out
  of the admin console.
- **The Helm chart now defaults `networkPolicy.enabled: true`** (default-deny
  egress). It degrades gracefully on a CNI that doesn't enforce NetworkPolicy.
- **Default deployment examples pin a released image tag** instead of `latest`
  (compose, `.env.example`, docs); floating tags are noted as convenience-only.

### Security

- **First-run bootstrap is race-safe.** The `bootstrapped` state is claimed
  atomically alongside admin creation, and SSO provisioning + the `/setup` gate
  both key off it, so exactly one admin is ever created (verified under
  concurrent load).
- **Login no longer leaks account existence via timing.** The unknown-user /
  SSO-only path now runs a dummy argon2id verification so it costs the same as a
  real wrong-password attempt.
- **Container images are vulnerability-scanned before publish.** The release
  workflow runs Trivy (fail on HIGH/CRITICAL) between build and push.
- **CI/CD hardening:** `step-security/harden-runner` (audit) on the
  credential-holding jobs, and `concurrency` cancellation on PR workflows.
- **The one-time setup token is accessed atomically** (`atomic.Pointer`), fixing
  a data race under concurrent `/setup` requests.

### Changed

- **Ingress TLS enforcement is configurable** (`ingress.sslRedirect`), and the
  docs recommend `existingSecret` (SOPS / External Secrets / Vault) as the
  primary way to supply secrets rather than plaintext `values.yaml`.

## [0.1.1] - Brand, distribution, and hardening

### Added

- **Docker Hub distribution.** The container image is mirrored to `nx1x/egret-nest`
  alongside GHCR, with floating `latest` / `v0` / `v0.1` tags, and the Docker Hub repo
  overview is kept in sync with the README.
- **Go fuzzing** over the untrusted-input parsing paths, plus contributor onboarding docs.

### Changed

- **New visual identity** - an egret-in-flight mark across the icon, app-icon, logo
  (a self-contained dark-card lockup), favicon, and social preview; the README now
  leads with the logo.
- **Wider security policy** in SECURITY.md - explicit safe harbor for good-faith
  research, response-time targets, coordinated disclosure, and reporter credit (plain
  email, no PGP required).

### Security

- Go toolchain 1.26.5 and refreshed digest-pinned Actions and base images (clears the
  stdlib advisories).

## [0.1.0] - first release

The optional self-hosted dashboard for Egret: ingest CI/CD runs and view egress
over time, endpoint drift, and violations across your fleet, with multi-tenant
access control. Ships as a single Go binary with embedded SQLite - no external
services required.

### Added

- **Run ingest + history.** The Egret agent/Action POSTs each run; stored in
  embedded SQLite. Run list/detail, per-repo egress-over-time, org **fleet** view,
  and **new-endpoint drift** (inline-SVG sparklines, no JavaScript).
- **Authentication - one core, three providers.** Local accounts (argon2id) with
  self-service **TOTP 2FA**, **GitHub OAuth**, and generic **OIDC** (Okta / Entra /
  Google), configurable via env or an admin UI (client secrets encrypted at rest,
  env always wins).
- **Authorization (multi-tenant RBAC).** Organizations → repositories → runs, with
  **fail-closed** org membership (SSO authenticates identity; an admin grants
  access), per-org roles (owner/admin/member/viewer), and scoped, revocable ingest
  tokens.
- **Admin console.** Settings, connect-a-repo, user management, audit log, live
  access log, and retention controls.
- **Deploy.** Dockerfile, hardened `docker-compose` (+ optional nginx TLS), a Helm
  chart, `healthcheck` + `backup` commands, and a deployment guide.

### Security

- **Hardened for crown-jewel data:** native TLS (or behind a proxy), `__Host-`
  cookies, CSRF on every mutation, a strict CSP (`script-src 'none'`), argon2id
  password hashing, AES-256-GCM secrets at rest, HMAC-verified webhooks, token-gated
  metrics, and an audit trail.
- **SSRF-guarded OIDC:** every OIDC fetch for a UI-configured issuer refuses internal
  addresses at dial time (closes DNS-rebinding and attacker-declared-endpoint holes).
- **Supply chain:** digest-pinned base images, SHA-pinned Actions, container CVE
  scanning (Trivy), `govulncheck`, and CodeQL.

[0.1.1]: https://github.com/NX1X/Egret-Nest-Dashboard/releases/tag/v0.1.1
[0.1.0]: https://github.com/NX1X/Egret-Nest-Dashboard/releases/tag/v0.1.0
