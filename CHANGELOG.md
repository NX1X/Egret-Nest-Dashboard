# Changelog

Notable changes to Egret Nest Dashboard, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **One anonymous request could crash the dashboard.** `POST /ingest` decoded the
  whole body before it checked the token. 8 MiB of empty JSON objects decodes into
  millions of structs (measured at about 770 MiB of heap), so one unauthenticated
  request exceeded the 256 MiB container limit and the process was killed. The
  token is now checked from the headers before the body is read.
- **A token holder can no longer exhaust memory through ingest either.** A
  streaming pre-check now rejects an envelope with more than 100,000 array
  elements, or nested deeper than 32 levels, before any structs are built. 8 MiB of
  real Egret entries is under about 60,000 elements, so real runs are not affected.
  A body over 8 MiB now returns `413` instead of a misleading `400`.
- **Parallel logins could crash the dashboard.** Each argon2id hash allocates
  64 MiB, and a login runs one even for an unknown user. About 4 parallel anonymous
  login attempts exceeded the 256 MiB limit. At most 2 hashes now run at once.
  Other callers wait up to 3 seconds, then get `503` with `Retry-After`. Known and
  unknown logins get the same busy answer, so it does not reveal which accounts
  exist, and a busy answer does not count as a failed attempt.
- **Go 1.26.9 (GO-2026-6617).** Fixes an HTTP/2 server crash caused by a race in
  the `net/http` HPACK encoder. `govulncheck` reported it as reachable. Every Go
  standard library CVE that Trivy reported in the image lists a fix at or below
  1.26.9.
- **`golang.org/x/crypto` v0.56.0**, the fixed version for the three `x/crypto`
  findings in the image. The `distroless/static-debian12` base moves to its current
  digest, to pick up the `tzdata` update that Trivy reported.

### Fixed

- **OpenSSF Scorecard runs again.** `ossf/scorecard-action` v2.4.0 pulls its image
  from `gcr.io`, and that pull is now refused. v2.5.0 pulls from `ghcr.io`.

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
- **CI/CD hardening:** `concurrency` cancellation on PR workflows.
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
