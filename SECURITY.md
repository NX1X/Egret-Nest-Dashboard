# Security Policy

Egret Nest is a self-hosted dashboard that stores other people's CI/CD
security telemetry and guards it behind a bearer token. A bug here can expose
that data, so we take reports seriously and disclose responsibly.

## Reporting a vulnerability

**Do not open a public issue for security bugs.**

Report privately via either:

- GitHub Security Advisories:
  <https://github.com/NX1X/Egret-Nest-Dashboard/security/advisories/new>
  (preferred), or
- Email: **support@nx1xlab.dev** with subject `SECURITY: Egret Nest`, or
- Contact form: <https://nx1xlab.dev/contact>.

For non-security bugs and questions, open a public issue at
<https://github.com/NX1X/Egret-Nest-Dashboard/issues>.

Please include:

- Affected version (release tag / image digest, or commit).
- How you're running it (binary / container / source) and relevant config
  (`EGRET_NEST_TOKEN` set or open, reverse proxy, TLS termination).
- A minimal reproduction — e.g. the request sequence, with tokens and any
  ingested data redacted.
- The impact you believe it has.

## High-value classes for this project

- **Auth bypass on `/ingest`** — posting a report without the configured
  bearer token, or a timing side-channel in token comparison.
- **Stored XSS** — an ingested report field rendered without escaping.
- **SQL injection / cross-instance data access** in the store.
- **Data exposure** — reports or tokens leaking via logs, error messages, or
  an unauthenticated endpoint.
- **Resource exhaustion** — an ingest payload that exhausts memory/disk past
  the documented limits.
- **Container escape / privilege** issues in the shipped image.

## Our commitment

- We acknowledge reports within **3 business days**.
- We aim to ship a fix or mitigation within **90 days**, faster for actively
  exploited issues.
- We credit reporters in the release notes unless you ask us not to.
- Fixes advise token rotation first if a secret is involved, ship a regression
  test, and go through a security review before release.

## Supported versions

Egret Nest is pre-1.0 and under active development. Only the latest tagged
release receives security fixes until 1.0.

## Scope

In scope: the `egret-nest` server, its ingest/auth/store/rendering code, the
`Dockerfile`, and the CI/release workflows in this repository. Out of scope:
third-party dependencies (report upstream; we track them via `govulncheck` +
Renovate), your reverse proxy / TLS setup, and self-hosted deployments you
modify.
