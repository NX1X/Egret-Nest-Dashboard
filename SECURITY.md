# Security Policy

Egret Nest is a self-hosted dashboard that stores other people's CI/CD security
telemetry and guards it behind a bearer token. A bug here can expose that data,
so every report genuinely matters - and we want reporting one to be easy and
safe.

**You will never get in trouble for reporting a vulnerability to us in good
faith.** See [Safe harbor](#safe-harbor) below.

## TL;DR

- Found something? Report it **privately** - please don't open a public issue.
- Fastest channel: **[open a private security advisory](https://github.com/NX1X/Egret-Nest-Dashboard/security/advisories/new)**.
- We reply within **3 business days**, keep you updated, fix it, and credit you
  (unless you'd rather stay anonymous).

## How to report

Pick whichever is easiest - all three are private:

| Channel | Where |
|---|---|
| GitHub private advisory *(preferred)* | <https://github.com/NX1X/Egret-Nest-Dashboard/security/advisories/new> |
| Email | **support@nx1xlab.dev**, subject `SECURITY: Egret Nest` |
| Contact form | <https://nx1xlab.dev/contact> |

Anonymous reports are welcome. If your report is sensitive and you'd like to
encrypt it, our PGP key is published at
<https://egret.nx1xlab.dev/.well-known/pgp-key.txt> (you can also just ask for
it in a first short email).

For non-security bugs and questions, please use a public issue instead:
<https://github.com/NX1X/Egret-Nest-Dashboard/issues>.

## Safe harbor

We consider security research and vulnerability disclosure carried out in good
faith to be **authorized conduct**, and we will not pursue or support legal
action against you for it. If you make a genuine effort to follow this policy,
we will treat you as an ally, not an adversary - and we'll work with you if
someone else raises a concern about your research.

In return, we ask that you:

- Make a good-faith effort to avoid privacy violations, data loss, and service
  disruption.
- Only test against your **own** instance - never another user's data or a
  third party's deployment.
- Don't access, modify, or exfiltrate more data than needed to demonstrate the
  issue.
- Give us a reasonable chance to ship a fix before disclosing publicly.

If you're unsure whether something is in bounds, just ask first at
**support@nx1xlab.dev** - we'd much rather answer a question than have you hold
back a report.

## What to include

The more of this you can share, the faster we can confirm and fix - but a clear
description is enough to get started, even without a polished write-up:

- Affected version (release tag / image digest, or commit).
- How you're running it (binary / container / source) and relevant config
  (`EGRET_NEST_TOKEN` set or open, reverse proxy, TLS termination).
- A minimal reproduction - e.g. the request sequence, with tokens and any
  ingested data redacted.
- The impact you believe it has.
- Any proof-of-concept, logs, or screenshots (redact your own secrets).

## What to expect

| Stage | Our target |
|---|---|
| Acknowledgement that we received it | within **3 business days** |
| Triage + our severity assessment | within **7 days** |
| Fix or documented mitigation | within **90 days** (sooner for critical / actively exploited) |
| Public disclosure | coordinated with you, after a fix or mitigation ships |

We'll keep you in the loop at each step, share how we're rating severity, and
tell you when a fix lands. In the rare case we need longer than 90 days, we'll
explain why and agree a timeline with you.

## Coordinated disclosure & credit

- We disclose through **GitHub Security Advisories** and request a **CVE** where
  it's warranted.
- We coordinate disclosure timing with you and honor a reasonable embargo.
- We **credit you by name or handle** in the advisory and release notes, unless
  you ask to remain anonymous.
- There is no paid bug-bounty program - Egret is independent open source - but
  we take acknowledgement seriously: your name goes on the fix.

## What we're especially interested in

High-value classes for this project specifically:

- **Auth bypass on `/ingest`** - posting a report without the configured bearer
  token, or a timing side-channel in token comparison.
- **Stored XSS** - an ingested report field rendered without escaping.
- **SQL injection / cross-instance or cross-tenant data access** in the store.
- **Session / CSRF / auth flaws** in the login, SSO (GitHub / OIDC), or admin
  and org-RBAC surfaces.
- **Data exposure** - reports or tokens leaking via logs, error messages, or an
  unauthenticated endpoint.
- **Resource exhaustion** - an ingest payload that exhausts memory / disk past
  the documented limits.
- **Container escape / privilege** issues in the shipped image.

## Supported versions

Egret Nest is pre-1.0 and under active development. Only the latest tagged
release receives security fixes until 1.0. If you're on an older tag, please try
to reproduce on the latest release where you can - but report it either way.

## Scope

**In scope:** the `egret-nest` server, its ingest / auth / store / rendering
code, the `Dockerfile`, and the CI / release workflows in this repository.

**Out of scope:** third-party dependencies (please report those upstream; we
track them via `govulncheck` + Renovate), your reverse proxy / TLS setup, and
self-hosted deployments you've modified. If a dependency issue affects Egret
Nest, tell us anyway - we'll help coordinate.

## Thank you

Researchers who take the time to report issues make Egret Nest safer for
everyone who trusts it with their data. We're grateful, and we'll treat your
report - and you - with respect.
