# OpenSSF Best Practices badge - answer sheet

Working notes for the [OpenSSF Best Practices](https://www.bestpractices.dev/)
**passing** badge self-certification for the **Egret Nest Dashboard**. Most
criteria auto-detect; this sheet covers the ones that want a written
justification, mapped to in-tree evidence. Paste into the form and set the
badge/project URLs once the entry exists.

## Basics

| Criterion | Answer / evidence |
|---|---|
| Project description | Self-hosted dashboard for Egret: ingests signed run reports, tracks egress allowlists, RBAC + TOTP + SSO. Single static Go binary, embedded SQLite. |
| Homepage / repo URL | https://github.com/NX1X/Egret-Nest-Dashboard |
| FLOSS license | See `LICENSE` (OSI-approved); stated in `README.md`. |
| Documentation | `README.md`, `docs/` (DEPLOY, AUTH, DEPENDENCIES, SECURITY-FOLLOWUPS), `CONTRIBUTING.md`. |
| Interact / bug report | GitHub Issues + Discussions; security via `SECURITY.md`. |

## Change control

| Criterion | Answer / evidence |
|---|---|
| Public version-controlled source | Git on GitHub. |
| Unique version numbering | SemVer tags. |
| Release notes | `CHANGELOG.md` (Keep a Changelog). |

## Reporting

| Criterion | Answer / evidence |
|---|---|
| Vulnerability report process | `SECURITY.md`. |
| Report responsiveness | Maintainer-monitored; acknowledged within a few days. |

## Quality

| Criterion | Answer / evidence |
|---|---|
| Working build system | `make build` (static, CGO off). |
| Automated test suite | `go test ./...` (store against a real SQLite file, server, model, auth); CI on every push/PR (`.github/workflows/ci.yml`). |
| Tests added with new features | Required by `CONTRIBUTING.md`. |
| Warning flags | `go vet` + `gofmt -l` gate in CI. |

## Security

| Criterion | Answer / evidence |
|---|---|
| Secure development knowledge | Auth/threat design in `docs/AUTH.md`; review gates in `CONTRIBUTING.md`. |
| Good cryptography | No home-rolled crypto: `golang.org/x/crypto` AEAD secretbox for TOTP-seed at-rest encryption (`internal/auth/secretbox.go`); Argon2id password hashing; HMAC-SHA256 webhook verification; constant-time compares. |
| No hardcoded credentials | Secrets are env-only (`EGRET_NEST_*`); none in-tree. |
| TLS | Native HTTPS (`EGRET_NEST_TLS_*`, TLS 1.2+) or behind a TLS-terminating proxy; `Secure`/`__Host-` cookies when secure. |
| Delivery against MITM | Container image published to GHCR with SLSA build provenance; digest-pinned base images. |

## Analysis

| Criterion | Answer / evidence |
|---|---|
| Static analysis | CodeQL (security-extended), zizmor, OpenSSF Scorecard, Trivy image scan - `.github/workflows/security.yml`. |
| Dynamic analysis | `govulncheck` in CI; **Go native fuzzing** on the secret decryptor and webhook signature verifier (`internal/auth/fuzz_test.go`, `internal/server/fuzz_test.go`). |
| Fix analysis-found issues | Code Scanning alerts triaged; unreachable/no-fix advisories documented. |

## Still to do for a higher tier (silver/gold)

- Two-person review on all changes (needs a second maintainer - see `CONTRIBUTING.md`).
- Signed commits required (currently preferred).
