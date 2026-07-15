# Dependency Policy — Egret Nest Dashboard

This mirrors the [Egret dependency policy](https://github.com/NX1X/Egret/blob/main/docs/DEPENDENCIES.md).
Egret is a supply-chain security tool; the dashboard's own dependencies are
attack surface and are vetted before adoption.

## Vetting checklist (all must hold)

- [ ] Maintained (activity < ~12 months; not archived)
- [ ] Reputable / meaningful adoption
- [ ] No known unpatched CVEs (`govulncheck`)
- [ ] Permissive license (MIT / BSD / Apache-2.0 / ISC). *Accepted exception:*
      `github.com/hashicorp/golang-lru/v2` (MPL-2.0) is pulled in **test-only**,
      transitively via `modernc.org/libc`; MPL-2.0 is weak, file-level copyleft and
      this is not linked into the shipped binary.
- [ ] Small transitive footprint
- [ ] **Pure-Go / no CGO** (the dashboard must build as a single static binary)
- [ ] Pinned + checksummed (`go.mod`/`go.sum`, `go mod verify` clean)

## Process

- Prefer the **standard library**: `net/http` (Go 1.22 routing), `html/template`
  (auto-escaping), `database/sql`, `go:embed`, `crypto/subtle`, `encoding/json`.
- **No npm / Node build chain.** If interactivity is needed, vendor a single
  pinned, SRI-hashed `htmx.min.js` — never a package manager.
- CI runs `govulncheck`, `go mod verify`, `gofmt -l`, `go vet`.

## Allowed

| Module | Purpose | Why it passes |
|---|---|---|
| **stdlib** | server, routing, templating, storage glue, auth | first-party; zero risk; used for everything possible |
| `modernc.org/sqlite` | embedded storage | **pure-Go** SQLite (no CGO); production-proven; enables the static single binary |
| `golang.org/x/crypto` | argon2id password hashing | Go team; permissive |
| `github.com/coreos/go-oidc/v3` | OIDC discovery + ID-token verification (N3) | de-facto Go OIDC library; CNCF/CoreOS lineage; maintained |
| `golang.org/x/oauth2` | OAuth2 code flow (GitHub + OIDC) | Go team; permissive |
| `github.com/go-jose/go-jose/v4` | JOSE/JWS (indirect, via go-oidc) | maintained successor to square/go-jose |

Optional, only when justified (not yet used):

| Module | Purpose | Note |
|---|---|---|
| vendored `htmx.min.js` | UI interactivity | single pinned + SRI asset, no build step |

## Blacklisted / avoid

| Package / class | Reason | Use instead |
|---|---|---|
| `github.com/mattn/go-sqlite3` | **CGO** — breaks the static single-binary goal | `modernc.org/sqlite` |
| `github.com/dgrijalva/jwt-go` | abandoned; CVE-2020-26160 | `github.com/golang-jwt/jwt/v5` |
| npm/Node build chains for the UI | large opaque supply-chain surface | vendored, pinned, SRI assets |
| Heavy web frameworks | unnecessary; stdlib suffices | `net/http` |
| Archived / stale / unpatched-CVE packages | risk | maintained equivalent or stdlib |

_Last reviewed: 2026-07-03._
