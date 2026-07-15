# Contributing to Egret Nest Dashboard

Thanks for helping build Egret Nest — the self-hosted dashboard for Egret. A
few things are stricter than a typical repo, mostly around the ingest boundary,
the data store, and the deliberately small dependency surface.

## Ground rules

- Read the auth & security design in [docs/AUTH.md](docs/AUTH.md) first.
- Keep PRs small and focused. One concern per PR.
- Every user-facing change updates [CHANGELOG.md](CHANGELOG.md).
- Be excellent to each other — see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Design constraints (please respect them)

- **Stdlib-only web stack.** `net/http` (Go 1.22 routing), `html/template`. No
  web framework, no router library, no ORM.
- **Pure-Go, no CGO.** SQLite via `modernc.org/sqlite` so the build stays a
  single static binary.
- **Env-only config.** `EGRET_NEST_ADDR`, `EGRET_NEST_DB`, `EGRET_NEST_TOKEN`,
  `EGRET_NEST_INSTANCE`. No config files, no flags for secrets.

Adding a dependency is a real decision — justify it in
[docs/DEPENDENCIES.md](docs/DEPENDENCIES.md) (permissive-licensed only, minimal
surface, pinned + verified).

## Development setup

Go 1.25, no CGO required.

```bash
make fmt vet     # hygiene
make test        # unit tests (store, server, model)
make build       # static binary
go mod verify    # checksums

# Run it locally:
EGRET_NEST_TOKEN=dev-token ./bin/egret-nest   # listens on :8080
```

## Branching & commits

- Never commit directly to `main` (a hook refuses it). Branch, PR, review.
- Conventional-commit style (`feat:`, `fix:`, `docs:`, `refactor:`, `ci:`).
- Signed commits preferred.

## Review gates (what your PR will be asked for)

| If your change touches… | Expect a security review for… |
|---|---|
| `internal/server` `/ingest` or auth | token compare, size/schema limits, authn/authz |
| `internal/store` | parameterized queries, IDOR, cross-instance isolation |
| `internal/server/templates/` | XSS; never `template.HTML` on ingested data |
| the auth model | update [docs/AUTH.md](docs/AUTH.md) with the change |
| `go.mod` / `go.sum` | a `docs/DEPENDENCIES.md` entry; permissive-only; cooldown before adopting |
| `Dockerfile` / `.github/workflows/` | pin images + actions by digest/SHA |

Expect a thorough security review on any PR that touches ingest, auth, the
store, or the templates.

## Tests

- Every fix ships with a regression test.
- Store behavior is verified against a real SQLite file, not a mock.
- Ingest/auth behavior asserts HTTP status + body (e.g. 401 without a token,
  413 over the size limit, 2xx for a valid schema-v1 report).

## After a bug fix

Capture the root cause and the fix in your PR description, so reviewers and
future contributors learn from this project's history.
