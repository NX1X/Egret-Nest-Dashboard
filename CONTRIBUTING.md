# Contributing to Egret Nest Dashboard

Thanks for helping build Egret Nest - the self-hosted dashboard for Egret. A
few things are stricter than a typical repo, mostly around the ingest boundary,
the data store, and the deliberately small dependency surface.

## We're looking for contributors

Egret Nest is young and actively maintained, and I'd like people to build it
with me - regulars who take an area (ingest, auth/SSO, the store, the UI) and
own it, not only drive-by patches. Stdlib-only Go, no framework to learn.

- **Say hi first if you want:** open a [Discussion](https://github.com/NX1X/Egret-Nest-Dashboard/discussions)
  or a draft issue. A small PR is a perfectly good introduction.
- **How reviews work right now:** while the team is small, the maintainer
  reviews PRs (usually within a few days). The review *gates* below aren't
  gatekeeping - they're the checklist your PR is measured against, and they
  apply to the maintainer's own changes too. As the project grows we move to
  peer review and hand out merge rights to established contributors.

### Good first contributions

- **More fuzz targets.** We fuzz the untrusted-input paths (`internal/auth`
  secret decryptor, `internal/server` webhook signature); the `/ingest` report
  decoder and SSO callback parsing are good next targets. See
  `internal/server/fuzz_test.go` for the pattern.
- **Deployment recipes:** a Helm values example, a systemd unit, or a
  reverse-proxy config for a setup we don't document yet.
- **UI/accessibility passes** on the admin templates.
- **Docs:** anything in `docs/` that tripped you up getting it running.

Anything tagged `good first issue` / `help wanted` is fair game - comment to
claim it.

## Ground rules

- Read the auth & security design in [docs/AUTH.md](docs/AUTH.md) first.
- Keep PRs small and focused. One concern per PR.
- Every user-facing change updates [CHANGELOG.md](CHANGELOG.md).
- Be excellent to each other - see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Design constraints (please respect them)

- **Stdlib-only web stack.** `net/http` (Go 1.22 routing), `html/template`. No
  web framework, no router library, no ORM.
- **Pure-Go, no CGO.** SQLite via `modernc.org/sqlite` so the build stays a
  single static binary.
- **Env-only config.** `EGRET_NEST_ADDR`, `EGRET_NEST_DB`, `EGRET_NEST_TOKEN`,
  `EGRET_NEST_INSTANCE`. No config files, no flags for secrets.

Adding a dependency is a real decision - justify it in
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
