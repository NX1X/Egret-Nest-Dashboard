<!-- Thanks for contributing to Egret Nest Dashboard. Keep PRs focused and small. -->

## What & why

<!-- One or two sentences: what this changes and the motivation. Link the issue. -->

Closes #

## Type

- [ ] Feature
- [ ] Fix
- [ ] Refactor / cleanup
- [ ] Docs
- [ ] CI / build / deps
- [ ] Security

## Checklist

- [ ] `make fmt vet` clean; `make test` passes
- [ ] `CHANGELOG.md` updated (category: Added/Changed/Deprecated/Removed/Fixed/Security)
- [ ] New/changed behavior is covered by a test
- [ ] No secrets, tokens, or ingested payloads committed in code, logs, or fixtures

## Security-sensitive paths (tick if touched — extra review required)

- [ ] `internal/server` `/ingest` or auth path → token handling, size limits, schema validation
- [ ] `internal/store` → parameterized queries, IDOR, cross-instance isolation
- [ ] `internal/server/templates/` → XSS; no `template.HTML` on ingested data
- [ ] Auth model changed → update `docs/AUTH.md`
- [ ] `go.mod`/`go.sum` → justified in `docs/DEPENDENCIES.md`
- [ ] `Dockerfile` or `.github/workflows/` → images + actions pinned by digest/SHA

## Notes for reviewers

<!-- Trade-offs, follow-ups, DB-upgrade path if the schema changed, etc. -->
