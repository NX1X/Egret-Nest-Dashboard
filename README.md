# 🪶 Egret Nest Dashboard

> The **optional**, self-hosted dashboard for [Egret](https://github.com/NX1X/Egret).
> It ingests Egret run reports and shows what your CI jobs connected to, what was
> flagged/blocked, and which endpoints are new. Your data stays on **your**
> infrastructure — Egret never runs a central server.

[![GitHub — NX1X/Egret-Nest-Dashboard](https://img.shields.io/badge/GitHub-NX1X%2FEgret--nest--dashboard-181717?logo=github&logoColor=white)](https://github.com/NX1X/Egret-Nest-Dashboard)

- **Status:** auth + hardening complete (Tier 3, [ROADMAP](docs/ROADMAP.md))
- **Repository:** [github.com/NX1X/Egret-Nest-Dashboard](https://github.com/NX1X/Egret-Nest-Dashboard)
- **Stack:** single static Go binary · pure-Go SQLite (`modernc.org/sqlite`, no CGO)
  · embedded UI (`html/template`) · **zero third-party web framework**
- **License:** Apache-2.0

> **The dashboard is never required.** The Egret agent works fully standalone;
> it only talks to this server when you set `EGRET_INGEST_URL`. Unset = nothing
> is sent. See the [core invariant](https://github.com/NX1X/Egret/blob/main/docs/ROADMAP.md).

---

## Run it

```bash
# Docker (recommended for self-hosting)
docker run -p 8080:8080 -v egret-nest-data:/data ghcr.io/nx1x/egret-nest:latest

# or from source
make run     # listens on :8080, db in ./egret-nest.db
```

Open http://localhost:8080.

### Configuration (env)

Common ones below; the **full reference** (~15 vars: SSO providers, TLS, secret key,
webhook/metrics tokens, retention, setup token) is in [docs/DEPLOY.md](docs/DEPLOY.md).

| Variable | Default | Purpose |
|---|---|---|
| `EGRET_NEST_ADDR` | `:8080` | listen address |
| `EGRET_NEST_DB` | `egret-nest.db` | SQLite file path |
| `EGRET_NEST_SECRET_KEY` | _(unset)_ | 32-byte hex/base64 key encrypting TOTP seeds + UI-stored SSO secrets at rest (**set this**) |
| `EGRET_NEST_BASE_URL` | _(derived)_ | public URL; required for SSO redirects |
| `EGRET_NEST_TLS_CERT` / `_TLS_KEY` | _(unset)_ | serve HTTPS natively (else run behind a TLS proxy with `EGRET_NEST_BEHIND_PROXY=1`) |
| `EGRET_NEST_INSTANCE` | `Egret Nest` | display name (also GUI-editable) |

Auth providers (GitHub/OIDC) are configured via `EGRET_NEST_GITHUB_*` / `_OIDC_*`
**or** the admin **Authentication** page — see [docs/AUTH.md](docs/AUTH.md).

---

## Connect an Egret run to it

In your workflow (or locally), point the agent at this server:

```yaml
env:
  EGRET_INGEST_URL: https://egret-nest.your-org.example/ingest
  EGRET_INGEST_TOKEN: ${{ secrets.EGRET_NEST_TOKEN }}   # matches EGRET_NEST_TOKEN
```

The agent POSTs an **Envelope** (`schema_version: 1`) after each run. That's the
only coupling — see the
[ingest contract](https://github.com/NX1X/Egret/blob/main/docs/ingest-contract.md).

---

## API

| Method & path | Purpose |
|---|---|
| `POST /ingest` | Accept a run envelope (JSON), bearer-token auth. `202`, returns `{id, new_endpoints}`. |
| `POST /webhook/github` | HMAC-SHA256-verified GitHub webhook (404 when unset). |
| `GET /` · `/runs/{id}` · `/repos` · `/repos/{repo}` | Runs list / detail / repositories / repo detail. |
| `GET \|POST /account` | Self-service TOTP 2FA (local users). |
| `GET \|POST /orgs`, `/org/{id}/members`, `/org/{id}/tokens` | Org self-service (owner/admin RBAC). |
| `GET \|POST /admin/settings \| /admin/auth \| /admin/tokens \| /admin/users` · `/admin/logs` · `/audit` | Admin console (instance-admin). |
| `GET /metrics` | Prometheus text, token-gated (404 when unset). |
| `GET /healthz` | Liveness (DB-checked). |

Auth flows: `/login`, `/logout`, `/setup`, `/auth/github/*`, `/auth/oidc/*`.

---

## Development

```bash
make test    # unit tests (no kernel, any OS)
make cover   # coverage report -> coverage.html
make build   # static binary -> bin/egret-nest
make docker  # container image
```

Dependencies are vetted per [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md): prefer
the standard library, pure-Go only (no CGO), no npm build chain.

## Roadmap & status

**Tagged `v0.1.0`** (feature-complete, security-reviewed). Shipped: ingest + drift
views, the full auth trilogy (local+TOTP / GitHub / OIDC) with org RBAC, sessions/CSRF,
scoped ingest tokens + HMAC webhooks, the admin console (incl. UI SSO config), native
TLS, packaging (Docker/compose/Helm), and a visual identity pass — all
security-reviewed.

For details, see the **docs map** below. Current status and future direction live in
[docs/ROADMAP.md](docs/ROADMAP.md).

### Docs map (where things live)

| Doc | Owns |
|---|---|
| [CHANGELOG.md](CHANGELOG.md) | Released changes (`[0.1.0]`) — the feature history |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Current status + what's planned |
| [docs/AUTH.md](docs/AUTH.md) | Authoritative auth & security design |
| [docs/DEPLOY.md](docs/DEPLOY.md) | Deploy guide + full env reference |
| [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md) | Dependency policy |

## Contact

- **Website:** [nx1xlab.dev](https://nx1xlab.dev)
- **Contact:** [nx1xlab.dev/contact](https://nx1xlab.dev/contact)
- **Bugs / questions:** open an issue at
  [github.com/NX1X/Egret-Nest-Dashboard/issues](https://github.com/NX1X/Egret-Nest-Dashboard/issues)
- **Security:** see [SECURITY.md](SECURITY.md) for private disclosure.

## License

Egret Nest Dashboard is licensed under the [Apache License 2.0](LICENSE) —
© 2026 NX1X ([nx1xlab.dev](https://nx1xlab.dev)). See [NOTICE](NOTICE) for
attribution and bundled-component licenses.
