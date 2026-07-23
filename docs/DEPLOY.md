# Deploying Egret Nest Dashboard

The dashboard is a single static Go binary with embedded SQLite. **The store is a
single writer - run exactly one instance** (no horizontal scaling). Back up the
SQLite file (`egret-nest backup <path>`) rather than replicating.

## 1. Docker (quickest)

```bash
docker run -d -p 8080:8080 -v egret-nest-data:/data \
  -e EGRET_NEST_SECRET_KEY=$(openssl rand -hex 32) \
  ghcr.io/nx1x/egret-nest:v0.1.1
```

Pin a **specific released tag** (e.g. `v0.1.1`) for reproducible deploys. The floating
tags (`latest`, `v0`, `v0.1`) are a convenience only - they move under you and are not for
pinned/reproducible deployments. `EGRET_NEST_SECRET_KEY` is required: without it (and
without `EGRET_NEST_ALLOW_PLAINTEXT_TOTP=1`) the server refuses to start rather than store
TOTP seeds in plaintext.

The image is published to **GitHub Container Registry** (`ghcr.io/nx1x/egret-nest`, signed
with SLSA build provenance) and mirrored on **Docker Hub** (`nx1x/egret-nest`). Swap the
image reference to pull from either.

> **Beta:** the Docker Hub mirror is newly wired into the release workflow and has not been
> fully validated across a release cycle yet. GHCR is the canonical, signed source; prefer
> it if you need the SLSA attestation.

Open http://localhost:8080 → first visit is `/setup` (create the admin).

## 2. docker compose (with optional nginx TLS)

```bash
cp .env.example .env         # then edit: set secrets + BASE_URL
docker compose up -d                 # dashboard only, on 127.0.0.1:8080
docker compose --profile tls up -d   # + nginx on :443 (TLS termination)
```

For the `tls` profile:
- put `fullchain.pem` + `privkey.pem` in `deploy/nginx/certs/`,
- set `server_name` in `deploy/nginx/conf.d/egret-nest.conf`,
- in `.env` set `EGRET_NEST_BEHIND_PROXY=1` and `EGRET_NEST_BASE_URL=https://your.domain`
  (so the app trusts `X-Forwarded-Proto` and issues `Secure` / `__Host-` cookies).

nginx terminates TLS, rate-limits `/ingest` + `/webhook/github`, and caps the body
at 8 MiB (matching the ingest limit). The **app** owns its security headers (CSP,
X-Frame-Options, HSTS-when-secure); nginx does not duplicate them.

## 3. Kubernetes (Helm)

```bash
helm install egret-nest deploy/helm/egret-nest \
  --set config.baseURL=https://egret.example.com \
  --set ingress.enabled=true --set ingress.host=egret.example.com \
  --set secrets.secretKey=$(openssl rand -hex 32)
```

The chart runs **1 replica** (SQLite) with the `Recreate` strategy, a hardened
pod (non-root, read-only rootfs, all caps dropped, seccomp `RuntimeDefault`), a
default-deny NetworkPolicy (`networkPolicy.enabled: true`), a PVC for `/data`, and
a Secret for the sensitive env. TLS is handled by your ingress controller (e.g.
cert-manager) - the app sits behind it with `config.behindProxy: true`, and
`ingress.sslRedirect: true` keeps the ingress forcing HTTPS and setting
`X-Forwarded-Proto=https` (which the app requires to issue `Secure` / `__Host-`
cookies).

**Secrets - recommended:** do NOT put secret values in `values.yaml` (they land in
plaintext in your release manifests / history). Instead point `existingSecret` at a
Secret you manage out-of-band with the same `EGRET_NEST_*` keys, sourced from
**SOPS**, **External Secrets Operator**, or **Vault**:

```bash
helm install egret-nest deploy/helm/egret-nest \
  --set config.baseURL=https://egret.example.com \
  --set ingress.enabled=true --set ingress.host=egret.example.com \
  --set existingSecret=egret-nest-secrets
```

Setting the inline `secrets.*` values is supported for quick trials only.

## Configuration reference

All configuration is via env (`EGRET_NEST_*`) - see the table in
[`cmd/egret-nest/main.go`](../cmd/egret-nest/main.go) and [AUTH.md](AUTH.md).
Highlights:

| Env | Purpose |
|---|---|
| `EGRET_NEST_DB` | SQLite path (default `/data/egret-nest.db` in the image) |
| `EGRET_NEST_SECRET_KEY` | 32-byte hex/base64 key encrypting TOTP seeds at rest (**set this**) |
| `EGRET_NEST_BASE_URL` + `EGRET_NEST_BEHIND_PROXY=1` | required when behind a TLS proxy / for SSO redirects |
| `EGRET_NEST_TLS_CERT` + `EGRET_NEST_TLS_KEY` | serve **HTTPS natively** (PEM paths, TLS 1.2+) instead of terminating at a proxy - set both or neither |
| `EGRET_NEST_WEBHOOK_SECRET` | enables the HMAC-verified `POST /webhook/github` |
| `EGRET_NEST_METRICS_TOKEN` | enables token-gated `/metrics` (≥32 chars) |
| `EGRET_NEST_RETENTION_DAYS` / `_AUDIT_RETENTION_DAYS` | pruning windows (0 = keep) |
| `EGRET_NEST_GITHUB_*` / `EGRET_NEST_OIDC_*` | SSO providers (see AUTH.md) |
| `EGRET_NEST_SETUP_TOKEN` | one-time token required at `/setup` (unset = a random one is generated + logged) |
| `EGRET_NEST_OPEN_INGEST` | `1` = accept `POST /ingest` with **no token** - **dev only, never in production** |

## Backup & upgrade

- **Backup:** `docker exec <container> /egret-nest backup /data/backup.db` (or run
  the `backup` subcommand in the pod). The snapshot is a **credential-bearing,
  unencrypted** SQLite file (password/session/token hashes; TOTP seeds - encrypted
  only if `EGRET_NEST_SECRET_KEY` is set). **Encrypt it before it leaves the host**
  (`age -p`, `gpg -c`) and store it **off-account** (not the same cloud creds that
  run the service). Schedule it (cron/CronJob) and **test a restore periodically**
  - a restore is just stopping the service and swapping the DB file back in. Target
  an RPO/RTO you can meet (e.g. daily backup → RPO 24h).
- **Upgrade:** pull the new image / bump `image.tag` and restart. Schema
  migrations are idempotent and apply on startup; the DB upgrades in place.

## Supply-chain

- Base images (`golang`, `distroless`, `nginx`) are **digest-pinned**; Renovate
  maintains the digests (see `.github/renovate.json5`).
- The release workflow builds from the pinned digests, **scans with Trivy (fails on
  HIGH/CRITICAL)**, then pushes by digest to `ghcr.io/nx1x/egret-nest` (mirrored to
  **Docker Hub** `nx1x/egret-nest`) with **SLSA build provenance**.
