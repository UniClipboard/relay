# UniClipboard Relay (v2)

Headless, zero-knowledge relay microservices for self-hosted and official Cloud-managed [UniClipboard](https://github.com/UniClipboard/UniClipboard) deployments.

No Web UI or management dashboard is included — this repository provides pure microservices designed for container self-hosting, serverless edge deployment, and future integration with the official UniClipboard Cloud control plane.

## Architecture Overview

UniClipboard Relay v2 separates relay concerns into **two independent headless microservices** sharing a unified credential & admission abstraction (`internal/auth`):

| Service | Status | Responsibility |
|---|---|---|
| **Hyper Relay** (`cmd/hyper-relay`, `deploy/cloudflare`) | **Implemented** | Zero-knowledge E2EE short-TTL HTTP chunk relay implementing **Relay HTTP API v1** (Hybrid Relay Contract / 0035 protocol). Supports 1-RTT single-chunk fast path (`<= 2 MiB`), multi-chunk uploads with SHA-256 verification, SSE push with `Last-Event-ID` replay, immediate deletion on ACK/DELETE, and automatic TTL expiry. |
| **P2P Relay** (`cmd/p2p-relay`) | **Reserved (out of scope)** | Future Tailcat DERP tunnel relay. Not implemented in v2 initial release; directory layout, `internal/auth`, and `docker-compose.yml` reserve its integration slot without coupling DERP forwarding into Hyper. |

See [docs/architecture.md](docs/architecture.md) for full protocol boundaries and future Cloud control-plane extension points.

### Shared Credential System (`internal/auth`)

Both `hyper-relay` and the future `p2p-relay` reuse the same admission configuration and Go `auth.Authorizer` interface:

- **Instance Access Key (`RELAY_ACCESS_KEY` / `RELAY_ACCESS_KEY_FILE`)**: Optional shared secret presented via `X-Unic-Relay-Key`. Only its SHA-256 digest is retained in memory and compared in constant time; raw keys are never logged, accepted as CLI flags, or persisted. On Unix, credential files must be owner-only (`chmod 0600`).
- **Device Ed25519 Public Key Allowlist (`RELAY_ALLOWED_PUBKEYS`)**: Optional comma-separated list of raw base64url-encoded 32-byte Ed25519 device public keys permitted to authenticate.
- **Zero-Knowledge Protocol Auth (0035)**:
  - Mailbox owners authenticate with Ed25519 Owner Auth headers (`X-Unic-PubKey`, `X-Unic-Timestamp`, `X-Unic-Nonce`, `X-Unic-Sig`) with ±60s clock skew and a 120s nonce replay window.
  - Senders authenticate with `Authorization: Bearer <delivery_token>`; the server hashes tokens with SHA-256 and stores only the pre-registered `token_hash`.
  - The server holds no device private keys and never sees clipboard plaintext, filenames, MIME types, or source app names.

---

## Option 1: Docker / Docker Compose (Recommended for Self-Hosting & VPS/NAS)

Works on any Linux/macOS host, NAS, or cloud VM (including **Tencent Cloud CVM / Lighthouse / TKE**, AWS EC2, Hetzner, Fly.io, etc.).

1. Create your configuration file:

   ```sh
   cp .env.example .env
   ```

2. Edit `.env` to configure optional shared credentials (`RELAY_ACCESS_KEY`, `RELAY_ALLOWED_PUBKEYS`), your public `HYPER_ORIGIN` (e.g., `https://relay.example.com`), and optionally set `HYPER_STORAGE_DIR=/var/lib/hyper-relay` to spill temporary encrypted chunks to disk instead of RAM (recommended on low-memory NAS devices).

3. Build and start the Hyper relay microservice:

   ```sh
   docker compose up -d --build
   docker compose ps
   curl --fail http://127.0.0.1:8080/healthz
   ```

4. Place a TLS-terminating reverse proxy (Caddy, Nginx, Traefik) in front of `127.0.0.1:8080` and configure the matching `HYPER_ORIGIN` (e.g., `https://relay.example.com`) so Ed25519 Owner Auth signatures validate against the public HTTPS origin. Ensure proxy buffering is disabled for `/v1/relay/mailboxes/*/events` (SSE).

---

## Option 2: Cloudflare Workers + Durable Objects + R2 (One-Click Serverless)

Deploy Hyper Relay globally on Cloudflare's edge with per-mailbox sharded SQLite Durable Objects (Owner Auth, 120s nonce replay protection, delivery token hashes, SSE + `Last-Event-ID`, Alarm TTL cleanup) and R2 object storage (encrypted chunks deleted immediately on ACK/DELETE).

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/UniClipboard/relay/tree/main/deploy/cloudflare)

See [deploy/cloudflare/README.md](deploy/cloudflare/README.md) for manual Wrangler CLI deployment, configuring `RELAY_ACCESS_KEY` via `wrangler secret put`, and setting the recommended R2 lifecycle fallback rule.

---

## Tencent Cloud Serverless Evaluation

Tencent Cloud serverless platforms (**EdgeOne Pages Functions**, **SCF + COS**, and **CloudBase Run / TCB**) were evaluated for parity with Cloudflare Workers + Durable Objects + R2. Because Tencent Cloud currently lacks a native Durable Objects equivalent (strongly consistent per-mailbox stateful actors combining co-located SQLite, alarms, and direct SSE fan-out without external Redis/DB infrastructure) and imposes stateless/timeout constraints on serverless functions, **one-click Tencent Cloud serverless deployment is intentionally not supported**.

Users running on Tencent Cloud can deploy directly on **CVM, Lighthouse, or container services (TKE)** using this repository's `Dockerfile` and `docker-compose.yml`. See [docs/tencent-cloud-evaluation.md](docs/tencent-cloud-evaluation.md) for full details.

---

## Development & Verification

All implementations are verified against the deterministic cross-language test vectors in [vectors/hybrid-relay-v1.json](vectors/hybrid-relay-v1.json):

```sh
# Go Hyper relay & shared auth tests (with race detector)
go test -race ./...
go vet ./...

# Cloudflare Worker typecheck & Vitest runtime tests (workerd + DO + R2)
cd deploy/cloudflare
npm ci
npm run cf-typegen
npm run typecheck
npm test

# Container image build
docker build -t uniclipboard-hyper-relay:local .
```

## v1 Archive

The legacy v1 relay (Rust `iroh-relay` adapter + Go gateway) is preserved in full on the `archive/v1` branch and the `v1-archive` tag:

```sh
git checkout v1-archive
```

## License

Original project code is licensed under **AGPL-3.0-only**. See [LICENSE](LICENSE).
