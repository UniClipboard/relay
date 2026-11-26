# UniClipboard Relay (v2)

Headless, zero-knowledge relay microservices for self-hosted and official Cloud-managed [UniClipboard](https://github.com/UniClipboard/UniClipboard) deployments.

No Web UI or management dashboard is included. **Hyper Relay** operates as a lightweight control plane where clients upload and download AES-256-GCM ciphertext chunks **directly against S3-compatible object storage** (Tencent Cloud COS, Cloudflare R2, AWS S3, Aliyun OSS, MinIO, Backblaze B2) via short-lived SigV4 presigned URLs — **zero chunk bandwidth transits the relay server**.

## Architecture Overview

| Service | Status | Responsibility |
|---|---|---|
| **Hyper Relay** (`cmd/hyper-relay`, `deploy/cloudflare`) | **Implemented** | Zero-knowledge E2EE control plane ([API v2 Direct-to-S3](docs/hyper-api-v2.md)). Handles Ed25519 Owner Auth + 120s nonce anti-replay, delivery token hashes, short-lived S3 SigV4 presigned `PUT`/`GET` URL issuance, `HeadObject` commit validation, SSE push with `Last-Event-ID`, and immediate `DeleteObject` cleanup on ACK/DELETE/TTL. |
| **P2P Relay** (`cmd/p2p-relay`) | **Reserved (out of scope)** | Future Tailcat DERP tunnel relay. Runs as a separate process/container sharing `internal/auth` (`RELAY_ACCESS_KEY`, `RELAY_ALLOWED_PUBKEYS`). |

See [docs/architecture.md](docs/architecture.md) and [docs/hyper-api-v2.md](docs/hyper-api-v2.md) for full details.

---

## Supported Object Storage Providers (Standard S3 SigV4)

Configure any S3-compatible bucket (private bucket + recommended 1-day expiration lifecycle rule on prefix `mailboxes/`):

| Provider | `S3_ENDPOINT` | `S3_REGION` | `S3_FORCE_PATH_STYLE` |
|---|---|---|---|
| **Tencent Cloud COS** | `https://cos.<region>.myqcloud.com` | e.g. `ap-guangzhou` | `false` (`S3_BUCKET=<name>-<appid>`) |
| **Cloudflare R2** | `https://<account_id>.r2.cloudflarestorage.com` | `auto` | `true` |
| **AWS S3** | `https://s3.<region>.amazonaws.com` | e.g. `us-east-1` | `false` |
| **Aliyun OSS** | `https://oss-<region>.aliyuncs.com` | e.g. `oss-cn-hangzhou` | `false` |
| **MinIO / Self-Hosted S3** | `http://minio:9000` (+ `S3_PUBLIC_ENDPOINT`) | `us-east-1` | `true` |

---

## Option 1: Docker / Docker Compose (VPS / Tencent Cloud CVM / Lighthouse / NAS)

Because ciphertext bytes flow directly between devices and COS/S3/R2, even a minimal 1 vCPU / 1 Mbps VM can handle high-throughput transfers cleanly.

1. Copy `.env.example` and configure your S3/COS/R2 credentials and optional shared admission keys:

   ```sh
   cp .env.example .env
   ```

2. Start Hyper Relay (or add `--profile minio` for a bundled local MinIO S3 server):

   ```sh
   docker compose up -d --build
   curl --fail http://127.0.0.1:8080/healthz
   ```

3. Place a TLS-terminating reverse proxy (Caddy/Nginx) in front of `127.0.0.1:8080`, set `HYPER_ORIGIN=https://your-relay-domain`, and disable proxy buffering on `/v1/relay/mailboxes/*/events` (SSE).

---

## Option 2: Cloudflare Workers + Durable Objects (Direct to COS / R2 / S3)

Deploy the Hyper Relay control plane globally on Cloudflare Workers + SQLite Durable Objects while pointing chunk traffic directly at **Cloudflare R2**, **Tencent Cloud COS**, **AWS S3**, or **Aliyun OSS** via S3 SigV4 presigned URLs.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/UniClipboard/relay/tree/main/deploy/cloudflare)

See [deploy/cloudflare/README.md](deploy/cloudflare/README.md) for Wrangler configuration (`S3_ENDPOINT`, `S3_BUCKET`, `wrangler secret put S3_ACCESS_KEY_ID`, `wrangler secret put S3_SECRET_ACCESS_KEY`) and bucket lifecycle setup.

---

## Tencent Cloud Serverless Evaluation

Tencent Cloud serverless platforms (**EdgeOne Pages Functions**, **SCF**, **CloudBase Run**) lack a native Durable Objects equivalent for stateful per-mailbox coordination + long-lived SSE fan-out, so one-click Tencent Cloud serverless deployment is intentionally not supported. However, **Tencent Cloud COS** is a first-class direct storage target for both Go `hyper-relay` (on CVM/Lighthouse/TKE) and Cloudflare Workers! See [docs/tencent-cloud-evaluation.md](docs/tencent-cloud-evaluation.md).

---

## Verification

```sh
# Go tests with race detector (includes vectors/hybrid-relay-v1.json & mock S3 round-trip)
go test -race ./...
go vet ./...

# Cloudflare Worker typegen, typecheck, and workerd Vitest tests
cd deploy/cloudflare
npm ci
npm run cf-typegen
npm run typecheck
npm test

# Container build
docker build -t uniclipboard-hyper-relay:local .
```

## v1 Archive

The legacy v1 relay (Rust `iroh-relay` adapter + Go gateway) is preserved on branch `archive/v1` and tag `v1-archive`.

## License

AGPL-3.0-only. See [LICENSE](LICENSE).
