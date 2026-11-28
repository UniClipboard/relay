# Hyper Relay — Cloudflare Workers + Durable Objects (Direct to S3 / COS / R2)

Zero-knowledge **Hyper Relay** control plane running on Cloudflare Workers + SQLite Durable Objects (sharded by `mailbox_id`). Clients upload and download AES-256-GCM ciphertext chunks **directly against configured S3-compatible object storage** (Tencent Cloud COS, Cloudflare R2, AWS S3, Aliyun OSS, MinIO) via short-lived SigV4 presigned URLs — zero chunk payload transits the Worker.

## One-Click Deploy

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/UniClipboard/relay/tree/main/deploy/cloudflare)

## Manual Deployment (Wrangler CLI)

```sh
cd deploy/cloudflare
npm ci
```

### 1. Configure Your S3-Compatible Bucket

Edit top-level `vars` in `wrangler.jsonc` (or set them in the Cloudflare Dashboard):

**Example A — Tencent Cloud COS:**
```jsonc
"vars": {
  "S3_ENDPOINT": "https://cos.ap-guangzhou.myqcloud.com",
  "S3_REGION": "ap-guangzhou",
  "S3_BUCKET": "uniclipboard-relay-1250000000",
  "S3_FORCE_PATH_STYLE": "false",
  "S3_KEY_PREFIX": "mailboxes",
  "S3_PRESIGN_TTL_SEC": "300"
}
```

**Example B — Cloudflare R2 (Direct Presigned URLs):**
```jsonc
"vars": {
  "S3_ENDPOINT": "https://<ACCOUNT_ID>.r2.cloudflarestorage.com",
  "S3_REGION": "auto",
  "S3_BUCKET": "uniclipboard-hyper-chunks",
  "S3_FORCE_PATH_STYLE": "true",
  "S3_KEY_PREFIX": "mailboxes",
  "S3_PRESIGN_TTL_SEC": "300"
}
```

> **Bucket Lifecycle Fallback (Recommended):** Configure a 1-day auto-expiration lifecycle rule on prefix `mailboxes/` in your COS / R2 / S3 bucket so orphaned chunks from interrupted uploads are always purged in addition to immediate ACK/DELETE and Durable Object `alarm()` cleanup.

### 2. Set Secrets & Deploy (Self-Hosted)

Never place credentials in `wrangler.jsonc` or git. Use Wrangler secrets:

```sh
npx wrangler secret put S3_ACCESS_KEY_ID
npx wrangler secret put S3_SECRET_ACCESS_KEY

# Optional: shared instance access key (X-Unic-Relay-Key)
npx wrangler secret put RELAY_ACCESS_KEY

npx wrangler deploy
```

## Official Production Hosting (`--env production`)

The `env.production` block in `wrangler.jsonc` configures a single unified global domain (`https://relay.uniclipboard.app`) with:

- **Cloud API Key Verification (`uc-cloud`)**
- **Per-Transfer Geo-Routed Dual S3 Storage** (`"global"` Cloudflare R2 + optional `"cn"` Tencent Cloud COS)
- **Worker-Level Rate Limiting** (`RATE_LIMITER`, 180 req/min keyed by Cloud `subject` or `CF-Connecting-IP`)

### Cloud API Key Verification

When `CLOUD_VERIFY_URL` is configured, every `/v1/relay/*` request must include `X-Unic-Relay-Key`:

- `CLOUD_VERIFY_URL`: Cloud key-verification endpoint (e.g. `https://cloud.uniclipboard.app/api/relay/v2/keys/verify`)
- `CLOUD_VERIFY_SECRET` *(secret, required when `CLOUD_VERIFY_URL` is set; fails closed with HTTP `503` if missing)*: Bearer token sent to `CLOUD_VERIFY_URL`
- `CLOUD_VERIFY_CACHE_TTL_SEC` *(optional, default `60`)*: Positive verification cache TTL in seconds (negative decisions are cached for 10 seconds)
- `RELAY_ACCESS_KEY` *(optional secret)*: Static fallback key checked in constant time before calling Cloud

The Worker hashes the presented key locally with SHA-256 and sends
`{"key_hash":"<hex>"}` to `CLOUD_VERIFY_URL` for authentication. Per-key
`max_transfer_bytes` limits apply alongside server and sender caps.
For each new transfer authenticated with a Cloud key, the Worker also sends
a reservation containing its own request ID and the envelope's ciphertext byte
count. Cloud enforces the per-account 100 MiB UTC calendar-month quota. The
Worker returns `429 monthly_quota_exceeded` with `Retry-After` when Cloud denies
the reservation. Deploy the compatible Cloud verifier and its migration before
deploying this Worker.

### Geo-Routed Dual S3 Storage (`global` R2 + `cn` COS)

Requests from China (`request.cf.country === "CN"`) automatically route newly created transfers to the `"cn"` S3 profile when configured; all other requests route to `"global"`. Each transfer persists its `storage_profile` in Durable Object SQLite so chunk commits, cross-region downloads, ACK cleanup, and expired alarm sweeps always operate against the exact bucket where the transfer was created.

Optional `"cn"` profile non-secret vars:

| Variable | Description |
| --- | --- |
| `S3_CN_ENDPOINT` | China S3/COS API endpoint (e.g. `https://cos.ap-guangzhou.myqcloud.com`) |
| `S3_CN_PUBLIC_ENDPOINT` | Optional public endpoint for presigned client URLs |
| `S3_CN_REGION` | China S3/COS region (e.g. `ap-guangzhou`) |
| `S3_CN_BUCKET` | China S3/COS bucket name |
| `S3_CN_FORCE_PATH_STYLE` | `"false"` for COS virtual-host addressing, `"true"` for path-style |
| `S3_CN_KEY_PREFIX` | Optional object key prefix (defaults to `S3_KEY_PREFIX` or `"mailboxes"`) |
| `S3_CN_PRESIGN_TTL_SEC` | Optional presign TTL in seconds (defaults to `S3_PRESIGN_TTL_SEC` or `300`) |

`/healthz` reports `storage_profiles` (e.g. `["global"]` or `["global", "cn"]`) without exposing credentials or endpoints.

### Production Secrets & Dry Run

Set production secrets via Wrangler (never commit them to `wrangler.jsonc`):

```sh
# Required for production R2 + Cloud API key verification
npx wrangler secret put S3_ACCESS_KEY_ID --env production
npx wrangler secret put S3_SECRET_ACCESS_KEY --env production
npx wrangler secret put CLOUD_VERIFY_SECRET --env production

# Optional: China Tencent Cloud COS credentials (pair with S3_CN_* vars)
npx wrangler secret put S3_CN_ACCESS_KEY_ID --env production
npx wrangler secret put S3_CN_SECRET_ACCESS_KEY --env production

# Validate configuration before deploying
npx wrangler deploy --dry-run --env production
```

## Testing

```sh
cd deploy/cloudflare
npm run cf-typegen
npm run typecheck
npm test
```
