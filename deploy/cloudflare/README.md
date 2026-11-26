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

Edit `vars` in `wrangler.jsonc` (or set them in the Cloudflare Dashboard):

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

### 2. Set Secrets & Deploy

Never place credentials in `wrangler.jsonc` or git. Use Wrangler secrets:

```sh
npx wrangler secret put S3_ACCESS_KEY_ID
npx wrangler secret put S3_SECRET_ACCESS_KEY

# Optional: shared instance access key (X-Unic-Relay-Key)
npx wrangler secret put RELAY_ACCESS_KEY

npx wrangler deploy
```

## Testing

```sh
cd deploy/cloudflare
npm run cf-typegen
npm run typecheck
npm test
```
