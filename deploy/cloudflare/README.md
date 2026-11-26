# Hyper Relay — Cloudflare Workers + Durable Objects + R2

Zero-knowledge **Relay HTTP API v1** microservice built on Cloudflare Workers, SQLite-backed Durable Objects (sharded by `mailbox_id`), and R2 object storage.

## One-Click Deploy

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/UniClipboard/relay/tree/main/deploy/cloudflare)

Cloudflare automatically forks the repository, parses `wrangler.jsonc`, provisions the R2 bucket and Durable Object SQLite namespace, and deploys the Worker.

## Architecture

- **Worker Entrypoint (`src/index.ts`)**:
  - Serves `GET /healthz` without credentials.
  - Enforces optional shared instance access key (`X-Unic-Relay-Key`) using SHA-256 digest + `crypto.subtle.timingSafeEqual`.
  - Validates `mailbox_id` and routes requests to the deterministic `MailboxDurableObject` shard (`env.MAILBOX_DO.idFromName(mailboxId)`).
- **Mailbox Durable Object (`src/mailbox-do.ts`)**:
  - Verifies Ed25519 Owner Auth (`X-Unic-PubKey`, `X-Unic-Timestamp`, `X-Unic-Nonce`, `X-Unic-Sig`) and optional `RELAY_ALLOWED_PUBKEYS`.
  - Persists 120s nonce anti-replay entries, sender `token_hash` allowlist, transfer metadata, and recent SSE event buffer (128 events) in DO SQLite storage.
  - Streams live SSE events (`transfer_announced`, `chunk_ready`, `transfer_single_ready`) with `Last-Event-ID` catch-up and periodic `: keepalive` heartbeats.
  - Deletes R2 chunk objects immediately on `POST .../ack` or `DELETE .../transfers/{id}`.
  - Schedules a Durable Object `alarm()` to purge expired transfers (both SQLite rows and R2 objects) and expired nonces automatically.
- **R2 Bucket (`CHUNKS_BUCKET`)**:
  - Stores only AES-256-GCM ciphertext chunks keyed by `mailboxes/<mailbox_id>/transfers/<transfer_id>/chunks/<index>`.

## Manual Deployment (Wrangler CLI)

```sh
cd deploy/cloudflare
npm ci

# 1. Create the R2 bucket (match bucket_name in wrangler.jsonc)
npx wrangler r2 bucket create uniclipboard-hyper-chunks

# 2. (Recommended) Add a 1-day R2 fallback lifecycle rule so orphaned chunks
#    from aborted uploads are always purged even if a Worker is interrupted.
npx wrangler r2 bucket lifecycle add uniclipboard-hyper-chunks \
  --name expire-orphaned-chunks \
  --prefix mailboxes/ \
  --expire-days 1

# 3. (Optional) Configure shared instance access key as an encrypted Wrangler secret
npx wrangler secret put RELAY_ACCESS_KEY

# 4. Deploy
npx wrangler deploy
```

### Configuration Variables (`wrangler.jsonc` -> `vars`)

| Variable | Description | Default |
|---|---|---|
| `RELAY_ORIGIN` | Canonical public HTTPS origin for Owner Auth verification (set if using a custom domain/proxy). | Derived from request URL |
| `RELAY_ALLOWED_PUBKEYS` | Optional comma-separated raw base64url Ed25519 device public keys allowed for Owner Auth. | `""` (any key) |
| `HYPER_MAX_TRANSFER_BYTES` | Maximum total ciphertext bytes per transfer. | `26214400` (25 MiB) |
| `HYPER_DEFAULT_TTL_SEC` | Default transfer TTL in seconds. | `600` (10 min) |
| `HYPER_MAX_TTL_SEC` | Hard ceiling for transfer TTL in seconds. | `1800` (30 min) |
| `HYPER_MAX_SENDERS` | Maximum registered sender token hashes per mailbox. | `64` |
| `HYPER_MAX_TRANSFERS` | Maximum concurrent active transfers per mailbox. | `32` |
| `HYPER_KEEPALIVE_MS` | SSE heartbeat interval in milliseconds. | `25000` |

> **Security:** Never place `RELAY_ACCESS_KEY` in `wrangler.jsonc` or git-tracked files. Always set it with `wrangler secret put RELAY_ACCESS_KEY` (or `.dev.vars` locally, which is gitignored).

## R2 Fallback Lifecycle Rule (Defense-in-Depth)

While `MailboxDurableObject` deletes R2 objects immediately on `ACK`/`DELETE` and via scheduled `alarm()` on TTL expiry, configuring an R2 object lifecycle rule (1-day expiration on prefix `mailboxes/`) ensures zero long-term storage accumulation even in abnormal edge failure scenarios.

## Testing

```sh
cd deploy/cloudflare
npm run cf-typegen
npm run typecheck
npm test
```

The test suite executes inside Cloudflare's `workerd` runtime via `@cloudflare/vitest-plugin` and directly validates `vectors/hybrid-relay-v1.json` plus full end-to-end Relay HTTP API v1 workflows (including R2 deletion and Durable Object Alarm TTL cleanup).
