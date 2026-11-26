# Tencent Cloud Serverless Evaluation for Hyper Relay

## Summary Decision

**Decision: Do not provide a Tencent Cloud serverless one-click deployment at this time.**

Operators deploying on Tencent Cloud should use **CVM, Lighthouse, or TKE (Kubernetes)** with this repository's `Dockerfile` and `docker-compose.yml` instead.

## Requirements for Serverless Parity (Cloudflare Baseline)

Hyper Relay (Relay HTTP API v1) relies on four tightly coupled primitives that Cloudflare Workers provides natively with zero external infrastructure:

1. **Per-entity stateful actor (Durable Objects)**: Strongly consistent single-writer state sharded by `mailbox_id` for 120s Owner Auth nonce anti-replay, sender token hashes, transfer metadata/bitmaps, and ordered SSE event history.
2. **Direct push fan-out over long-lived SSE**: When a sender uploads a chunk (`PUT .../chunks/{i}`), the exact actor holding the recipient's active `GET .../events` SSE stream immediately pushes `chunk_ready` without polling.
3. **Scheduled per-entity TTL alarms**: Durable Object `alarm()` wakes up automatically to delete expired transfer metadata and associated R2 ciphertext objects.
4. **Native object storage binding + one-click provisioning**: `wrangler.jsonc` + Deploy to Cloudflare provisions the Worker, Durable Object SQLite namespace, and R2 bucket in one step.

## Evaluation of Tencent Cloud Offerings

| Platform | Capabilities | Gaps Blocking Parity |
|---|---|---|
| **EdgeOne Pages Functions / Edge Functions** | V8 edge runtime, Node.js Cloud Functions, KV & Blob storage. | **No Durable Objects equivalent.** Compute instances are stateless and cannot coordinate per-mailbox single-writer state, atomic 120s nonce replay protection, or in-memory SSE fan-out across edge PoPs without external Redis/database services. Edge proxy idle timeouts also complicate long-lived SSE connections. |
| **SCF (Web Functions) + COS** | Supports HTTP chunked/SSE streaming per invocation and COS object storage. | **Stateless instances with hard execution limits** (max 900s / 15-minute timeout, 6 MB sync response cap). A sender's `PUT` invocation lands on a different stateless container than the recipient's live `GET .../events` SSE invocation, requiring an external pub/sub broker (e.g., TencentDB for Redis) and API Gateway streaming configuration — breaking zero-ops one-click deployment. |
| **CloudBase Run (TCB 云托管)** | Container-based serverless runtime supporting scale-to-zero and SSE streaming. | **Stateless horizontal scaling.** Multi-replica autoscaling splits SSE subscribers and in-memory nonce/transfer state across instances unless pinned to a single replica or backed by external Redis/SQL. Pinning a single container offers no advantage over deploying our standard `Dockerfile` on CVM/Lighthouse while adding platform lock-in. |

## Recommended Tencent Cloud Deployment Path

Deploy the standard Go `hyper-relay` container on **Tencent Cloud Lighthouse**, **CVM**, or **TKE** using the root `docker-compose.yml`:

- Runs in a single ~10 MB distroless container with minimal memory overhead (`HYPER_STORAGE_DIR=/var/lib/hyper-relay` spills chunks to disk on small instances).
- Full native support for long-lived SSE connections, 120s nonce anti-replay, and instant TTL/ACK cleanup with zero external dependencies.
- Ready to co-host the future `p2p-relay` (Tailcat DERP) container on the same host with shared `RELAY_ACCESS_KEY` / `RELAY_ALLOWED_PUBKEYS`.
