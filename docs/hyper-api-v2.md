# Hyper Relay API v2 — Direct-to-S3 Object Storage Contract

This document defines the Direct-to-S3 Relay HTTP API implemented by both Go `hyper-relay` (`cmd/hyper-relay`) and the Cloudflare Worker (`deploy/cloudflare`).

## Design Goal

Ciphertext chunk bytes **never transit the relay server**. The relay acts purely as a zero-knowledge control plane (authentication, quota/TTL enforcement, SSE notifications, short-lived AWS SigV4 presigned URLs, `HeadObject` verification, and `DeleteObject` cleanup), while clients upload and download AES-256-GCM ciphertext chunks directly against any S3-compatible object storage (Tencent COS, Cloudflare R2, AWS S3, Aliyun OSS, MinIO, Backblaze B2).

## Cryptography & Admission

Unchanged from Hybrid Relay Contract 0035 (`vectors/hybrid-relay-v1.json`):

- Optional shared instance key: `X-Unic-Relay-Key` (SHA-256 constant-time digest comparison).
- Optional Ed25519 allowlist: `RELAY_ALLOWED_PUBKEYS`.
- Mailbox Owner Auth: `X-Unic-PubKey`, `X-Unic-Timestamp` (or `X-Unic-TS`), `X-Unic-Nonce` (120s anti-replay), `X-Unic-Sig` (±60s skew).
- Sender Auth: `Authorization: Bearer <delivery_token>` (server stores only `SHA-256(delivery_token)`).
- End-to-end encryption: Clients continue encrypting chunks with AES-256-GCM and verifying `SHA-256(C[i]) == envelope.chunk_hashes[i]` on download.

## Endpoints

| Method & Path | Auth | Description |
|---|---|---|
| `GET /healthz` | None | Returns `{"status":"ok","service":"hyper-relay","storage":"s3-direct"}` |
| `PUT /v1/relay/mailboxes/{mailbox_id}/senders/{token_hash}` | Owner Auth | Register/update sender delivery token hash and optional `max_bytes` (`204`) |
| `DELETE /v1/relay/mailboxes/{mailbox_id}/senders/{token_hash}` | Owner Auth | Revoke sender delivery token hash (`204`) |
| `POST /v1/relay/mailboxes/{mailbox_id}/transfers` | `Bearer <token>` | Create transfer with outer signed `Envelope` JSON (unified for both 1-chunk and multi-chunk transfers). Emits SSE `transfer_announced` and returns `{transfer_id, expires_at_ms, max_chunk_bytes, upload_mode: "presigned", upload_urls: [...]}` (inline presigned `PUT` URLs for up to 16 chunks). |
| `POST /v1/relay/mailboxes/{mailbox_id}/transfers/{transfer_id}/chunks/{index}/upload-url` | `Bearer <token>` | Issue or refresh a short-lived SigV4 presigned `PUT` URL for chunk `index`. Returns `{method: "PUT", url, expires_at_ms}`. |
| `POST /v1/relay/mailboxes/{mailbox_id}/transfers/{transfer_id}/chunks/{index}/commit` | `Bearer <token>` | Confirm direct upload of chunk `index`. Server verifies existence and byte size via S3 `HeadObject` (rejecting and deleting oversized chunks with `413`), sets bit `index`, emits SSE `chunk_ready`, and returns `204`. |
| `GET /v1/relay/mailboxes/{mailbox_id}/events` | Owner Auth | SSE stream (`Last-Event-ID` replay + `: keepalive` heartbeats) delivering `transfer_announced` and `chunk_ready`. |
| `GET /v1/relay/mailboxes/{mailbox_id}/transfers` | Owner Auth | List active non-expired transfers with `envelope` and `available_bitmap`. |
| `GET /v1/relay/mailboxes/{mailbox_id}/transfers/{transfer_id}/chunks/{index}` | Owner Auth | Issue a short-lived SigV4 presigned `GET` URL for chunk `index`. Returns `{method: "GET", url, expires_at_ms, size}`. |
| `POST /v1/relay/mailboxes/{mailbox_id}/transfers/{transfer_id}/ack` | Owner Auth | Mark transfer consumed and immediately `DeleteObject` all chunk objects in S3/COS/R2 (`204`). |
| `DELETE /v1/relay/mailboxes/{mailbox_id}/transfers/{transfer_id}` | Owner Auth or `Bearer <token>` | Cancel/abort transfer and immediately `DeleteObject` all chunk objects in S3/COS/R2 (`204`). |

## Client Security Requirements for Direct Object Storage

1. **Strip all relay credentials**: Never send `Authorization`, `X-Unic-Relay-Key`, or `X-Unic-*` headers when calling a presigned S3/COS/R2 URL.
2. **SSRF protection**: Enforce HTTPS (unless loopback test mode is explicitly enabled) and reject private/link-local IP addresses before dialing presigned URLs.
3. **Never log presigned URLs**: Presigned URLs contain temporary bearer signatures and must be treated as secrets.
4. **End-to-end verification**: Always verify `SHA-256(body) == envelope.chunk_hashes[index]` and AES-256-GCM AEAD authentication after downloading from object storage.
