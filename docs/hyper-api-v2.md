# Hyper Relay API v2 — Direct-to-S3 Object Storage Contract

This document defines the Direct-to-S3 Relay HTTP API implemented by both Go `hyper-relay` (`cmd/hyper-relay`) and the Cloudflare Worker (`deploy/cloudflare`).

## Design Goal

Clients upload and download AES-256-GCM ciphertext chunks directly against S3-compatible object storage (Tencent COS, Cloudflare R2, AWS S3, Aliyun OSS, MinIO, Backblaze B2) using short-lived AWS SigV4 presigned URLs. The official Cloudflare Worker also accepts authenticated ciphertext uploads when a sender cannot use direct storage. The relay handles authentication, quota, transfer expiry, SSE, commit verification, and object cleanup.

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
| `POST /v1/relay/mailboxes/{mailbox_id}/transfers/{transfer_id}/chunks/{index}/commit` | `Bearer <token>` | Confirm upload of chunk `index`. Server verifies existence and byte size via S3 `HeadObject` (rejecting and deleting oversized chunks with `413`), sets bit `index`, emits SSE `chunk_ready`, and returns `204`. The Worker snapshots the committed object and returns `204` for a repeated commit of the same object version. |
| `GET /v1/relay/mailboxes/{mailbox_id}/events` | Owner Auth | SSE stream (`Last-Event-ID` replay + `: keepalive` heartbeats) delivering `transfer_announced` and `chunk_ready`. |
| `GET /v1/relay/mailboxes/{mailbox_id}/transfers` | Owner Auth | List active non-expired transfers with `envelope` and `available_bitmap`. |
| `GET /v1/relay/mailboxes/{mailbox_id}/transfers/{transfer_id}/chunks/{index}` | Owner Auth | Issue a short-lived SigV4 presigned `GET` URL for chunk `index`. Returns `{method: "GET", url, expires_at_ms, size}`. |
| `POST /v1/relay/mailboxes/{mailbox_id}/transfers/{transfer_id}/ack` | Owner Auth | Mark transfer consumed and immediately `DeleteObject` all chunk objects in S3/COS/R2 (`204`). |
| `DELETE /v1/relay/mailboxes/{mailbox_id}/transfers/{transfer_id}` | Owner Auth or `Bearer <token>` | Cancel/abort transfer and immediately `DeleteObject` all chunk objects in S3/COS/R2 (`204`). |

## Official Relay Upload Fallback

At `https://relay.uniclipboard.app`, the Cloudflare Worker includes an optional `"relay_upload_fallback": true` field in a successful create response. A missing field or a value other than `true` means the client uses direct uploads. The response keeps `"upload_mode": "presigned"` and the existing upload grants.

1. Try the presigned PUT first. If the storage transport reports `address_blocked` and the transfer advertises support, make one fallback attempt before abort cleanup. Use only the canonical official HTTPS origin.
2. Send `PUT /v1/relay/mailboxes/{mailbox_id}/transfers/{transfer_id}/chunks/{index}/upload` using the authenticated Relay transport and its redirect policy. Send the usual `X-Unic-Relay-Key`, the transfer's `Authorization: Bearer <delivery_token>`, and the original encrypted chunk as the raw `application/octet-stream` body. The client constructs the path locally.
3. On `204`, call the existing commit operation. The upload stages the object in the transfer's persisted storage profile. Commit snapshots the object, updates the bitmap, and publishes `chunk_ready`. Receivers download the snapshot using presigned GET and perform their existing ciphertext verification.

The Worker validates sender ownership, transfer lifetime, chunk index, size, and the ciphertext SHA-256 from the envelope. Staged and committed bytes share the original transfer budget. Upload retries use the same transfer, index, and ciphertext and do not make another Cloud quota reservation. A successful replay for a committed chunk returns `204` without rewriting the object. Cancellation, ACK, and expiry remove the transfer and wait for in-flight fallback writes before deleting the objects. Bucket lifecycle rules cover interrupted cleanup.

| Status | Error | Meaning |
|---|---|---|
| `400` | `invalid_body`, `invalid_chunk_index`, `invalid_transfer_id`, `size_mismatch`, `chunk_hash_mismatch` | Invalid data or path. |
| `401` / `403` | `unauthorized` / `forbidden` | Missing Relay or sender credentials, rejected sender, or wrong transfer owner. |
| `404` / `410` | `not_found` / `gone` | Wrong origin, missing transfer, or expired or removed transfer. |
| `405` | `method_not_allowed` | The upload requires PUT. |
| `409` | `upload_in_progress` | A fallback upload or commit already holds this chunk. |
| `413` | `chunk_too_large`, `payload_too_large` | The chunk or combined staged and committed bytes exceed the transfer budget. |
| `429` | `rate_limited` | The existing Worker rate limit denied the request. |
| `502` / `503` | `storage_error` / `s3_not_configured`, `auth_unavailable` | Storage write, storage configuration, or authentication service error. |

Keep server errors and client diagnostics categorical. The Go Relay and self-hosted Worker origins use the presigned contract.

## Client Security Requirements for Direct Object Storage

1. **Strip all relay credentials**: Never send `Authorization`, `X-Unic-Relay-Key`, or `X-Unic-*` headers when calling a presigned S3/COS/R2 URL.
2. **SSRF protection**: Enforce HTTPS (unless loopback test mode is explicitly enabled) and reject private/link-local IP addresses before dialing presigned URLs.
3. **Never log presigned URLs**: Presigned URLs contain temporary bearer signatures and must be treated as secrets.
4. **End-to-end verification**: Always verify `SHA-256(body) == envelope.chunk_hashes[index]` and AES-256-GCM AEAD authentication after downloading from object storage.
