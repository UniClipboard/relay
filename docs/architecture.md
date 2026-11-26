# UniClipboard Relay v2 Architecture

## Design Principles

1. **Headless Microservices Only**: No Web UI, admin panel, or user account management. Official Cloud operations will call or configure these services from an external control plane.
2. **Strict Separation of Relay Planes**:
   - **Hyper Relay (`cmd/hyper-relay`, `deploy/cloudflare`)**: Application-layer zero-knowledge E2EE short-TTL HTTP chunk store & SSE notifier (Relay HTTP API v1 / Hybrid Relay Contract 0035).
   - **P2P Relay (`cmd/p2p-relay`, reserved)**: Future Tailcat DERP transport tunnel relay. Runs as a separate process/container so operators can deploy either or both independently.
3. **Zero-Knowledge Boundary**:
   - Relay servers never possess device private keys or Content Encryption Keys (CEKs).
   - Only outer signed envelopes (`v`, `transfer_id`, `sender_id`, `recipient_id`, timestamps, chunk sizes/hashes, `eph_pub`, `wrapped_cek`, `sig`) and AES-256-GCM ciphertext chunks transit the server.
   - No clipboard plaintext, filenames, MIME types, or source app metadata ever reach the relay.

## Repository Layout

```text
.
├── cmd/
│   ├── hyper-relay/         # Go Hyper HTTP relay microservice entrypoint
│   └── p2p-relay/           # Reserved boundary for future Tailcat DERP relay
├── internal/
│   ├── auth/                # Shared admission interface & static credential verifier
│   ├── relaycrypto/         # Wire-compatible E2EE crypto, Owner Auth, bitmaps, single-frame codec
│   └── hyper/               # Relay HTTP API v1 server + pluggable ChunkStore (memory / disk)
├── deploy/
│   └── cloudflare/          # Cloudflare Workers + SQLite Durable Objects + R2 implementation
├── vectors/
│   └── hybrid-relay-v1.json # Cross-language deterministic test vectors
├── Dockerfile               # Minimal multi-stage distroless image for hyper-relay
├── docker-compose.yml       # Hyper service + reserved P2P Compose slot
└── .env.example             # Shared RELAY_* and service-specific HYPER_* configuration
```

## Shared Credential Abstraction (`internal/auth`)

Both `hyper-relay` and future `p2p-relay` depend on `internal/auth.Authorizer`:

```go
type Authorizer interface {
    AuthorizeAccessKey(ctx context.Context, req Request) Decision
    AuthorizeDevicePubKey(ctx context.Context, req Request) Decision
}
```

- **Self-Hosted Mode (`auth.StaticAuthorizer`)**:
  - Loads `RELAY_ACCESS_KEY_FILE` (preferred, owner-only `0600` on Unix) or `RELAY_ACCESS_KEY`.
  - Immediately hashes the secret into a 32-byte SHA-256 digest and wipes the raw buffer so no raw access key remains in memory.
  - Compares incoming `X-Unic-Relay-Key` headers by hashing the presented value and calling `subtle.ConstantTimeCompare`.
  - Validates optional `RELAY_ALLOWED_PUBKEYS` as canonical 32-byte raw base64url Ed25519 public keys at startup.
- **Future Cloud Control Plane Mode**:
  - Can implement `auth.Authorizer` backed by short-lived JWTs or control-plane policy RPCs returning per-subject `MaxBytesLimit` overrides, without changing any HTTP or DERP handler code.

## Storage & Lifecycle Guarantees

### Go Microservice (`internal/hyper`)

- **Memory Mode (default)**: Stores ciphertext chunks in RAM (`MemoryChunkStore`) for minimal latency.
- **Disk Temp Mode (`HYPER_STORAGE_DIR`)**: Stores ciphertext chunks in `<dir>/chunks/<mailbox_id>/<transfer_id>/<index>.chunk` (`0700`/`0600`, atomic temp-file rename) to prevent OOM on low-memory NAS devices or under high concurrency. Stale chunk directories are purged on startup and shutdown.
- **Immediate Cleanup**: `POST .../ack`, `DELETE .../transfers/{id}`, and TTL sweepers delete both metadata and backing chunks immediately.

### Cloudflare Edge (`deploy/cloudflare`)

- **Sharding**: Every mailbox routes to an isolated `MailboxDurableObject` keyed by `idFromName(mailbox_id)`.
- **Consistency**: Owner Auth 120s nonce anti-replay, delivery token hashes, transfer bitmaps, and SSE event history live in Durable Object SQLite storage.
- **Blob Offload**: Ciphertext chunks are stored in R2 (`CHUNKS_BUCKET`) and streamed directly on download without buffering large payloads in Worker memory.
- **Expiry**: Chunks are deleted immediately on `ACK`/`DELETE`, pruned on TTL expiry by Durable Object `alarm()`, and backed by a recommended 1-day R2 bucket lifecycle rule.
