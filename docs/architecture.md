# UniClipboard Relay v2 Architecture

## Design Principles

1. **Headless Microservices Only**: No Web UI or admin dashboard.
2. **Direct-to-Object-Storage Data Plane**: Clients use short-lived SigV4 presigned URLs to transfer ciphertext chunks with S3-compatible storage (Tencent COS, Cloudflare R2, AWS S3, Aliyun OSS, MinIO). The official Cloudflare Worker can also upload an authenticated ciphertext chunk to the storage profile selected at transfer creation. Both upload paths use the same `HeadObject` commit checks, SSE updates, and object cleanup.
3. **Strict Separation of Relay Planes**:
   - **Hyper Relay (`cmd/hyper-relay`, `deploy/cloudflare`)**: Application-layer zero-knowledge E2EE control plane ([docs/hyper-api-v2.md](hyper-api-v2.md)).
   - **P2P Relay (`cmd/p2p-relay`, reserved)**: Future Tailcat DERP tunnel relay sharing `internal/auth`.
4. **Zero-Knowledge Boundary**: Neither the relay server nor S3/COS/R2 ever sees device private keys, CEKs, clipboard plaintext, filenames, MIME types, or source app names.

## Repository Layout

```text
.
├── cmd/
│   ├── hyper-relay/         # Go Hyper relay control-plane entrypoint
│   └── p2p-relay/           # Reserved boundary for future Tailcat DERP relay
├── internal/
│   ├── auth/                # Shared admission interface & SHA-256 digest static verifier
│   ├── relaycrypto/         # Wire-compatible E2EE crypto, Owner Auth, bitmaps
│   ├── s3store/             # Zero-dependency S3 SigV4 presigner + HeadObject/DeleteObject
│   └── hyper/               # Direct-to-S3 Hyper relay HTTP API & SSE server
├── deploy/
│   └── cloudflare/          # Cloudflare Workers + SQLite Durable Objects + S3 SigV4 presigner
├── vectors/
│   └── hybrid-relay-v1.json # Cross-language deterministic crypto vectors
├── Dockerfile               # Minimal non-root distroless image for hyper-relay
├── docker-compose.yml       # Hyper service + optional local MinIO profile + reserved P2P slot
└── .env.example             # Shared RELAY_* and S3/COS/R2/OSS configuration templates
```
