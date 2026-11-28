# Repository Guidelines

This repository contains UniClipboard Relay v2: headless, zero-knowledge relay microservices (Go Hyper control plane + Cloudflare Workers/DO deployment) using Direct-to-S3 object storage (Tencent COS, Cloudflare R2, AWS S3, Aliyun OSS, MinIO), a shared credential abstraction (`internal/auth`), and a reserved service slot for the future Tailcat DERP (`p2p-relay`) service.

## Commands

Before committing Go changes, run:

- `gofmt -l .` (must produce no output)
- `go vet ./...`
- `go test -race ./...`

Before committing Cloudflare Worker changes (`deploy/cloudflare`), run:

- `npm run cf-typegen`
- `npm run typecheck`
- `npm test`

Changes to container packaging (`Dockerfile`, `docker-compose.yml`) must pass a local `docker build` and `/healthz` smoke check.

## Architecture

- Keep `hyper-relay` and future `p2p-relay` strictly decoupled as independent headless microservices with no Web UI.
- Both services must share credential & admission policy through `internal/auth` (`auth.Authorizer`, `RELAY_ACCESS_KEY`, `RELAY_ALLOWED_PUBKEYS`).
- Hyper Relay uses short-lived S3 SigV4 presigned PUT/GET URLs for direct object storage traffic. The official Cloudflare Worker also accepts authenticated ciphertext uploads for transfers that use the upload fallback. Cryptography must remain compatible with `vectors/hybrid-relay-v1.json`.
- Do not implement Tailcat DERP forwarding logic unless explicitly scoped; keep `cmd/p2p-relay` as a clean reserved boundary.

## Security

Never accept access tokens, access keys, or S3 secrets as command-line values. Never log tokens, authorization headers, `X-Unic-Relay-Key`, S3 secret keys, presigned URLs, signatures, nonces, or token-bearing URLs. Raw access keys and delivery tokens must not be persisted or retained in application-owned authorization state after their SHA-256 digest has been computed. Credential files must not be committed and, on Unix, must be readable only by their owner (`0600` or stricter).

Use English for code, comments, documentation, commit messages, and pull request text.
Use AGPL-3.0-only for original project code.
