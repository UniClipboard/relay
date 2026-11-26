# Repository Guidelines

This repository contains UniClipboard Relay v2: headless, zero-knowledge relay microservices (Go Hyper HTTP relay + Cloudflare Workers/DO/R2 deployment) with a shared credential abstraction (`internal/auth`) and a reserved service slot for the future Tailcat DERP (`p2p-relay`) service.

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
- Hyper Relay must remain 100% wire-compatible with Relay HTTP API v1 and the deterministic cross-language vectors in `vectors/hybrid-relay-v1.json`.
- Do not implement Tailcat DERP forwarding logic unless explicitly scoped; keep `cmd/p2p-relay` as a clean reserved boundary.

## Security

Never accept access tokens or access keys as command-line values. Never log tokens, authorization headers, `X-Unic-Relay-Key`, signatures, nonces, or token-bearing URLs. Raw access keys and delivery tokens must not be persisted or retained in application-owned authorization state after their SHA-256 digest has been computed. Credential files must not be committed and, on Unix, must be readable only by their owner (`0600` or stricter).

Use English for code, comments, documentation, commit messages, and pull request text.
Use AGPL-3.0-only for original project code.
