# UniClipboard Relay

A small, token-protected relay server for UniClipboard. Relay transport and protocol handling come
from the official `iroh-relay` crate; this project adds UniClipboard-owned configuration and access
control without maintaining a fork.

## Authentication

Clients authenticate with an access token. Usernames, passwords, HTTP Basic authentication, and
credentials embedded in the relay URL are not supported.

The native Iroh client sends the token as an `Authorization: Bearer` header. Browser clients send it
as a `token` query parameter because browsers cannot attach custom headers to WebSocket requests.

The authorization checker keeps only a digest of the configured token. Tokens are never accepted
as command-line values and must not be written to logs.

## Run locally

Create an owner-only credential file:

```sh
umask 077
openssl rand -hex 32 > relay.token
```

Start the relay:

```sh
cargo run --release -- --bind 127.0.0.1:3340 --token-file relay.token
```

For container environments, `UC_RELAY_TOKEN` may be used instead of a file. Prefer a secret manager
that injects the value at process start. Other settings can be supplied through
`UC_RELAY_BIND`, `UC_RELAY_TOKEN_FILE`, and `UC_RELAY_METRICS_BIND`.

The server listens only on localhost by default. The local relay URL is `http://127.0.0.1:3340`.
Production deployments should expose an HTTPS URL and terminate TLS in a reverse proxy. The proxy
must preserve the `Authorization` header and support WebSocket upgrades. If browser clients are
enabled, redact the `token` query parameter from proxy access logs.

## Verify

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

## License

AGPL-3.0-only. See `LICENSE`.
