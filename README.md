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

## Run with Docker

The published image supports both AMD64 and ARM64:

```sh
export UC_RELAY_TOKEN="$(openssl rand -hex 32)"
printf 'Relay token: %s\n' "$UC_RELAY_TOKEN"

docker run --detach \
  --name uniclipboard-relay \
  --publish 3340:3340 \
  --env UC_RELAY_TOKEN \
  ghcr.io/uniclipboard/relay:latest
```

To use a credential file instead, mount an owner-only file that is readable by user `10001` in the
container and set `UC_RELAY_TOKEN_FILE` to its mounted path.

The image runs as an unprivileged user and includes a health check at `/healthz`. Every push to
`main` publishes `latest` and a commit tag. Tags such as `v0.1.0` additionally publish `0.1.0` and
`0.1`.

The server listens only on localhost by default. The local relay URL is `http://127.0.0.1:3340`.
Production deployments should expose an HTTPS URL and terminate TLS in a reverse proxy. The proxy
must preserve the `Authorization` header and support WebSocket upgrades. If browser clients are
enabled, redact the `token` query parameter from proxy access logs.

## Verify

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
docker build --tag uniclipboard-relay:local .
```

## License

AGPL-3.0-only. See `LICENSE`.
