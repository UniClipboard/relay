# Gateway architecture

## Ownership and request flow

1. A client opens a WebSocket request to the Go gateway.
2. The gateway generates a random 256-bit tunnel ID. It replaces any client-supplied `X-UC-Relay-Tunnel` header.
3. The gateway proxies the request to the private Rust relay container.
4. Upstream `iroh-relay` completes the Iroh handshake and proves the client's endpoint ID.
5. The Rust `AccessControl` hook posts the tunnel ID, proven endpoint ID, and transient credential to `POST /internal/admit` on the gateway's private listener.
6. The Go gateway verifies the credential and applies the current policy under one lock. It reserves the endpoint connection count before returning HTTP 204. Any other response denies admission.
7. Upstream completes authorization and forwards relay data.
8. When the public tunnel ends, the gateway releases its connection reservation.

The internal RPC listener is a trusted service interface. It has no published host port. The relay belongs only to the internal Compose network. The gateway rejects the RPC path on its public listener. A direct relay connection has no gateway-generated live tunnel and cannot pass the access hook. Do not attach untrusted containers to this network.

The gateway counts admitted public tunnels, including a reservation between admission and completion of upstream connection setup. This conservative count can briefly exceed the number of fully registered upstream clients. Failed setup releases the reservation when its proxy tunnel closes. A gateway restart closes all proxy tunnels, so stale upstream connections cannot consume an untracked public tunnel.

The Rust adapter does not validate static tokens or JWTs. It extracts the upstream credential and forwards it transiently to Go. It does not retain application-owned credential state.

## Policy and key updates

The gateway polls the key set and authenticated configuration every 30 seconds. It validates both responses before publishing the policy and keys together. Configuration responses use ETags. An authenticated HTTP 304 refreshes the current policy's freshness and applies the fetched keys. A failed poll does not refresh freshness. A regressing revision or changed relay identity is rejected.

The policy revision is an integer. `max_connections_per_endpoint` must be positive. `client_rx_bytes_per_second` is a non-negative integer; zero means no receive limit. Endpoint IDs use canonical lowercase 64-character hexadecimal text. The issue is the contract source until Cloud publishes `docs/RELAY_CONTROL_PLANE.md`.

Cloud must include old public keys in its JWKS during rotation. The gateway replaces the cached key set only after a valid poll. Unknown key IDs fail closed until the next successful poll.

Admission, blocks, credential validity, and per-endpoint connection counts use the latest applied policy. Freshness uses Go's monotonic clock. The gateway stops admitting new connections after five minutes without a valid policy response. Wall-clock time determines JWT validity.

## Receive-rate limit

Upstream exposes a receive-rate limit in immutable server configuration. Restarting that server on every rate update would terminate existing connections. The Go gateway therefore limits writes to the upgraded upstream tunnel instead. The Rust adapter and upstream protocol internals remain unchanged.

The gateway uses `golang.org/x/time/rate` with a 32-KiB burst. The limit counts WebSocket framing bytes as well as relay data. It applies in the client-to-relay direction. Each connection keeps the rate selected at admission. A new policy rate applies to new connections only. This limit is not an exact per-endpoint byte quota.

## Telemetry and outages

The gateway records active, accepted, and denied connections. It reports applied policy revisions only. Aggregate ingress and egress counters are nullable and remain `null` in v1.

Each retry uses the same `(relay_id, window_start, window_end)` and the same aggregate values. The queue contains only non-secret aggregate windows. It retains up to 24 hours in memory. A process restart discards unsent windows. Cloud must deduplicate retries. The gateway does not send raw endpoint IDs or credentials in telemetry.

Configuration and telemetry requests use node management headers. The gateway reads the owner-only management credential file for each operation and removes the bearer header after the request. Redirects are disabled. Request errors, authorization headers, raw tokens, and token-bearing URLs are never logged by project code.

## Acceptance boundaries

The local suite uses actual upstream clients and the real Rust relay process. A local HTTP server implements Cloud fixtures. Tests exercise the complete public proxy, upstream handshake, private access hook, and Go admission path.

Live Cloud compatibility, production TLS/reverse-proxy logs, and a deployed server upgrade require separate acceptance. Image publication is separate from deployment.
