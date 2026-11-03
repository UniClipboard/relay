# UniClipboard Relay

UniClipboard Relay deploys two containers with Docker Compose:

- The Go gateway owns static-token authentication, Cloud credentials, admission policy, connection limits, receive-rate limits, and telemetry.
- The Rust adapter runs upstream `iroh-relay`. Upstream owns the handshake, relay protocol, forwarding, and connection lifecycle.

Clients connect to the gateway. The gateway proxies WebSocket traffic to the relay on a private Docker network. After the upstream handshake proves the endpoint ID, the Rust access hook requests an admission decision from the gateway. The relay rejects requests without a live gateway tunnel.

See [the gateway design](docs/GATEWAY.md) for the internal contract and failure behavior.

## Deploy with a static token

Install Docker Engine and the Docker Compose plugin. Run these commands from this repository.

1. Create the credential file:

   ```sh
   mkdir -p secrets
   chmod 700 secrets
   (umask 077; openssl rand -hex 32 > secrets/relay.token)
   ```

2. Give the gateway container access to the file. On Linux, the default container user is UID/GID `10001`:

   ```sh
   sudo chown 10001:10001 secrets/relay.token
   chmod 600 secrets/relay.token
   ```

   Alternatively, set `UC_RELAY_UID` and `UC_RELAY_GID` to the file owner's numeric IDs. Compose bind-mounts file secrets and does not change their ownership. Docker Desktop can map file ownership differently; verify access on the target host.

3. Build and start both containers:

   ```sh
   docker compose up --detach --build
   docker compose ps
   curl --fail http://127.0.0.1:3340/healthz
   ```

The published listener binds to host loopback by default. A reverse proxy on the host can expose HTTPS. Set `UC_RELAY_PUBLISH_ADDRESS` when another bind address is required. Never publish the relay container's port or the gateway's internal port `3341`.

The gateway accepts a 32-to-512-character static token. Native clients send `Authorization: Bearer <token>`. Browser clients use the `token` query parameter. The upstream extractor keeps bearer-header precedence and case-insensitive scheme matching. The gateway retains only a SHA-256 digest of the configured static token and compares digests in constant time.

The Go gateway also accepts `UC_RELAY_TOKEN` for deployments that inject environment secrets. A configured `UC_RELAY_TOKEN_FILE` takes precedence. Compose uses a file secret by default. Tokens are not accepted as command-line values.

## Deploy a Cloud-managed node

Use a node management credential issued by Cloud. This credential is different from a client JWT.

1. Store the management credential in an owner-only file. Give the container user access as described above.
2. Create `.env` with non-secret settings:

   ```dotenv
   UC_GATEWAY_MODE=cloud
   UC_RELAY_NODE_ID=your-node-id
   UC_RELAY_CREDENTIAL_PATH=./secrets/node.secret
   UC_RELAY_TOKEN_FILE=
   UC_RELAY_MANAGEMENT_FILE=/run/secrets/relay-credential
   ```

3. Start the containers:

   ```sh
   docker compose up --detach --build
   docker compose ps
   ```

The gateway starts closed. It polls Cloud every 30 seconds and applies a policy before reporting its revision. It keeps a valid policy for at most five minutes during a Cloud outage. After that interval, it denies new connections. Existing connections remain open.

The gateway verifies EdDSA JWTs against Cloud's public Ed25519 JWKS. It requires `kid`, issuer `https://cloud.uniclipboard.app`, audience `uc-relay`, the handshake-proven endpoint ID in `sub`, the policy's `relay_id`, `nbf`, and `exp`. Clock skew is at most 30 seconds. JWTs have a separate 16-KiB safety limit; the static-token limit does not apply.

Cloud receives telemetry every 30 seconds, including idle windows. Retried windows keep their original timestamps and contents. Aggregate ingress and egress bytes are `null`. The gateway does not claim exact per-endpoint byte accounting.

## TLS and proxy logs

Terminate TLS at an external reverse proxy. Preserve the `Authorization` header and enable WebSocket upgrades. Redact the `token` query parameter from access logs. Do not enable request dumps or upstream debug/trace logs in production. Such logs can include credential-bearing request URLs.

## Health and upgrades

The gateway health check succeeds when static authentication is configured or a Cloud policy is fresh. The relay health check requests the upstream `/healthz` route. Relay health alone does not prove that clients can authenticate.

The gateway forwards unauthenticated `GET /ping` latency probes to upstream `iroh-relay`. The upstream returns HTTP 200 with an empty body. Iroh clients use this probe to measure relay latency and select a relay. The `/generate_204` probe returns HTTP 204. Probe success does not prove that a client can authenticate or forward data.

For published images, set `UC_RELAY_IMAGE_TAG` to the same immutable `sha-<commit>` tag for both containers. Then run:

```sh
docker compose pull
docker compose up --detach --no-build
```

A process upgrade closes active connections. Clients must reconnect. A policy update does not close existing connections. Run exactly one gateway and one relay process per public node in v1.

The publication workflow builds AMD64 and ARM64 images at `ghcr.io/uniclipboard/relay` and `ghcr.io/uniclipboard/relay-gateway`. Pushes to `main` publish `latest` and a commit tag. Version tags also publish version and major/minor tags. Publishing images does not update a running server.

Each build pushes an inspectable `sha-<commit>-amd64` or `sha-<commit>-arm64` tag, using the first seven characters of the commit SHA. The publication job checks both source tags before merging them. It verifies every published tag contains both Linux architectures, then pulls each platform and checks its image configuration. The job retains publication evidence for seven days, including the full commit SHA, workflow run, source manifests, published manifests, pull results, and final status. Both image publication jobs must pass before the release is considered published. A failed run can leave partial tags in the registry; do not deploy them.

## Configuration

| Setting | Default | Owner |
| --- | --- | --- |
| `UC_GATEWAY_MODE` | `static` | Go gateway |
| `UC_RELAY_ALLOW_UNAUTHENTICATED_LOCAL` | `false` | Go gateway, loopback only |
| `UC_GATEWAY_BIND` | `:3340` | Go gateway public listener |
| `UC_GATEWAY_INTERNAL_BIND` | `:3341` | Go gateway private access listener |
| `UC_RELAY_UPSTREAM` | `http://relay:3340` | Go gateway |
| `UC_RELAY_TOKEN_FILE` | None outside Compose | Go gateway static mode |
| `UC_RELAY_TOKEN` | None | Go gateway static mode |
| `UC_RELAY_NODE_ID` | None | Go gateway Cloud mode |
| `UC_RELAY_MANAGEMENT_FILE` | None | Go gateway Cloud mode |
| `UC_CLOUD_URL` | `https://cloud.uniclipboard.app` | Go gateway Cloud mode |
| `UC_RELAY_BIND` | `127.0.0.1:3340` outside Compose | Rust adapter |
| `UC_RELAY_GATEWAY_URL` | `http://gateway:3341` | Rust adapter |
| `UC_RELAY_METRICS_BIND` | Disabled | Rust adapter |

Gateway service URLs accept an HTTP or HTTPS origin only. Credentials, query strings, fragments, and paths are rejected. HTTP Cloud origins are allowed only on loopback for local acceptance fixtures. Production nodes must use HTTPS.

The previous standalone Rust token checker has moved to the Go gateway. Start both services to use static authentication. For local simulators, set `UC_RELAY_ALLOW_UNAUTHENTICATED_LOCAL=true` on the Go gateway and bind `UC_GATEWAY_BIND` to a numeric loopback address. The gateway rejects this mode on a non-loopback listener. The Rust relay still requires a live gateway tunnel. Do not enable this mode for public deployments.

## Verify

Run the complete acceptance script:

```sh
./scripts/verify.sh
```

The script builds a real upstream Iroh client, starts real Rust relay processes, runs the Go gateway acceptance suite with a local Cloud HTTP fixture, and runs the Rust and Go checks. It writes a timestamped directory under `artifacts/` with the source identity, diff, and machine-readable results. No production credentials are required.

To verify both images and Compose health, also run:

```sh
./scripts/verify-compose.sh
```

The tests cover unauthenticated latency probes in static mode and before Cloud policy loading, valid and invalid credentials, endpoint binding, policy changes, limits, outages, telemetry retry, and real datagram forwarding. Compose acceptance also checks `/ping` through the published gateway port and records its status, headers, and body. Local fixture acceptance does not prove compatibility with the live Cloud deployment.

## License

AGPL-3.0-only. See `LICENSE`.
