# P2P Relay (Tailcat DERP) — Reserved Service Slot

This directory reserves the binary entrypoint and architectural boundary for the future **P2P Relay (`p2p-relay`, Tailcat DERP)** microservice.

## Scope & Status

- **Status:** Intentionally not implemented in v2 initial release (DERP forwarding logic is out of scope).
- **Process isolation:** `p2p-relay` will run as a separate binary/container from `hyper-relay` so operators can deploy either service independently or together via `docker-compose.yml`.
- **Shared admission boundary:** When implemented, `p2p-relay` will import `github.com/uniclipboard/relay/internal/auth` and reuse the exact same credential configuration (`RELAY_ACCESS_KEY` / `RELAY_ACCESS_KEY_FILE`, `RELAY_ALLOWED_PUBKEYS`, and future Cloud control-plane `auth.Authorizer` implementations) using `auth.ServiceP2P`.

## Planned Environment Variables (Reserved)

- Shared credentials (identical to `hyper-relay`):
  - `RELAY_ACCESS_KEY` / `RELAY_ACCESS_KEY_FILE`
  - `RELAY_ALLOWED_PUBKEYS`
- Service-specific (reserved):
  - `P2P_DERP_ADDR`
  - `P2P_STUN_PORT`
  - `P2P_REGION_ID`
  - `P2P_REGION_NAME`
