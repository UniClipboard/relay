#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
artifact="$(pwd)/artifacts/$(date -u +%Y%m%dT%H%M%SZ)-compose"
mkdir -p "$artifact"
printf 'Compose verification artifact: %s\n' "$artifact"
git rev-parse HEAD > "$artifact/head.txt"
git status --porcelain > "$artifact/worktree.txt"
credential="$(mktemp)"
override="$(mktemp)"
project="relay-acceptance-$$"
cleanup() {
 status=$?
 if [ "$status" -ne 0 ]; then printf 'FAIL exit=%s\n' "$status" > "$artifact/result.txt"; fi
 docker compose -p "$project" -f compose.yaml -f "$override" down --remove-orphans > "$artifact/down.log" 2>&1 || true
 rm -f "$credential" "$override"
}
trap cleanup EXIT INT TERM
(umask 077; openssl rand -hex 32 > "$credential")
# This disposable file contains only the numeric file owner, never a credential.
cat > "$override" <<OVERRIDE
services:
  gateway:
    user: "$(id -u):$(id -g)"
    ports: !override
      - "127.0.0.1::3340"
OVERRIDE
export UC_RELAY_CREDENTIAL_PATH="$credential"
export UC_GATEWAY_MODE=static
export UC_RELAY_TOKEN_FILE=/run/secrets/relay-credential
export UC_RELAY_IMAGE_TAG="acceptance-$$"
docker compose -p "$project" -f compose.yaml -f "$override" config --quiet
docker compose -p "$project" -f compose.yaml -f "$override" build > "$artifact/build.log" 2>&1
docker compose -p "$project" -f compose.yaml -f "$override" up --detach --wait --wait-timeout 120 > "$artifact/up.log" 2>&1
docker compose -p "$project" -f compose.yaml -f "$override" ps --format json > "$artifact/containers.jsonl"
address="$(docker compose -p "$project" -f compose.yaml -f "$override" port gateway 3340)"
curl --fail --silent --show-error "http://$address/healthz" > "$artifact/health.txt"
# Run real upstream clients against the published container port.
cargo build --locked --example relay_probe > "$artifact/probe-build.log" 2>&1
./target/debug/examples/relay_probe "http://$address" "$credential" forward > "$artifact/forward.txt"
docker compose -p "$project" -f compose.yaml -f "$override" logs --no-color > "$artifact/containers.log"
if rg -F -f "$credential" "$artifact/containers.log" >/dev/null; then
 printf 'Credential appeared in container logs\n' >&2
 rm -f "$artifact/containers.log"
 exit 1
fi
printf 'PASS\n' > "$artifact/result.txt"
printf 'Compose verification artifact: %s\n' "$artifact"
