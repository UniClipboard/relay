#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
artifact="$(pwd)/artifacts/$(date -u +%Y%m%dT%H%M%SZ)-gateway"
mkdir -p "$artifact"
printf 'Verification artifact: %s\n' "$artifact"
record_failure() {
 status=$?
 if [ "$status" -ne 0 ]; then printf 'FAIL exit=%s\n' "$status" > "$artifact/result.txt"; fi
}
trap record_failure EXIT
git rev-parse HEAD > "$artifact/head.txt"
git status --porcelain > "$artifact/worktree.txt"
git diff --binary > "$artifact/tracked.patch"
# Capture added source without credentials or ignored files.
git ls-files --others --exclude-standard > "$artifact/untracked.txt"
if [ -s "$artifact/untracked.txt" ]; then tar -cf "$artifact/untracked.tar" -T "$artifact/untracked.txt"; fi
cargo fmt --check > "$artifact/fmt.log" 2>&1
cargo test --locked > "$artifact/cargo-test.log" 2>&1
cargo clippy --locked --all-targets --all-features -- -D warnings > "$artifact/clippy.log" 2>&1
cargo build --locked --bin uniclipboard-relay --example relay_probe > "$artifact/build.log" 2>&1
(cd gateway && go vet ./...) > "$artifact/go-vet.log" 2>&1
(cd gateway && go test -race -count=1 -timeout=120s -json ./...) > "$artifact/e2e.jsonl" 2>&1
printf 'PASS\n' > "$artifact/result.txt"
printf 'Verification artifact: %s\n' "$artifact"
