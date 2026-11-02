#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail

: "${IMAGE_NAME:?}" "${GITHUB_SHA:?}" "${DOCKER_METADATA_OUTPUT_JSON:?}" "${ARTIFACT_DIR:?}"
mkdir -p "$ARTIFACT_DIR"
record_result() {
  status=$?
  if [ "$status" -eq 0 ]; then
    printf 'PASS\n' > "$ARTIFACT_DIR/result.txt"
  else
    printf 'FAIL exit=%s\n' "$status" > "$ARTIFACT_DIR/result.txt"
  fi
}
trap record_result EXIT
printf '%s\n' "$GITHUB_SHA" > "$ARTIFACT_DIR/head.txt"
printf '%s/%s/actions/runs/%s/attempts/%s\n' \
  "$GITHUB_SERVER_URL" "$GITHUB_REPOSITORY" "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" \
  > "$ARTIFACT_DIR/run.txt"
jq -er '.tags | select(length > 0) | .[]' <<< "$DOCKER_METADATA_OUTPUT_JSON" > "$ARTIFACT_DIR/tags.txt"
sha_tag="sha-${GITHUB_SHA:0:7}"
sources=()
for arch in amd64 arm64; do
  source="$IMAGE_NAME:$sha_tag-$arch"
  docker buildx imagetools inspect "$source" > "$ARTIFACT_DIR/source-$arch.txt"
  docker buildx imagetools inspect --raw "$source" > "$ARTIFACT_DIR/source-$arch.json"
  sources+=("$source")
done

args=()
while IFS= read -r tag; do
  args+=(-t "$tag")
done < "$ARTIFACT_DIR/tags.txt"
docker buildx imagetools create "${args[@]}" "${sources[@]}" 2>&1 | tee "$ARTIFACT_DIR/create.log"

baseline=""
while IFS= read -r tag; do
  name="${tag##*:}"
  docker buildx imagetools inspect "$tag" > "$ARTIFACT_DIR/$name.txt"
  docker buildx imagetools inspect --raw "$tag" > "$ARTIFACT_DIR/$name.json"
  jq -e '
    [.manifests[].platform | select(.os != "unknown") | "\(.os)/\(.architecture)"]
    | sort == ["linux/amd64", "linux/arm64"]
  ' "$ARTIFACT_DIR/$name.json" > "$ARTIFACT_DIR/$name-platforms.txt"
  if [ -n "$baseline" ]; then
    cmp "$baseline" "$ARTIFACT_DIR/$name.json"
  fi
  baseline="$ARTIFACT_DIR/$name.json"
  for arch in amd64 arm64; do
    docker pull --platform "linux/$arch" "$tag" 2>&1 | tee "$ARTIFACT_DIR/$name-$arch-pull.log"
    docker image inspect --platform "linux/$arch" "$tag" > "$ARTIFACT_DIR/$name-$arch-image.json"
    jq -e --arg arch "$arch" 'length == 1 and .[0].Os == "linux" and .[0].Architecture == $arch' \
      "$ARTIFACT_DIR/$name-$arch-image.json" > "$ARTIFACT_DIR/$name-$arch-result.txt"
  done
done < "$ARTIFACT_DIR/tags.txt"
