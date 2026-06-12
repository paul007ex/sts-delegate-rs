#!/usr/bin/env bash
set -euo pipefail

image="${1:-sts-delegate-rs:local}"

docker run --rm "$image" --help >/dev/null

if output="$(docker run --rm "$image" smoke 2>&1)"; then
  echo "expected offline smoke to require IDP_JWKS_FILE, but it passed" >&2
  exit 1
fi

if ! grep -q "offline smoke requires IDP_JWKS_FILE" <<<"$output"; then
  echo "$output" >&2
  exit 1
fi

echo "docker_smoke=pass"
