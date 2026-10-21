#!/usr/bin/env bash
set -euo pipefail

IMAGE="${1:?Usage: $0 <registry/image@sha256:digest>}"
DIR="$(cd "$(dirname "$0")" && pwd)"

# Tag allowed nahi, sirf digest (verify aur run me same image ho)
case "$IMAGE" in
  *@sha256:*) ;;
  *) echo "DENIED: image must be referenced by digest (@sha256:...)"; exit 1 ;;
esac

# Gate fail hua to set -e ki wajah se yahin ruk jayega
"$DIR/gate.sh" "$IMAGE"

echo "Gate passed. Starting container..."
docker run -d --read-only --cap-drop=ALL "$IMAGE"
