#!/usr/bin/env bash
set -euo pipefail

IMAGE="${1:?Usage: $0 <image>}"
COSIGN_IDENTITY="${COSIGN_IDENTITY:-manpreet.881449@gmail.com}"
COSIGN_ISSUER="${COSIGN_ISSUER:-https://github.com/login/oauth}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Local HTTP registry ke liye extra flags (sirf lab me)
FLAGS=""
case "$IMAGE" in
  localhost:*) FLAGS="--allow-insecure-registry"; export GRYPE_REGISTRY_INSECURE_USE_HTTP=true ;;
esac

# 1. Verify the signature (fail-closed: koi bhi error = unsigned)
if [ -n "${COSIGN_KEY:-}" ]; then
  VERIFY_ARGS=(--key "$COSIGN_KEY" --insecure-ignore-tlog)
else
  VERIFY_ARGS=(--certificate-identity "$COSIGN_IDENTITY" --certificate-oidc-issuer "$COSIGN_ISSUER")
fi
if cosign verify $FLAGS "${VERIFY_ARGS[@]}" "$IMAGE" >/dev/null 2>&1; then SIGNED=true; else SIGNED=false; fi

# 2. Scan for vulnerabilities
grype "$IMAGE" -o json > "$WORK/grype.json"
CRIT=$(jq '[.matches[] | select(.vulnerability.severity=="Critical")] | length' "$WORK/grype.json")

# 3. Build the OPA input
jq -n --arg image "$IMAGE" --argjson signed "$SIGNED" --argjson crit "$CRIT" \
  '{image:$image, signature_verified:$signed, vulnerabilities:{critical:$crit}}' > "$WORK/input.json"
echo "OPA input:"; cat "$WORK/input.json"

# 4. Ask OPA
ALLOW=$(opa eval -f raw -i "$WORK/input.json" -d policy/ "data.deploy.allow")
if [ "$ALLOW" != "true" ]; then
  echo "DENIED:"
  opa eval -f pretty -i "$WORK/input.json" -d policy/ "data.deploy.deny"
  exit 1
fi
echo "ALLOWED: $IMAGE"
