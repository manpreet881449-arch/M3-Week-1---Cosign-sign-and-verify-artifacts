#!/usr/bin/env bash
set -euo pipefail

IMAGE="${1:?Usage: $0 <repo@sha256:digest>}"
COSIGN_IDENTITY="${COSIGN_IDENTITY:-manpreet.881449@gmail.com}"
COSIGN_ISSUER="${COSIGN_ISSUER:-https://github.com/login/oauth}"
SBOM_TYPE="${SBOM_TYPE:-cyclonedx}"
TF_DIR="${TF_DIR:-terraform}"

if [ -z "${BASE_IMAGE:-}" ] && [ -f app/Dockerfile ]; then
  BASE_IMAGE=$(grep -m1 -i '^FROM ' app/Dockerfile | awk '{print $2}' || true)
fi
BASE_IMAGE="${BASE_IMAGE:-}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

FLAGS=""
case "$IMAGE" in
  localhost:*) FLAGS="--allow-insecure-registry"; export GRYPE_REGISTRY_INSECURE_USE_HTTP=true ;;
esac

if cosign verify $FLAGS \
     --certificate-identity "$COSIGN_IDENTITY" \
     --certificate-oidc-issuer "$COSIGN_ISSUER" \
     "$IMAGE" >/dev/null 2>&1; then SIGNED=true; else SIGNED=false; fi

if cosign verify-attestation $FLAGS --type "$SBOM_TYPE" \
     --certificate-identity "$COSIGN_IDENTITY" \
     --certificate-oidc-issuer "$COSIGN_ISSUER" \
     "$IMAGE" >/dev/null 2>&1; then SBOM_OK=true; else SBOM_OK=false; fi

grype "$IMAGE" -o json > "$WORK/grype.json"
CRIT=$(jq '[.matches[] | select(.vulnerability.severity=="Critical")] | length' "$WORK/grype.json")

if [ -d "$TF_DIR" ] && trivy config --exit-code 1 --severity HIGH,CRITICAL "$TF_DIR" >/dev/null 2>&1; then
  TF_OK=true
else
  TF_OK=false
fi

jq -n --arg image "$IMAGE" --arg base "$BASE_IMAGE" \
  --argjson signed "$SIGNED" --argjson sbom "$SBOM_OK" \
  --argjson crit "$CRIT" --argjson tf "$TF_OK" \
  '{image:$image, signature_verified:$signed, sbom_attested:$sbom,
    base_image:$base, terraform_scan_passed:$tf,
    vulnerabilities:{critical:$crit}}' > "$WORK/input.json"
echo "OPA input:"; cat "$WORK/input.json"

ALLOW=$(opa eval -f raw -i "$WORK/input.json" -d policy/ "data.deploy.allow")
if [ "$ALLOW" != "true" ]; then
  echo "DENIED:"
  opa eval -f pretty -i "$WORK/input.json" -d policy/ "data.deploy.deny"
  exit 1
fi
echo "ALLOWED: $IMAGE"
