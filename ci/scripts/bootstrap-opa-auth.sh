#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUTPUT_DIR="${REPO_ROOT}/.cloudsentinel"
OUTPUT_FILE="${OUTPUT_DIR}/opa_auth_config.json"

mkdir -p "${OUTPUT_DIR}"

if [[ -z "${OPA_AUTH_TOKEN:-}" ]]; then
  OPA_AUTH_TOKEN="$(openssl rand -hex 32 2>/dev/null || head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  echo "[bootstrap] Generated OPA_AUTH_TOKEN (save this in .env or CI variables):"
  echo "[bootstrap]   OPA_AUTH_TOKEN=${OPA_AUTH_TOKEN}"
  echo ""
  export OPA_AUTH_TOKEN
fi

# Validate token minimum length (32 chars = 128 bits minimum entropy)
if [[ "${#OPA_AUTH_TOKEN}" -lt 32 ]]; then
  echo "[bootstrap][ERROR] OPA_AUTH_TOKEN must be at least 32 characters." >&2
  echo "[bootstrap][ERROR] Generate one with: openssl rand -hex 32" >&2
  exit 1
fi

# Write the config file consumed by OPA's system.authz policy via data.opa_config
# The key "opa_config" maps to the OPA data namespace data.opa_config.auth_token
cat > "${OUTPUT_FILE}" <<EOF
{
  "opa_config": {
    "auth_token": "${OPA_AUTH_TOKEN}",
    "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "minimum_entropy_bits": 128
  }
}
EOF

chmod 600 "${OUTPUT_FILE}"
echo "[bootstrap] OPA auth config written to ${OUTPUT_FILE}"
