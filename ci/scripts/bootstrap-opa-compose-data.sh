#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUTPUT_DIR="${REPO_ROOT}/.cloudsentinel"
COMPOSE_DATA_DIR="${OPA_COMPOSE_DATA_DIR:-${REPO_ROOT}/config/opa/data}"

command -v jq >/dev/null 2>&1 || { echo "[bootstrap][ERROR] jq is required"; exit 1; }

mkdir -p "${OUTPUT_DIR}" "${COMPOSE_DATA_DIR}"

_copy_if_valid_json() {
  local src="$1"
  local dst="$2"
  local jq_filter="$3"
  local label="$4"

  if [[ -s "${src}" ]] && jq -e "${jq_filter}" "${src}" >/dev/null 2>&1; then
    cp "${src}" "${dst}"
    echo "[bootstrap] Synced ${label}: ${src} -> ${dst}"
  fi
}

_write_if_missing() {
  local dst="$1"
  local content="$2"
  if [[ ! -s "${dst}" ]]; then
    printf '%s\n' "${content}" > "${dst}"
    echo "[bootstrap] Created ${dst}"
  fi
}

_copy_if_valid_json \
  "${OUTPUT_DIR}/exceptions.json" \
  "${COMPOSE_DATA_DIR}/exceptions.json" \
  'type == "object" and (.cloudsentinel.exceptions.exceptions | type == "array")' \
  "shift-left exceptions"

_copy_if_valid_json \
  "${OUTPUT_DIR}/drift_exceptions.json" \
  "${COMPOSE_DATA_DIR}/drift_exceptions.json" \
  'type == "object" and (.cloudsentinel.drift_exceptions.exceptions | type == "array")' \
  "shift-right drift exceptions"

_copy_if_valid_json \
  "${OUTPUT_DIR}/opa_auth_config.json" \
  "${COMPOSE_DATA_DIR}/opa_auth_config.json" \
  'type == "object" and (.opa_config.auth_token | type == "string")' \
  "OPA auth config"

_write_if_missing \
  "${COMPOSE_DATA_DIR}/exceptions.json" \
  '{"cloudsentinel":{"exceptions":{"schema_version":"2.0.0","generated_at":"2099-01-01T00:00:00Z","metadata":{"source":"compose-bootstrap","total_raw_risk_acceptances":0,"total_valid_exceptions":0,"total_dropped":0},"exceptions":[]}}}'

_write_if_missing \
  "${COMPOSE_DATA_DIR}/drift_exceptions.json" \
  '{"cloudsentinel":{"drift_exceptions":{"schema_version":"1.0.0","generated_at":"2099-01-01T00:00:00Z","metadata":{"source":"compose-bootstrap","total_exceptions":0},"exceptions":[]}}}'

if [[ ! -s "${COMPOSE_DATA_DIR}/opa_auth_config.json" ]]; then
  OPA_AUTH_TOKEN="${OPA_AUTH_TOKEN:-$(openssl rand -hex 32 2>/dev/null || head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
  cat > "${COMPOSE_DATA_DIR}/opa_auth_config.json" <<EOF_INNER
{
  "opa_config": {
    "auth_token": "${OPA_AUTH_TOKEN}",
    "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "source": "compose-bootstrap"
  }
}
EOF_INNER
  echo "[bootstrap] Created ${COMPOSE_DATA_DIR}/opa_auth_config.json"
fi

chmod 600 "${COMPOSE_DATA_DIR}/opa_auth_config.json"

if [[ ! -s "${OUTPUT_DIR}/opa_auth_config.json" ]]; then
  cp "${COMPOSE_DATA_DIR}/opa_auth_config.json" "${OUTPUT_DIR}/opa_auth_config.json"
  chmod 600 "${OUTPUT_DIR}/opa_auth_config.json"
fi

echo "[bootstrap] OPA compose data ready: ${COMPOSE_DATA_DIR}"
