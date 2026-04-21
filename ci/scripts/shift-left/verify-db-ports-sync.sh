#!/usr/bin/env bash
# CloudSentinel — Policy integrity: DB_PORTS (Python) must match db_ports (Rego).
# Fails CI if drift is detected between:
#   shift-left/normalizer/cs_norm_constants.py
#   policies/opa/gate/gate_context.rego
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
PY_FILE="${REPO_ROOT}/shift-left/normalizer/cs_norm_constants.py"
REGO_FILE="${REPO_ROOT}/policies/opa/gate/gate_context.rego"

_normalize_port_list() {
  # stdin: comma-separated integers; stdout: sorted unique space-separated
  tr ',' '\n' | tr -d ' \r' | grep -E '^[0-9]+$' | sort -n | uniq | paste -sd' ' -
}

_extract_py_ports() {
  # Line: DB_PORTS: frozenset = frozenset({3306, 5432, ...})
  local line
  line="$(grep -F 'DB_PORTS' "$PY_FILE" | grep 'frozenset' | head -1)" || true
  if [[ -z "$line" ]]; then
    echo "[verify-db-ports-sync][ERROR] DB_PORTS line not found in ${PY_FILE}" >&2
    exit 1
  fi
  echo "$line" | sed -n 's/.*frozenset({\([^}]*\)}).*/\1/p' | _normalize_port_list
}

_extract_rego_ports() {
  local line
  line="$(grep -E '^db_ports :=' "$REGO_FILE" | head -1)" || true
  if [[ -z "$line" ]]; then
    echo "[verify-db-ports-sync][ERROR] db_ports line not found in ${REGO_FILE}" >&2
    exit 1
  fi
  echo "$line" | sed -n 's/^db_ports := {\([^}]*\)}.*/\1/p' | _normalize_port_list
}

main() {
  if [[ ! -f "$PY_FILE" ]]; then
    echo "[verify-db-ports-sync][ERROR] Missing ${PY_FILE}" >&2
    exit 1
  fi
  if [[ ! -f "$REGO_FILE" ]]; then
    echo "[verify-db-ports-sync][ERROR] Missing ${REGO_FILE}" >&2
    exit 1
  fi

  local py_ports rego_ports
  py_ports="$(_extract_py_ports)"
  rego_ports="$(_extract_rego_ports)"

  if [[ "$py_ports" != "$rego_ports" ]]; then
    echo "[verify-db-ports-sync][ERROR] DB_PORTS drift detected." >&2
    echo "  Python (cs_norm_constants): ${py_ports}" >&2
    echo "  Rego   (gate_context.rego): ${rego_ports}" >&2
    echo "  Update both sources to the same sorted set of ports." >&2
    exit 1
  fi

  echo "[verify-db-ports-sync][OK] DB_PORTS and db_ports are in sync (${py_ports})"
}

main "$@"
