#!/usr/bin/env bash
set -euo pipefail

# ── Argument parsing ──────────────────────────────────────────────────────────
TFPLAN_PATH=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tfplan)
      TFPLAN_PATH="$2"
      shift 2
      ;;
    *)
      echo "[normalize-reports][WARN] Unknown argument: $1" >&2
      shift
      ;;
  esac
done

chmod +x shift-left/normalizer/normalize.py
export ENVIRONMENT="${CI_ENVIRONMENT_NAME:-dev}"
export CLOUDSENTINEL_EXECUTION_MODE="ci"
export CLOUDSENTINEL_SCHEMA_STRICT="true"
export DOJO_URL="${DOJO_URL:-${DEFECTDOJO_URL:-}}"
export DOJO_API_KEY="${DOJO_API_KEY:-${DEFECTDOJO_API_KEY:-${DEFECTDOJO_API_TOKEN:-}}}"

if [[ -n "${TFPLAN_PATH}" ]]; then
  export TERRAFORM_PLAN_JSON="${TFPLAN_PATH}"
  echo "[normalize-reports][INFO] TERRAFORM_PLAN_JSON=${TERRAFORM_PLAN_JSON}"
fi

python3 shift-left/normalizer/normalize.py
jq '.summary' .cloudsentinel/golden_report.json
jq '.quality_gate' .cloudsentinel/golden_report.json
if ! timeout 30 python3 shift-left/opa/fetch-exceptions.py; then
  if [ "${CLOUDSENTINEL_FAIL_CLOSED:-true}" = "true" ]; then
    echo "[normalize-reports][ERROR] Exceptions fetch failed/timed out. CLOUDSENTINEL_FAIL_CLOSED=true. Halting." >&2
    exit 1
  else
    echo "[normalize-reports][WARN] Exceptions fetch failed/timed out. Entering DEGRADED mode."
    cat > .cloudsentinel/exceptions.json <<'EOF'
{
  "cloudsentinel": {
    "exceptions": {
      "metadata": {
        "mode": "DEGRADED",
        "reason": "defectdojo_unreachable",
        "component": "shift-left",
        "total_valid_exceptions": 0,
        "total_dropped": 0
      },
      "exceptions": []
    }
  }
}
EOF
  fi
fi

if [[ -f .cloudsentinel/exceptions.json ]]; then
  VALID_EXCEPTIONS="$(jq -r '.cloudsentinel.exceptions.metadata.total_valid_exceptions // 0' .cloudsentinel/exceptions.json)"
  DROPPED_EXCEPTIONS="$(jq -r '.cloudsentinel.exceptions.metadata.total_dropped // 0' .cloudsentinel/exceptions.json)"
  echo "[exceptions] valid=${VALID_EXCEPTIONS} dropped=${DROPPED_EXCEPTIONS}"
fi
