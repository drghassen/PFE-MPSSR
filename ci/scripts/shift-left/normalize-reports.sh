#!/usr/bin/env bash
set -euo pipefail

export ENVIRONMENT="${CI_ENVIRONMENT_NAME:-dev}"
export CLOUDSENTINEL_EXECUTION_MODE="ci"
export CLOUDSENTINEL_SCHEMA_STRICT="true"
export CLOUDSENTINEL_SCAN_ID="${CLOUDSENTINEL_SCAN_ID:-${CI_COMMIT_SHA:-}}"
export DOJO_URL="${DOJO_URL:-${DEFECTDOJO_URL:-}}"
export DOJO_API_KEY="${DOJO_API_KEY:-${DEFECTDOJO_API_KEY:-${DEFECTDOJO_API_TOKEN:-}}}"
# Optional enterprise PKI bootstrap for DefectDojo TLS.
source ci/scripts/setup-custom-ca.sh

list_input_artifacts() {
  local artifacts=(
    ".cloudsentinel/gitleaks_raw.json"
    ".cloudsentinel/checkov_raw.json"
    "shift-left/trivy/reports/raw/trivy-fs-raw.json"
    "shift-left/trivy/reports/raw/trivy-config-raw.json"
    ".cloudsentinel/cloudinit_analysis.json"
  )
  echo "[normalize-reports][debug] Input artifacts inventory:"
  for file in "${artifacts[@]}"; do
    if [[ -f "$file" ]]; then
      size="$(wc -c < "$file" | tr -d ' ')"
      echo "[normalize-reports][debug] - ${file} size=${size}B"
    else
      echo "[normalize-reports][debug] - ${file} MISSING"
    fi
  done
}

debug_trivy_results_shape() {
  local trivy_files=(
    "shift-left/trivy/reports/raw/trivy-fs-raw.json"
    "shift-left/trivy/reports/raw/trivy-config-raw.json"
  )
  for file in "${trivy_files[@]}"; do
    [[ -f "$file" ]] || continue
    if jq empty "$file" >/dev/null 2>&1; then
      shape="$(jq -r '
        if has("Results") then
          "Results:" + (.Results | type)
        elif has("results") then
          "results:" + (.results | type)
        else
          "Results:<missing>"
        end
      ' "$file" 2>/dev/null || echo "Results:<unknown>")"
      echo "[normalize-reports][debug] - ${file}: ${shape}"
    fi
  done
}

log_scan_id_propagation() {
  local include_golden="${1:-false}"
  local files=(
    ".cloudsentinel/gitleaks_raw.json"
    ".cloudsentinel/checkov_raw.json"
    "shift-left/trivy/reports/raw/trivy-fs-raw.json"
    "shift-left/trivy/reports/raw/trivy-config-raw.json"
    ".cloudsentinel/cloudinit_analysis.json"
  )
  if [[ "$include_golden" == "true" ]]; then
    files+=(".cloudsentinel/golden_report.json")
  fi
  echo "[normalize-reports][debug] scan_id propagation:"
  for file in "${files[@]}"; do
    [[ -f "$file" ]] || continue
    if jq empty "$file" >/dev/null 2>&1; then
      sid="$(jq -r '.scan_id // .metadata.scan_id // .scan_metadata.scan_id // ""' "$file" 2>/dev/null || true)"
      st="$(jq -r '.scan_status // ""' "$file" 2>/dev/null || true)"
      echo "[normalize-reports][debug] - ${file}: scan_id=${sid:-<missing>} scan_status=${st:-<n/a>}"
    else
      echo "[normalize-reports][debug] - ${file}: INVALID_JSON"
    fi
  done
}

run_detection_contract_check() {
  local expected_scan_id="${CLOUDSENTINEL_SCAN_ID:-${CI_COMMIT_SHA:-}}"
  local cmd=(
    python3 ci/libs/cloudsentinel_contracts.py validate-artifact-contract
    --contract ci/contracts/artifact_contract.json
    --report-output .cloudsentinel/artifact_contract_report.json
    --golden-schema shift-left/normalizer/schema/cloudsentinel_report.schema.json
    --stage detection
  )
  if [[ -n "${expected_scan_id}" ]]; then
    cmd+=(--expected-scan-id "${expected_scan_id}")
  fi

  set +e
  "${cmd[@]}"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "[normalize-reports][ERROR] Detection artifact contract failed." >&2
    if [[ -f .cloudsentinel/artifact_contract_report.json ]]; then
      jq -r '
        .errors[]? as $e | "[normalize-reports][contract-error] " + $e
      ' .cloudsentinel/artifact_contract_report.json 2>/dev/null || true
      jq -r '
        .stages[]? as $s
        | $s.artifacts[]?
        | select(.status != "passed")
        | "[normalize-reports][contract-failed] " + (.id // "unknown") + " -> " + ((.errors // []) | join(", "))
      ' .cloudsentinel/artifact_contract_report.json 2>/dev/null || true
    fi
    exit "$rc"
  fi
}

list_input_artifacts
debug_trivy_results_shape
log_scan_id_propagation false
run_detection_contract_check
python3 shift-left/normalizer/normalize.py
jq '.summary' .cloudsentinel/golden_report.json
jq '.quality_gate' .cloudsentinel/golden_report.json
log_scan_id_propagation true

if ! jq -e '
  type == "object"
  and ((.scan_id // "") | type == "string" and length > 0)
  and ((.scan_status // "") | type == "string")
  and (.findings | type == "array")
  and (.metadata | type == "object")
  and (.metadata.executed_scanners | type == "array" and length > 0)
  and (.metadata.timestamp | type == "string" and length > 0)
' .cloudsentinel/golden_report.json >/dev/null 2>&1; then
  echo "[normalize-reports][ERROR] golden_report.json is invalid or missing mandatory execution fields." >&2
  exit 1
fi

# --- Artifact integrity: sign golden_report.json with HMAC-SHA256 ---
# The .hmac sidecar is passed as an artifact and verified by opa-decision
# before golden_report.json is fed to OPA — prevents artifact substitution
# on a compromised runner.
if [[ -n "${CLOUDSENTINEL_HMAC_SECRET:-}" ]]; then
  python3 ci/scripts/shift-left/artifact_hmac.py sign .cloudsentinel/golden_report.json
elif [[ -n "${CI:-}" ]]; then
  echo "[normalize-reports][ERROR] CLOUDSENTINEL_HMAC_SECRET is not set in CI." >&2
  echo "[normalize-reports][ERROR] Add it as a masked+protected variable in Settings → CI/CD → Variables." >&2
  exit 1
else
  echo "[normalize-reports][WARN] CLOUDSENTINEL_HMAC_SECRET not set — skipping HMAC signing (non-CI mode)."
fi

if [[ -n "${CI:-}" ]] && [[ ! -s .cloudsentinel/golden_report.json.hmac ]]; then
  echo "[normalize-reports][ERROR] HMAC sidecar missing or empty after signing." >&2
  exit 1
fi
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
    jq -nc \
      --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --arg scan_id "${CLOUDSENTINEL_SCAN_ID:-${CI_COMMIT_SHA:-unknown}}" \
      '{
        timestamp: $ts,
        scan_id: $scan_id,
        source: "defectdojo",
        action: "normalize_exception_summary",
        status: "degraded",
        reason: "defectdojo_unreachable"
      }' > .cloudsentinel/audit_events.jsonl
  fi
fi

if [[ -f .cloudsentinel/exceptions.json ]]; then
  VALID_EXCEPTIONS="$(jq -r '.cloudsentinel.exceptions.metadata.total_valid_exceptions // 0' .cloudsentinel/exceptions.json)"
  DROPPED_EXCEPTIONS="$(jq -r '.cloudsentinel.exceptions.metadata.total_dropped // 0' .cloudsentinel/exceptions.json)"
  echo "[exceptions] valid=${VALID_EXCEPTIONS} dropped=${DROPPED_EXCEPTIONS}"
fi

if [[ ! -s .cloudsentinel/audit_events.jsonl ]]; then
  echo "[normalize-reports][ERROR] Missing or empty audit_events.jsonl" >&2
  exit 1
fi

python3 - <<'PY'
import json
import sys
from pathlib import Path

path = Path(".cloudsentinel/audit_events.jsonl")
count = 0
with path.open("r", encoding="utf-8") as handle:
    for idx, raw in enumerate(handle, start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception as exc:
            print(f"[normalize-reports][ERROR] audit_events.jsonl invalid at line {idx}: {exc}", file=sys.stderr)
            sys.exit(1)
        if not isinstance(obj, dict):
            print(f"[normalize-reports][ERROR] audit_events.jsonl line {idx} is not a JSON object", file=sys.stderr)
            sys.exit(1)
        count += 1

if count == 0:
    print("[normalize-reports][ERROR] audit_events.jsonl has no JSON events", file=sys.stderr)
    sys.exit(1)
print(f"[normalize-reports][debug] audit_events.jsonl valid entries={count}")
PY
