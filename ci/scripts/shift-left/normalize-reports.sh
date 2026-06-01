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
source ci/scripts/shift-left/audit-utils.sh
trap 'cloudsentinel_finalize_audit "$?" "normalize-reports" "normalize" "normalizer" ".cloudsentinel/gitleaks_raw.json" ".cloudsentinel/gitleaks_head_raw.json" ".cloudsentinel/gitleaks_range_raw.json" ".cloudsentinel/checkov_raw.json" "shift-left/trivy/reports/raw/trivy-fs-raw.json" ".cloudsentinel/cloudinit_analysis.json" ".cloudsentinel/golden_report.json" ".cloudsentinel/exceptions.json" ".cloudsentinel/dropped_exceptions.json" ".cloudsentinel/audit_events.jsonl" ".cloudsentinel/artifact_contract_report.json"' EXIT

line() {
  printf '%s\n' '==============================================================================='
}

print_header() {
  line
  printf 'CloudSentinel Normalization\n'
  line
  printf 'Purpose : Normalize scanner outputs into the Golden Report before OPA decision\n'
  printf 'Scope   : Gitleaks + Checkov + Trivy + Cloud-init\n'
  printf 'Mode    : fail-closed schema and artifact integrity contract\n'
  printf 'Report  : .cloudsentinel/golden_report.json\n'
  line
}

list_input_artifacts() {
  local artifacts=(
	    ".cloudsentinel/gitleaks_raw.json"
	    ".cloudsentinel/gitleaks_head_raw.json"
	    ".cloudsentinel/gitleaks_range_raw.json"
	    ".cloudsentinel/checkov_raw.json"
    "shift-left/trivy/reports/raw/trivy-fs-raw.json"
    ".cloudsentinel/cloudinit_analysis.json"
  )
  line
  printf 'Input Artifact Inventory\n'
  line
  printf '%-36s %-10s %-12s %s\n' 'Artifact' 'Status' 'Size' 'Path'
  printf '%-36s %-10s %-12s %s\n' '--------' '------' '----' '----'
  for file in "${artifacts[@]}"; do
    if [[ -f "$file" ]]; then
      size="$(wc -c < "$file" | tr -d ' ')"
      artifact="$(basename "$file")"
      printf '%-36s %-10s %-12s %s\n' "${artifact}" "present" "${size}B" "${file}"
    else
      artifact="$(basename "$file")"
      printf '%-36s %-10s %-12s %s\n' "${artifact}" "missing" "-" "${file}"
    fi
  done
}

debug_trivy_results_shape() {
  local trivy_files=(
    "shift-left/trivy/reports/raw/trivy-fs-raw.json"
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
      echo "[normalize-reports][debug] ${file}: ${shape}"
    fi
  done
}

log_scan_id_propagation() {
  local include_golden="${1:-false}"
  local files=(
	    ".cloudsentinel/gitleaks_raw.json"
	    ".cloudsentinel/gitleaks_head_raw.json"
	    ".cloudsentinel/gitleaks_range_raw.json"
	    ".cloudsentinel/checkov_raw.json"
    "shift-left/trivy/reports/raw/trivy-fs-raw.json"
    ".cloudsentinel/cloudinit_analysis.json"
  )
  if [[ "$include_golden" == "true" ]]; then
    files+=(".cloudsentinel/golden_report.json")
  fi
  line
  printf 'Scan ID Propagation\n'
  line
  printf '%-36s %-12s %s\n' 'Artifact' 'Status' 'scan_id'
  printf '%-36s %-12s %s\n' '--------' '------' '-------'
  for file in "${files[@]}"; do
    [[ -f "$file" ]] || continue
    if jq empty "$file" >/dev/null 2>&1; then
      sid="$(jq -r '.scan_id // .metadata.scan_id // .scan_metadata.scan_id // ""' "$file" 2>/dev/null || true)"
      st="$(jq -r '.scan_status // ""' "$file" 2>/dev/null || true)"
      printf '%-36s %-12s %s\n' "$(basename "$file")" "${st:-n/a}" "${sid:-<missing>}"
    else
      printf '%-36s %-12s %s\n' "$(basename "$file")" "invalid" "INVALID_JSON"
    fi
  done
}

print_normalization_summary() {
  python3 - <<'PY'
import json
from pathlib import Path

report_path = Path(".cloudsentinel/golden_report.json")

def line():
    print("=" * 79)

def sev(stats, key):
    return int(stats.get(key, 0) or 0)

def display_result(status):
    status = str(status or "NOT_RUN").upper()
    if status == "FAILED":
        return "FINDINGS"
    if status == "PASSED":
        return "CLEAN"
    return status

with report_path.open(encoding="utf-8") as handle:
    report = json.load(handle)

metadata = report.get("metadata", {})
summary = report.get("summary", {})
by_tool = summary.get("by_tool", {})
findings = report.get("findings", [])

line()
print("Normalization Result Summary")
line()
print(f"Status              : {report.get('scan_status', 'unknown')}")
print(f"Environment         : {metadata.get('environment', 'unknown')}")
print(f"Execution mode      : {metadata.get('execution', {}).get('mode', 'unknown')}")
print(f"Golden Report       : {report_path}")
print(f"Correlation scan_id : {report.get('scan_id', '<missing>')}")
print(f"Executed scanners   : {', '.join(metadata.get('executed_scanners', [])) or '<none>'}")
line()
print("Scanner Normalization Summary")
line()
print(f"{'Scanner':<12} {'Result':<10} {'Total':>6} {'Critical':>9} {'High':>7} {'Medium':>8} {'Low':>7}")
print(f"{'-------':<12} {'------':<10} {'-----':>6} {'--------':>9} {'----':>7} {'------':>8} {'---':>7}")
for scanner in ("gitleaks", "checkov", "trivy", "cloudinit"):
    stats = by_tool.get(scanner, {})
    print(
        f"{scanner:<12} {display_result(stats.get('status', 'NOT_RUN')):<10} "
        f"{sev(stats, 'TOTAL'):>6} {sev(stats, 'CRITICAL'):>9} "
        f"{sev(stats, 'HIGH'):>7} {sev(stats, 'MEDIUM'):>8} {sev(stats, 'LOW'):>7}"
    )

def read_json(path):
    p = Path(path)
    if not p.is_file():
        return None, "missing"
    try:
        with p.open(encoding="utf-8") as handle:
            return json.load(handle), "present"
    except Exception:
        return None, "invalid"

def tool_findings(tool):
    return [
        f for f in findings
        if f.get("source", {}).get("tool") == tool
        and not f.get("context", {}).get("deduplication", {}).get("is_duplicate", False)
    ]

def count_checkov_raw(path=".cloudsentinel/checkov_raw.json"):
    doc, status = read_json(path)
    if status != "present":
        return status
    results = doc.get("results", {}) if isinstance(doc, dict) else {}
    failed = results.get("failed_checks", []) if isinstance(results, dict) else []
    return str(len(failed)) if isinstance(failed, list) else "invalid"

def count_trivy_doc(doc):
    if not isinstance(doc, dict):
        return 0
    total = 0
    for result in doc.get("Results", []) if isinstance(doc.get("Results"), list) else []:
        if not isinstance(result, dict):
            continue
        vulns = result.get("Vulnerabilities", [])
        if isinstance(vulns, list):
            total += len([v for v in vulns if isinstance(v, dict)])
        misconfigs = result.get("Misconfigurations", [])
        if isinstance(misconfigs, list):
            total += len([
                m for m in misconfigs
                if isinstance(m, dict)
                and str(m.get("Status", "")).upper() in {"FAILURE", "FAIL", "EXCEPTION"}
            ])
    return total

def count_trivy_raw(path):
    doc, status = read_json(path)
    if status != "present":
        return status
    return str(count_trivy_doc(doc))

def count_trivy_image_raw():
    image_dir = Path("shift-left/trivy/reports/raw/image")
    if not image_dir.is_dir():
        return "missing"
    files = sorted(image_dir.glob("trivy-image-*-raw.json"))
    if not files:
        return "missing"
    total = 0
    invalid = False
    for file in files:
        doc, status = read_json(file)
        if status != "present":
            invalid = True
            continue
        total += count_trivy_doc(doc)
    return "invalid" if invalid else str(total)

def sum_counts(*values):
    nums = []
    markers = []
    for value in values:
        text = str(value)
        if text.isdigit():
            nums.append(int(text))
        else:
            markers.append(text)
    if nums and not markers:
        return str(sum(nums))
    if nums:
        return f"{sum(nums)}+{','.join(markers)}"
    return ",".join(markers) if markers else "0"

def count_cloudinit_raw(path=".cloudsentinel/cloudinit_analysis.json"):
    doc, status = read_json(path)
    if status != "present":
        return status
    resources = doc.get("resources_analyzed", []) if isinstance(doc, dict) else []
    if not isinstance(resources, list):
        return "invalid"
    total = 0
    for resource in resources:
        if not isinstance(resource, dict):
            continue
        violations = resource.get("violations", [])
        if isinstance(violations, list):
            total += len([v for v in violations if isinstance(v, dict)])
    return str(total)

line()
print("Scanner Detection Scope")
line()
print(f"{'Scanner / level':<24} {'Raw':>12} {'Normalized':>12} {'OPA signal':<18} {'Meaning'}")
print(f"{'---------------':<24} {'---':>12} {'----------':>12} {'----------':<18} {'-------'}")
print(
    f"{'checkov IaC':<24} {count_checkov_raw():>12} "
    f"{len(tool_findings('checkov')):>12} {'threshold input':<18} Terraform/IaC misconfiguration"
)
trivy_fs_raw = count_trivy_raw("shift-left/trivy/reports/raw/trivy-fs-raw.json")
trivy_image_raw = count_trivy_image_raw()
trivy_total_raw = sum_counts(trivy_fs_raw, trivy_image_raw)
print(
    f"{'trivy fs raw':<24} {trivy_fs_raw:>12} "
    f"{'-':>12} {'evidence':<18} filesystem dependencies and config"
)
print(
    f"{'trivy image raw':<24} {trivy_image_raw:>12} "
    f"{'-':>12} {'evidence':<18} container image vulnerabilities"
)
print(
    f"{'trivy aggregate':<24} {trivy_total_raw:>12} "
    f"{len(tool_findings('trivy')):>12} {'threshold input':<18} normalized Trivy findings for OPA"
)
print(
    f"{'cloud-init':<24} {count_cloudinit_raw():>12} "
    f"{len(tool_findings('cloudinit')):>12} {'intent rules':<18} VM bootstrap and role-spoofing signals"
)

gitleaks_findings = [
    f for f in findings
    if f.get("source", {}).get("tool") == "gitleaks"
    and not f.get("context", {}).get("deduplication", {}).get("is_duplicate", False)
]
current_tree = [
    f for f in gitleaks_findings
    if f.get("context", {}).get("git", {}).get("present_in_head") is True
]
latest_push = [
    f for f in gitleaks_findings
    if f.get("context", {}).get("git", {}).get("in_latest_push") is True
]
historical_only = [
    f for f in gitleaks_findings
    if f.get("context", {}).get("git", {}).get("present_in_head") is False
    and f.get("context", {}).get("git", {}).get("in_latest_push") is False
]
blocking = [
    f
    for f in gitleaks_findings
    if f.get("context", {}).get("git", {}).get("present_in_head") is True
    or f.get("context", {}).get("git", {}).get("in_latest_push") is True
]

def raw_count(path):
    p = Path(path)
    if not p.is_file():
        return "missing"
    try:
        with p.open(encoding="utf-8") as handle:
            doc = json.load(handle)
        if isinstance(doc, list):
            return str(len(doc))
        if isinstance(doc, dict):
            return str(len(doc.get("findings", [])))
        return "invalid"
    except Exception:
        return "invalid"

line()
print("Gitleaks Detection Scope")
line()
print(f"{'Level':<22} {'Raw':>8} {'Normalized':>12} {'OPA signal':<14} {'Meaning'}")
print(f"{'-----':<22} {'---':>8} {'----------':>12} {'----------':<14} {'-------'}")
print(
    f"{'full history + merge':<22} {raw_count('.cloudsentinel/gitleaks_raw.json'):>8} "
    f"{len(gitleaks_findings):>12} {'audit':<14} complete evidence set"
)
print(
    f"{'current tree / HEAD':<22} {raw_count('.cloudsentinel/gitleaks_head_raw.json'):>8} "
    f"{len(current_tree):>12} {'blocking':<14} secret still present in code"
)
print(
    f"{'latest push / MR':<22} {raw_count('.cloudsentinel/gitleaks_range_raw.json'):>8} "
    f"{len(latest_push):>12} {'blocking':<14} secret introduced by latest change"
)
print(
    f"{'historical only':<22} {'-':>8} "
    f"{len(historical_only):>12} {'advisory':<14} old finding no longer active"
)
line()
print(f"Gitleaks OPA blocking set : {len(blocking)} finding(s)")
print("Decision ownership        : normalization labels scope; OPA alone returns ALLOW/DENY")
line()
PY
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

print_header
list_input_artifacts
debug_trivy_results_shape
log_scan_id_propagation false
run_detection_contract_check
python3 shift-left/normalizer/normalize.py
print_normalization_summary
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

# --- Defense-in-depth: full JSON schema validation BEFORE signing with HMAC ---
# normalize.py validates its in-memory dict before writing, but that guard can
# be bypassed when jsonschema is not installed and CLOUDSENTINEL_SCHEMA_STRICT
# is false. This independent check guarantees the HMAC is NEVER applied to a
# schema-invalid artifact, regardless of what happened inside normalize.py.
python3 - <<'PY'
import json, sys
from pathlib import Path

schema_file = Path("shift-left/normalizer/schema/cloudsentinel_report.schema.json")
report_file = Path(".cloudsentinel/golden_report.json")

if not schema_file.is_file():
    print(f"[normalize-reports][ERROR] Schema file missing: {schema_file}", file=sys.stderr)
    sys.exit(1)
if not report_file.is_file():
    print(f"[normalize-reports][ERROR] Golden report missing: {report_file}", file=sys.stderr)
    sys.exit(1)

try:
    from jsonschema import Draft7Validator, validate
except ImportError:
    print(
        "[normalize-reports][ERROR] jsonschema not installed — cannot validate golden report "
        "before HMAC signing. Install with: pip install jsonschema",
        file=sys.stderr,
    )
    sys.exit(1)

with schema_file.open(encoding="utf-8") as fh:
    schema = json.load(fh)
with report_file.open(encoding="utf-8") as fh:
    report = json.load(fh)

try:
    Draft7Validator.check_schema(schema)
    validate(report, schema)
    print("[normalize-reports][schema] Golden report validated against JSON schema: OK")
except Exception as exc:
    print(
        f"[normalize-reports][ERROR] Schema validation failed — refusing to sign with HMAC: {exc}",
        file=sys.stderr,
    )
    sys.exit(1)
PY

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
# Exception fetch with configurable timeout and retry.
# A transient DefectDojo blip should not kill the whole pipeline — the retry
# loop gives the service a chance to recover before applying fail-closed logic.
_EXCEPTION_TIMEOUT="${CLOUDSENTINEL_EXCEPTION_FETCH_TIMEOUT:-30}"
_EXCEPTION_RETRIES="${CLOUDSENTINEL_EXCEPTION_FETCH_RETRIES:-2}"
_EXCEPTION_RETRY_DELAY="${CLOUDSENTINEL_EXCEPTION_RETRY_DELAY:-5}"

_fetch_ok=false
for _attempt in $(seq 1 "${_EXCEPTION_RETRIES}"); do
  echo "[normalize-reports][exceptions] Fetch attempt ${_attempt}/${_EXCEPTION_RETRIES} (timeout=${_EXCEPTION_TIMEOUT}s)"
  if timeout "${_EXCEPTION_TIMEOUT}" python3 shift-left/opa/fetch-exceptions.py; then
    _fetch_ok=true
    break
  fi
  if [[ "${_attempt}" -lt "${_EXCEPTION_RETRIES}" ]]; then
    echo "[normalize-reports][WARN] Exceptions fetch attempt ${_attempt} failed — retrying in ${_EXCEPTION_RETRY_DELAY}s" >&2
    sleep "${_EXCEPTION_RETRY_DELAY}"
  fi
done

if [[ "${_fetch_ok}" != "true" ]]; then
  if [ "${CLOUDSENTINEL_FAIL_CLOSED:-true}" = "true" ]; then
    echo "[normalize-reports][ERROR] Exceptions fetch failed after ${_EXCEPTION_RETRIES} attempt(s). CLOUDSENTINEL_FAIL_CLOSED=true. Halting." >&2
    echo "[normalize-reports][ERROR] Set CLOUDSENTINEL_EXCEPTION_FETCH_TIMEOUT / CLOUDSENTINEL_EXCEPTION_FETCH_RETRIES to tune retry behaviour." >&2
    exit 1
  else
    echo "[normalize-reports][WARN] Exceptions fetch failed after ${_EXCEPTION_RETRIES} attempt(s). Entering DEGRADED mode."
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
