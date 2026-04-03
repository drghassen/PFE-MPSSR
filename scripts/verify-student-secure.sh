#!/usr/bin/env bash
set -euo pipefail

TARGET_DIR="${1:-infra/azure/student-secure}"
TRIVY_IMAGE_TARGET="${2:-alpine:3.21}"

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

OUT_DIR="$REPO_ROOT/.cloudsentinel"
mkdir -p "$OUT_DIR"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[verify][ERROR] missing dependency: $1" >&2
    exit 2
  }
}

need jq
need python3
need gitleaks
need checkov
need trivy
need opa

emit_not_run_contract() {
  local tool="$1"
  local out_file="$2"
  local reason="$3"
  jq -n \
    --arg tool "$tool" \
    --arg reason "$reason" \
    '{
      tool: $tool,
      version: "unknown",
      status: "NOT_RUN",
      findings: [],
      errors: [$reason],
      has_findings: false,
      stats: {
        CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0,
        TOTAL: 0, EXEMPTED: 0, FAILED: 0, PASSED: 0
      }
    }' >"$out_file"
}

echo "[verify] target dir: $TARGET_DIR"
if [[ ! -d "$TARGET_DIR" ]]; then
  echo "[verify][ERROR] target directory not found: $TARGET_DIR" >&2
  exit 2
fi

tmp_gitleaks="$(mktemp -t gitleaks-student.XXXXXX.json)"
trap 'rm -f "$tmp_gitleaks"' EXIT

echo "[verify] gitleaks scan..."
set +e
gitleaks detect \
  --source "$TARGET_DIR" \
  --no-git \
  --redact \
  --config "$REPO_ROOT/shift-left/gitleaks/gitleaks.toml" \
  --report-format json \
  --report-path "$tmp_gitleaks"
gleaks_rc=$?
set -e

if [[ "$gleaks_rc" -gt 1 ]]; then
  emit_not_run_contract "gitleaks" "$OUT_DIR/gitleaks_opa.json" "gitleaks_execution_error:rc=$gleaks_rc"
else
  if ! jq -e 'type == "array"' "$tmp_gitleaks" >/dev/null 2>&1; then
    emit_not_run_contract "gitleaks" "$OUT_DIR/gitleaks_opa.json" "gitleaks_invalid_json"
  else
    jq '
      def sev(x):
        if (x|type) != "string" then "MEDIUM"
        else (x|ascii_upcase) as $s
        | if ($s=="CRITICAL" or $s=="HIGH" or $s=="MEDIUM" or $s=="LOW" or $s=="INFO") then $s else "MEDIUM" end
        end;

      map({
        rule_id: (.RuleID // "unknown"),
        description: (.Description // "unknown"),
        file: (.File // "unknown"),
        start_line: (.StartLine // 0),
        severity: sev(.Severity // "MEDIUM"),
        fingerprint: (.Fingerprint // ("fp:" + (.RuleID // "unknown") + "|" + (.File // "unknown") + "|" + ((.StartLine // 0)|tostring))),
        secret: "REDACTED"
      }) as $f
      | {
          tool: "gitleaks",
          version: "local",
          status: "OK",
          errors: [],
          has_findings: (($f|length) > 0),
          stats: {
            CRITICAL: ($f | map(select(.severity=="CRITICAL")) | length),
            HIGH: ($f | map(select(.severity=="HIGH")) | length),
            MEDIUM: ($f | map(select(.severity=="MEDIUM")) | length),
            LOW: ($f | map(select(.severity=="LOW")) | length),
            INFO: ($f | map(select(.severity=="INFO")) | length),
            TOTAL: ($f|length),
            EXEMPTED: 0,
            FAILED: ($f|length),
            PASSED: 0
          },
          findings: $f
        }
    ' "$tmp_gitleaks" >"$OUT_DIR/gitleaks_opa.json"
  fi
fi

echo "[verify] checkov scan..."
bash "$REPO_ROOT/shift-left/checkov/run-checkov.sh" "$TARGET_DIR"

echo "[verify] trivy fs/config/image scans..."
bash "$REPO_ROOT/shift-left/trivy/scripts/run-trivy.sh" "$TARGET_DIR" "fs"
cp "$OUT_DIR/trivy_opa.json" "$OUT_DIR/trivy_fs_opa.json"

bash "$REPO_ROOT/shift-left/trivy/scripts/run-trivy.sh" "$TARGET_DIR" "config"
cp "$OUT_DIR/trivy_opa.json" "$OUT_DIR/trivy_config_opa.json"

bash "$REPO_ROOT/shift-left/trivy/scripts/run-trivy.sh" "$TRIVY_IMAGE_TARGET" "image"
cp "$OUT_DIR/trivy_opa.json" "$OUT_DIR/trivy_image_opa.json"

echo "[verify] merge trivy reports..."
python3 - <<'PY'
import json
from pathlib import Path

root = Path(".cloudsentinel")
reports = {
    "fs": root / "trivy_fs_opa.json",
    "config": root / "trivy_config_opa.json",
    "image": root / "trivy_image_opa.json",
}
loaded = {}
for name, path in reports.items():
    if not path.exists():
        loaded[name] = {"status": "NOT_RUN", "errors": [f"missing_report:{path}"], "findings": [], "stats": {"TOTAL": 0}}
        continue
    try:
        loaded[name] = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        loaded[name] = {"status": "NOT_RUN", "errors": [f"invalid_json:{path}"], "findings": [], "stats": {"TOTAL": 0}}

if any(str(r.get("status", "")).upper() == "NOT_RUN" for r in loaded.values()):
    errors = []
    for name, report in loaded.items():
        if str(report.get("status", "")).upper() == "NOT_RUN":
            errs = report.get("errors", [])
            if isinstance(errs, list):
                errors.extend([f"{name}:{e}" for e in errs])
            else:
                errors.append(f"{name}:not_run")
    merged = {
        "tool": "trivy",
        "version": "multi",
        "status": "NOT_RUN",
        "errors": errors or ["trivy_subscan_not_run"],
        "has_findings": False,
        "stats": {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
            "TOTAL": 0, "EXEMPTED": 0, "FAILED": 0, "PASSED": 0,
            "by_type": {"vulnerability": 0, "secret": 0, "misconfig": 0},
            "by_category": {"INFRASTRUCTURE": 0, "APPLICATION": 0, "CONFIGURATION": 0, "SECRET": 0}
        },
        "findings": []
    }
else:
    findings = []
    sev_keys = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "TOTAL", "EXEMPTED", "FAILED", "PASSED"]
    by_type_keys = ["vulnerability", "secret", "misconfig"]
    by_cat_keys = ["INFRASTRUCTURE", "APPLICATION", "CONFIGURATION", "SECRET"]
    stats = {k: 0 for k in sev_keys}
    by_type = {k: 0 for k in by_type_keys}
    by_cat = {k: 0 for k in by_cat_keys}
    for report in loaded.values():
        findings.extend(report.get("findings", []))
        rstats = report.get("stats", {})
        for key in sev_keys:
            stats[key] += int(rstats.get(key, 0) or 0)
        for key in by_type_keys:
            by_type[key] += int((rstats.get("by_type", {}) or {}).get(key, 0) or 0)
        for key in by_cat_keys:
            by_cat[key] += int((rstats.get("by_category", {}) or {}).get(key, 0) or 0)
    stats["by_type"] = by_type
    stats["by_category"] = by_cat
    merged = {
        "tool": "trivy",
        "version": "multi",
        "status": "OK",
        "errors": [],
        "has_findings": len(findings) > 0,
        "stats": stats,
        "findings": findings
    }

(root / "trivy_opa.json").write_text(json.dumps(merged, indent=2), encoding="utf-8")
PY

echo "[verify] strict exceptions payload..."
cat > "$OUT_DIR/exceptions.json" <<'JSON'
{
  "cloudsentinel": {
    "exceptions": {
      "schema_version": "2.0.0",
      "generated_at": "2026-01-01T00:00:00Z",
      "metadata": {
        "source": "verify-student-secure"
      },
      "exceptions": []
    }
  }
}
JSON

echo "[verify] normalize + contract validation..."
export ENVIRONMENT="dev"
export CLOUDSENTINEL_EXECUTION_MODE="ci"
export CLOUDSENTINEL_SCHEMA_STRICT="true"
python3 "$REPO_ROOT/shift-left/normalizer/normalize.py"

python3 - <<'PY'
import json
from jsonschema import Draft7Validator, validate

with open(".cloudsentinel/golden_report.json", "r", encoding="utf-8") as f:
    golden = json.load(f)
with open("shift-left/normalizer/schema/cloudsentinel_report.schema.json", "r", encoding="utf-8") as f:
    golden_schema = json.load(f)
Draft7Validator.check_schema(golden_schema)
validate(golden, golden_schema)

with open(".cloudsentinel/exceptions.json", "r", encoding="utf-8") as f:
    exceptions = json.load(f)
with open("shift-left/opa/schema/exceptions_v2.schema.json", "r", encoding="utf-8") as f:
    exceptions_schema = json.load(f)
Draft7Validator.check_schema(exceptions_schema)
validate(exceptions, exceptions_schema)
PY

echo "[verify] OPA enforce..."
OPA_PREFER_CLI=true bash "$REPO_ROOT/shift-left/opa/run-opa.sh" --enforce

echo "[verify] post-checks: fail-open and redaction..."
jq -e '.scanners | to_entries | all(.value.status != "NOT_RUN")' "$OUT_DIR/golden_report.json" >/dev/null

python3 - <<'PY'
import json
from pathlib import Path

raw_reports = [
    Path("shift-left/trivy/reports/raw/trivy-fs-raw.json"),
    Path("shift-left/trivy/reports/raw/trivy-config-raw.json"),
    Path("shift-left/trivy/reports/raw/trivy-image-raw.json"),
]
for report in raw_reports:
    if not report.exists():
        raise SystemExit(f"missing_trivy_raw_report:{report}")
    payload = json.loads(report.read_text(encoding="utf-8"))
    for result in payload.get("Results", []) or []:
        for secret in result.get("Secrets", []) or []:
            if secret.get("Match") != "REDACTED":
                raise SystemExit(f"secret_not_redacted:{report}")
            if not secret.get("MatchSHA256"):
                raise SystemExit(f"missing_match_sha256:{report}")
print("trivy_redaction_ok")
PY

echo "[verify] SUCCESS - scanners, normalization, contract, and OPA enforcement all passed."
