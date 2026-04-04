#!/usr/bin/env bash
set -euo pipefail

TARGET_DIR="${1:-infra/azure/student-secure}"
TRIVY_IMAGE_TARGET="${2:-alpine:3.21}"

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"
source "$REPO_ROOT/shift-left/lib_scanner_utils.sh"

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
  cs_emit_not_run "$tool" "$out_file" "$reason" "$REPO_ROOT"
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
python3 "$REPO_ROOT/ci/libs/cloudsentinel_contracts.py" merge-trivy \
  --fs "$OUT_DIR/trivy_fs_opa.json" \
  --config "$OUT_DIR/trivy_config_opa.json" \
  --image "$OUT_DIR/trivy_image_opa.json" \
  --output "$OUT_DIR/trivy_opa.json"

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

python3 "$REPO_ROOT/ci/libs/cloudsentinel_contracts.py" validate-schema \
  --document "$OUT_DIR/golden_report.json" \
  --schema "$REPO_ROOT/shift-left/normalizer/schema/cloudsentinel_report.schema.json" \
  --success-message "[verify] golden_report schema validation passed"
python3 "$REPO_ROOT/ci/libs/cloudsentinel_contracts.py" validate-schema \
  --document "$OUT_DIR/exceptions.json" \
  --schema "$REPO_ROOT/shift-left/opa/schema/exceptions_v2.schema.json" \
  --success-message "[verify] exceptions schema validation passed"

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
