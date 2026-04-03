#!/usr/bin/env bash
set -euo pipefail

################################################################################
# CloudSentinel - Trivy Orchestrator v7.1
# - Scan types: image | fs | config
# - Produces sanitized OPA-ready JSON
# - Fail-closed on technical/format errors (status=NOT_RUN)
################################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../../lib_scanner_utils.sh"

REPO_ROOT="$(cs_get_repo_root)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

CONFIG_DEFAULT="$BASE_DIR/configs/trivy.yaml"
CONFIG_CI="$BASE_DIR/configs/trivy-ci.yaml"
MAPPING_FILE="$BASE_DIR/configs/severity-mapping.json"

SCAN_IMAGE="$SCRIPT_DIR/scan-image.sh"
SCAN_FS="$SCRIPT_DIR/scan-fs.sh"
SCAN_CONFIG="$SCRIPT_DIR/scan-config.sh"

REPORTS_RAW_DIR="$BASE_DIR/reports/raw"
mkdir -p "$REPORTS_RAW_DIR"

OUT_DIR="$REPO_ROOT/.cloudsentinel"
mkdir -p "$OUT_DIR"
OPA_FINAL_REPORT="$OUT_DIR/trivy_opa.json"

log()  { echo -e "\033[1;34m[CloudSentinel][Trivy]\033[0m $*"; }
warn() { echo -e "\033[1;33m[CloudSentinel][Trivy][WARN]\033[0m $*" >&2; }
err()  { echo -e "\033[1;31m[CloudSentinel][Trivy][ERROR]\033[0m $*" >&2; }

emit_not_run() {
  local reason="$1"
  cs_emit_not_run "trivy" "$OPA_FINAL_REPORT" "$reason" "$REPO_ROOT"
}

if ! command -v jq >/dev/null 2>&1; then
  emit_not_run "jq_binary_missing"
  exit 0
fi

if ! command -v trivy >/dev/null 2>&1; then
  emit_not_run "trivy_binary_missing"
  exit 0
fi

if [[ ! -f "$MAPPING_FILE" ]]; then
  emit_not_run "trivy_mapping_file_missing:$MAPPING_FILE"
  exit 0
fi

SCAN_MODE="${SCAN_MODE:-local}"
[[ -n "${CI:-}" ]] && SCAN_MODE="ci"
export SCAN_MODE

CONFIG_FILE="$CONFIG_DEFAULT"
[[ "$SCAN_MODE" == "ci" ]] && CONFIG_FILE="$CONFIG_CI"

TARGET="${1:-}"
SCAN_TYPE="${2:-}"

if [[ -z "$TARGET" || -z "$SCAN_TYPE" ]]; then
  err "Usage: $0 <target> <scan_type>"
  err "  scan_type: image | fs | config"
  emit_not_run "trivy_invalid_arguments"
  exit 0
fi

export TRIVY_CACHE_DIR="$REPO_ROOT/.trivy-cache"
TRIVY_VERSION="$(trivy --version 2>/dev/null | awk 'NR==1 {print $2}' | tr -d '\r' || echo unknown)"
[[ -z "$TRIVY_VERSION" ]] && TRIVY_VERSION="unknown"

log "Scan type : $SCAN_TYPE"
log "Target    : $TARGET"
log "Mode      : $SCAN_MODE"
log "Config    : $CONFIG_FILE"
log "Cache     : $TRIVY_CACHE_DIR"

set +e
case "$SCAN_TYPE" in
  image)
    bash "$SCAN_IMAGE" "$TARGET"
    RAW_RESULTS="$REPORTS_RAW_DIR/trivy-image-raw.json"
    ;;
  fs)
    bash "$SCAN_FS" "$TARGET"
    RAW_RESULTS="$REPORTS_RAW_DIR/trivy-fs-raw.json"
    ;;
  config)
    bash "$SCAN_CONFIG" "$TARGET"
    RAW_RESULTS="$REPORTS_RAW_DIR/trivy-config-raw.json"
    ;;
  *)
    err "Unknown scan type: '$SCAN_TYPE'. Valid types: image | fs | config"
    emit_not_run "trivy_invalid_scan_type:$SCAN_TYPE"
    exit 0
    ;;
esac
SCAN_RC=$?
set -e

if [[ "$SCAN_RC" -ne 0 ]]; then
  emit_not_run "trivy_subscan_error:rc=$SCAN_RC"
  exit 0
fi

if [[ ! -f "$RAW_RESULTS" ]]; then
  emit_not_run "trivy_raw_output_missing:$RAW_RESULTS"
  exit 0
fi

if ! jq empty "$RAW_RESULTS" >/dev/null 2>&1; then
  emit_not_run "trivy_raw_output_invalid_json:$RAW_RESULTS"
  exit 0
fi

# Secret redaction boundary: raw scanner output is sanitized before any downstream use.
if ! python3 - "$RAW_RESULTS" <<'PY'
import hashlib
import json
import os
import sys

path = sys.argv[1]
tmp = f"{path}.sanitized.tmp"

with open(path, "r", encoding="utf-8") as infile:
    payload = json.load(infile)

for result in payload.get("Results", []) or []:
    secrets = result.get("Secrets")
    if not isinstance(secrets, list):
        continue
    for secret in secrets:
        match = str(secret.get("Match", ""))
        secret["MatchSHA256"] = hashlib.sha256(match.encode("utf-8")).hexdigest()
        secret["Match"] = "REDACTED"
        secret.pop("Code", None)
        secret.pop("Raw", None)

with open(tmp, "w", encoding="utf-8") as outfile:
    json.dump(payload, outfile, separators=(",", ":"))

os.replace(tmp, path)
PY
then
  emit_not_run "trivy_sanitization_failed"
  exit 0
fi

log "Normalizing findings for OPA..."

TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")"
COMMIT="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"

if ! jq -n \
  --arg timestamp "$TIMESTAMP" \
  --arg branch    "$BRANCH" \
  --arg commit    "$COMMIT" \
  --arg version   "$TRIVY_VERSION" \
  --arg scan_type "$SCAN_TYPE" \
  --arg target    "$TARGET" \
  --slurpfile raw     "$RAW_RESULTS" \
  --slurpfile mapping "$MAPPING_FILE" \
'
  ($raw[0].Results // []) as $results
  | ($mapping[0].severity_mapping) as $sev_map
  | ($mapping[0].categories)       as $cat_map
  | ($mapping[0].remediation_sla)  as $sla_map

  | ($results | map(
      . as $result
      | (
          (.Vulnerabilities // [] | map({
            id:           (.VulnerabilityID // "UNKNOWN"),
            resource:     (.PkgName         // "unknown"),
            file:         ($result.Target   // "unknown"),
            description:  (.Title           // .Description // "N/A"),
            severity:     ($sev_map[.Severity | ascii_upcase] // "MEDIUM"),
            category:     ($cat_map[$result.Class // ""] // "UNKNOWN"),
            status:       "FAILED",
            finding_type: "vulnerability",
            fingerprint:  ((.VulnerabilityID // "UNKNOWN") + ":" + (.PkgName // "unknown") + ":" + ($result.Target // "unknown") | @base64),
            metadata: {
              installed_version: (.InstalledVersion // "N/A"),
              fixed_version:     (.FixedVersion     // "N/A"),
              references:        (.References       // [])
            }
          }))

          +

          (.Secrets // [] | map({
            id:           (.RuleID       // "SECRET-UNKNOWN"),
            resource:     (.Category     // "unknown"),
            file:         ($result.Target // "unknown"),
            description:  (.Title        // "Secret detected"),
            severity:     ($sev_map[.Severity | ascii_upcase] // "HIGH"),
            category:     "SECRET",
            status:       "FAILED",
            finding_type: "secret",
            fingerprint:  ((.RuleID // "SECRET-UNKNOWN") + ":" + ($result.Target // "unknown") + ":" + ((.StartLine // 0)|tostring) | @base64),
            metadata: {
              match: "REDACTED",
              match_sha256: (.MatchSHA256 // ""),
              line: (.StartLine // 0),
              end_line: (.EndLine // 0)
            }
          }))

          +

          (.Misconfigurations // [] | map({
            id:           (.ID           // "MISCONFIG-UNKNOWN"),
            resource:     (.Type         // "unknown"),
            file:         ($result.Target // "unknown"),
            description:  (.Title        // .Description // "N/A"),
            severity:     ($sev_map[.Severity | ascii_upcase] // "MEDIUM"),
            category:     "CONFIGURATION",
            status:       "FAILED",
            finding_type: "misconfig",
            fingerprint:  ((.ID // "MISCONFIG-UNKNOWN") + ":" + ($result.Target // "unknown") | @base64),
            metadata: {
              resolution: (.Resolution // "N/A"),
              references: (.References // [])
            }
          }))
        )
    ) | flatten) as $findings

  | {
      tool: "trivy",
      version: $version,
      status: "OK",
      errors: [],
      has_findings: (($findings | length) > 0),
      timestamp: $timestamp,
      branch: $branch,
      commit: $commit,
      scan_type: $scan_type,
      target: $target,
      stats: {
        CRITICAL: ($findings | map(select(.severity == "CRITICAL")) | length),
        HIGH:     ($findings | map(select(.severity == "HIGH"))     | length),
        MEDIUM:   ($findings | map(select(.severity == "MEDIUM"))   | length),
        LOW:      ($findings | map(select(.severity == "LOW"))      | length),
        INFO:     ($findings | map(select(.severity == "INFO"))     | length),
        TOTAL:    ($findings | length),
        EXEMPTED: 0,
        FAILED:   ($findings | length),
        PASSED:   0,
        by_type: {
          vulnerability: ($findings | map(select(.finding_type == "vulnerability")) | length),
          secret:        ($findings | map(select(.finding_type == "secret"))        | length),
          misconfig:     ($findings | map(select(.finding_type == "misconfig"))     | length)
        },
        by_category: {
          INFRASTRUCTURE: ($findings | map(select(.category == "INFRASTRUCTURE")) | length),
          APPLICATION:    ($findings | map(select(.category == "APPLICATION"))    | length),
          CONFIGURATION:  ($findings | map(select(.category == "CONFIGURATION"))  | length),
          SECRET:         ($findings | map(select(.category == "SECRET"))         | length)
        }
      },
      remediation_sla: $sla_map,
      findings: $findings
    }
' > "$OPA_FINAL_REPORT"; then
  emit_not_run "trivy_normalization_failed"
  exit 0
fi

TOTAL=$(jq '.stats.TOTAL' "$OPA_FINAL_REPORT")
CRITICAL=$(jq '.stats.CRITICAL' "$OPA_FINAL_REPORT")
HIGH=$(jq '.stats.HIGH' "$OPA_FINAL_REPORT")

log "---------------------------------------------"
log "OPA Report : $OPA_FINAL_REPORT"
log "Total      : $TOTAL findings"
log "Critical   : $CRITICAL | High: $HIGH"
log "Enforcement: Delegated to OPA Quality Gate"
log "---------------------------------------------"

exit 0
