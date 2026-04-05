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

log "Passing raw findings to Normalizer..."
cp "$RAW_RESULTS" "$OPA_FINAL_REPORT"

TOTAL=$(jq '[.Results[]? | .Vulnerabilities[]?, .Secrets[]?, .Misconfigurations[]?] | length' "$OPA_FINAL_REPORT")

log "---------------------------------------------"
log "Raw Report : $OPA_FINAL_REPORT"
log "Total      : ${TOTAL:-0} raw findings"
log "Enforcement: Delegated to CloudSentinel Normalizer"
log "---------------------------------------------"

exit 0
