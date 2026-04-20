#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../../lib_scanner_utils.sh"

REPO_ROOT="$(cs_get_repo_root)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

SCAN_IMAGE="$SCRIPT_DIR/scan-image.sh"
SCAN_FS="$SCRIPT_DIR/scan-fs.sh"
SCAN_CONFIG="$SCRIPT_DIR/scan-config.sh"

REPORTS_RAW_DIR="$BASE_DIR/reports/raw"
mkdir -p "$REPORTS_RAW_DIR"

log()  { echo -e "\033[1;34m[CloudSentinel][Trivy]\033[0m $*"; }
err()  { echo -e "\033[1;31m[CloudSentinel][Trivy][ERROR]\033[0m $*" >&2; }

command -v trivy >/dev/null 2>&1 || { err "trivy binary missing"; exit 2; }
command -v jq >/dev/null 2>&1 || { err "jq binary missing"; exit 2; }

TARGET="${1:-}"
SCAN_TYPE="${2:-}"

if [[ -z "$TARGET" || -z "$SCAN_TYPE" ]]; then
  err "Usage: $0 <target> <scan_type>"
  err "  scan_type: image | fs | config"
  exit 2
fi

RAW_RESULTS=""
case "$SCAN_TYPE" in
  image)
    bash "$SCAN_IMAGE" "$TARGET"
    RAW_RESULTS="${TRIVY_IMAGE_OUTPUT_PATH:-$REPORTS_RAW_DIR/trivy-image-raw.json}"
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
    exit 2
    ;;
esac

[[ -f "$RAW_RESULTS" ]] || { err "trivy raw output missing: $RAW_RESULTS"; exit 2; }
jq empty "$RAW_RESULTS" >/dev/null 2>&1 || { err "trivy raw output invalid JSON: $RAW_RESULTS"; exit 2; }

log "Raw report ready: $RAW_RESULTS"
exit 0
