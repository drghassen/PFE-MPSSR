#!/usr/bin/env bash
set -euo pipefail

log_info() { echo "[Checkov][INFO] $*"; }
log_err()  { echo "[Checkov][ERROR] $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib_scanner_utils.sh"

REPO_ROOT="$(cs_get_repo_root)"
OUT_DIR="$REPO_ROOT/.cloudsentinel"
mkdir -p "$OUT_DIR"

POLICIES_DIR="${SCRIPT_DIR}/policies"
CONFIG_FILE="${SCRIPT_DIR}/.checkov.yml"

REPORT_RAW="$OUT_DIR/checkov_raw.json"
REPORT_LOG="$OUT_DIR/checkov_scan.log"

command -v checkov >/dev/null 2>&1 || { log_err "checkov binary missing"; exit 2; }
command -v jq >/dev/null 2>&1 || { log_err "jq binary missing"; exit 2; }
[[ -f "$CONFIG_FILE" ]] || { log_err "config file missing: $CONFIG_FILE"; exit 2; }
[[ -d "$POLICIES_DIR" ]] || { log_err "policies dir missing: $POLICIES_DIR"; exit 2; }

SCAN_TARGET="${1:-$REPO_ROOT}"
log_info "Starting raw scan on: $SCAN_TARGET"

checkov_cmd=(checkov --directory "$SCAN_TARGET")
checkov_cmd+=("--config-file" "$CONFIG_FILE")
checkov_cmd+=("--external-checks-dir" "$POLICIES_DIR")
# CKV_AZURE_43: Storage name uses substr() for the Azure 24-char limit.
# Static analysis cannot evaluate the dynamic name — validated at runtime.
checkov_cmd+=("--skip-check" "CKV_AZURE_43")

# Optional skip paths (comma-separated). Empty by default for full-repo scans.
SKIP_PATHS_CSV="${CHECKOV_SKIP_PATHS:-}"
if [[ -n "$SKIP_PATHS_CSV" ]]; then
  IFS=',' read -r -a skip_paths <<< "$SKIP_PATHS_CSV"
  for skip_path in "${skip_paths[@]}"; do
    skip_path="$(echo "$skip_path" | xargs)"
    [[ -z "$skip_path" ]] && continue
    checkov_cmd+=("--skip-path" "$skip_path")
  done
  log_info "Applied skip paths from CHECKOV_SKIP_PATHS: $SKIP_PATHS_CSV"
else
  log_info "No skip paths configured (CHECKOV_SKIP_PATHS empty)."
fi

set +e
"${checkov_cmd[@]}" > "$REPORT_RAW" 2> "$REPORT_LOG"
RC=$?
set -e

if [[ "$RC" -ge 2 ]]; then
  log_err "Technical Checkov failure (rc=$RC). See $REPORT_LOG"
  exit 2
fi

[[ -s "$REPORT_RAW" ]] || { log_err "checkov raw output missing: $REPORT_RAW"; exit 2; }
jq -e 'type == "object" and (.results | type == "object")' "$REPORT_RAW" >/dev/null \
  || { log_err "invalid checkov raw JSON structure"; exit 2; }

PARSING_ERRORS="$(jq -r '(.results.parsing_errors // []) | length' "$REPORT_RAW" 2>/dev/null || echo 0)"
[[ "$PARSING_ERRORS" =~ ^[0-9]+$ ]] || PARSING_ERRORS=0
if [[ "$PARSING_ERRORS" -gt 0 ]]; then
  log_info "WARN: checkov reported ${PARSING_ERRORS} parsing error(s) — check $REPORT_LOG"
fi

log_info "Raw report ready: $REPORT_RAW"
exit 0
