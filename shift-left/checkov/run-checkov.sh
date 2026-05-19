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
CUSTOM_CHECKS_DIR="${POLICIES_DIR}/azure"
CONFIG_FILE="${SCRIPT_DIR}/.checkov.yml"
SUPPRESSIONS_FILE="${SCRIPT_DIR}/config/checkov-suppressions.yml"
EFFECTIVE_CONFIG_FILE="$OUT_DIR/checkov.effective.yml"

REPORT_RAW="$OUT_DIR/checkov_raw.json"
REPORT_LOG="$OUT_DIR/checkov_scan.log"

command -v checkov >/dev/null 2>&1 || { log_err "checkov binary missing"; exit 2; }
command -v jq >/dev/null 2>&1 || { log_err "jq binary missing"; exit 2; }
[[ -f "$CONFIG_FILE" ]] || { log_err "config file missing: $CONFIG_FILE"; exit 2; }
[[ -f "$SUPPRESSIONS_FILE" ]] || { log_err "suppressions file missing: $SUPPRESSIONS_FILE"; exit 2; }
[[ -d "$POLICIES_DIR" ]] || { log_err "policies dir missing: $POLICIES_DIR"; exit 2; }
[[ -d "$CUSTOM_CHECKS_DIR" ]] || { log_err "custom checks dir missing: $CUSTOM_CHECKS_DIR"; exit 2; }

SCAN_TARGET="${1:-$REPO_ROOT}"
log_info "Starting raw scan on: $SCAN_TARGET"

INLINE_SUPPRESSIONS="$(
  grep -RInE '#[[:space:]]*checkov:skip[[:space:]]*=' "$SCAN_TARGET" \
    --include='*.tf' \
    --include='*.tfvars' \
    --include='*.hcl' \
    --include='*.yaml' \
    --include='*.yml' \
    --exclude-dir='.git' \
    --exclude-dir='.terraform' \
    --exclude-dir='.cloudsentinel' \
    2>/dev/null || true
)"
if [[ -n "$INLINE_SUPPRESSIONS" ]]; then
  log_err "Inline checkov:skip detected. Use DefectDojo/OPA risk acceptance instead."
  printf '%s\n' "$INLINE_SUPPRESSIONS" >&2
  exit 1
fi

{
  cat "$CONFIG_FILE"
  printf '\n'
  cat "$SUPPRESSIONS_FILE"
} > "$EFFECTIVE_CONFIG_FILE"

checkov_cmd=(checkov --directory "$SCAN_TARGET")
checkov_cmd+=("--config-file" "$EFFECTIVE_CONFIG_FILE")
checkov_cmd+=("--external-checks-dir" "$CUSTOM_CHECKS_DIR")
checkov_cmd+=("--run-all-external-checks")

CHECKOV_CHECKS_CSV="${CHECKOV_CHECKS:-}"
if [[ -n "$CHECKOV_CHECKS_CSV" ]]; then
  checkov_cmd+=("--check" "$CHECKOV_CHECKS_CSV")
  log_info "Applied explicit checks from CHECKOV_CHECKS: $CHECKOV_CHECKS_CSV"
fi

CHECKOV_SKIP_CHECKS_CSV="${CHECKOV_SKIP_CHECKS:-}"
if [[ -n "$CHECKOV_SKIP_CHECKS_CSV" ]]; then
  if [[ -n "${CI:-}" ]]; then
    log_err "CHECKOV_SKIP_CHECKS is forbidden in CI. Use DefectDojo/OPA exceptions."
    exit 1
  fi
  checkov_cmd+=("--skip-check" "$CHECKOV_SKIP_CHECKS_CSV")
  log_info "Applied explicit skip checks from CHECKOV_SKIP_CHECKS: $CHECKOV_SKIP_CHECKS_CSV"
fi

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

if grep -E "No __init__\\.py found|Cannot load any check here|Failed to load external check" "$REPORT_LOG" >/dev/null 2>&1; then
  log_err "Custom Checkov policies were not loaded correctly. See $REPORT_LOG"
  exit 2
fi

MODULE_ROOT=""
if [[ -d "$SCAN_TARGET/infra/azure/modules" ]]; then
  MODULE_ROOT="$SCAN_TARGET/infra/azure/modules"
elif [[ -d "$SCAN_TARGET/modules" && "$SCAN_TARGET" == *"infra/azure"* ]]; then
  MODULE_ROOT="$SCAN_TARGET/modules"
elif [[ -d "$REPO_ROOT/infra/azure/modules" && "$SCAN_TARGET" == "." ]]; then
  MODULE_ROOT="$REPO_ROOT/infra/azure/modules"
fi

module_reports=()
if [[ -n "$MODULE_ROOT" ]]; then
  while IFS= read -r module_file; do
    module_report="$(mktemp "$OUT_DIR/checkov_module_XXXXXX.json")"
    module_log="$(mktemp "$OUT_DIR/checkov_module_XXXXXX.log")"
    module_cmd=(checkov --file "$module_file")
    module_cmd+=("--config-file" "$EFFECTIVE_CONFIG_FILE")
    module_cmd+=("--external-checks-dir" "$CUSTOM_CHECKS_DIR")
    module_cmd+=("--run-all-external-checks")
    set +e
    "${module_cmd[@]}" > "$module_report" 2> "$module_log"
    module_rc=$?
    set -e
    cat "$module_log" >> "$REPORT_LOG"
    rm -f "$module_log"
    if [[ "$module_rc" -ge 2 ]]; then
      log_err "Technical Checkov module scan failure (rc=$module_rc) on $module_file. See $REPORT_LOG"
      exit 2
    fi
    module_rel_path="${module_file#"$MODULE_ROOT"/}"
    module_display_path="/modules/${module_rel_path}"
    module_normalized_report="$(mktemp "$OUT_DIR/checkov_module_norm_XXXXXX.json")"
    jq --arg file_path "$module_display_path" '
      .results.failed_checks = ((.results.failed_checks // []) | map(.file_path = $file_path))
    ' "$module_report" > "$module_normalized_report"
    mv "$module_normalized_report" "$module_report"
    module_reports+=("$module_report")
  done < <(find "$MODULE_ROOT" -mindepth 2 -maxdepth 2 -type f -name "main.tf" | sort)
fi

if [[ "${#module_reports[@]}" -gt 0 ]]; then
  merged_report="$(mktemp "$OUT_DIR/checkov_merged_XXXXXX.json")"
  jq -s '
    def norm_resource:
      ((.resource // "") | tostring | sub("^module\\.[^.]+\\."; ""));
    def finding_key:
      [
        (.check_id // ""),
        (.file_abs_path // .file_path // ""),
        norm_resource
      ] | join("|");

    .[0] as $base
    | (.[1:] | map(.results.failed_checks // []) | add) as $module_failed
    | (($base.results.failed_checks // []) | map(finding_key)) as $existing_keys
    | ($module_failed | map(select((finding_key as $key | ($existing_keys | index($key) | not))))) as $new_failed
    | $base
    | .results.failed_checks = (($base.results.failed_checks // []) + $new_failed)
    | .summary.failed = (.results.failed_checks | length)
  ' "$REPORT_RAW" "${module_reports[@]}" > "$merged_report"
  mv "$merged_report" "$REPORT_RAW"
  rm -f "${module_reports[@]}"
  log_info "Merged module-library Checkov findings from $MODULE_ROOT"
fi

[[ -s "$REPORT_RAW" ]] || { log_err "checkov raw output missing: $REPORT_RAW"; exit 2; }
jq -e 'type == "object" and (.results | type == "object")' "$REPORT_RAW" >/dev/null \
  || { log_err "invalid checkov raw JSON structure"; exit 2; }

PARSING_ERRORS="$(jq -r '(.results.parsing_errors // []) | length' "$REPORT_RAW" 2>/dev/null || echo 0)"
[[ "$PARSING_ERRORS" =~ ^[0-9]+$ ]] || PARSING_ERRORS=0
if [[ "$PARSING_ERRORS" -gt 0 ]]; then
  # In CI, parsing errors mean Terraform files were silently skipped — the scan
  # result is incomplete and cannot be trusted as a security gate.
  # Set CHECKOV_ALLOW_PARSING_ERRORS=true only for local debugging.
  if [[ -n "${CI:-}" && "${CHECKOV_ALLOW_PARSING_ERRORS:-false}" != "true" ]]; then
    log_err "${PARSING_ERRORS} parsing error(s) detected — Terraform files were silently skipped."
    log_err "Incomplete scan cannot be used as a security gate. Fix the files or set CHECKOV_ALLOW_PARSING_ERRORS=true to override (local only)."
    jq -r '(.results.parsing_errors // []) | .[]' "$REPORT_RAW" 2>/dev/null \
      | while IFS= read -r _fe; do log_err "  parse error: ${_fe}"; done
    exit 2
  fi
  log_info "WARN: checkov reported ${PARSING_ERRORS} parsing error(s) — check $REPORT_LOG"
fi

log_info "Raw report ready: $REPORT_RAW"
exit 0
