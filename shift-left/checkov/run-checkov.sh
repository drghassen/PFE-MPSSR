#!/usr/bin/env bash
set -euo pipefail

################################################################################
# CloudSentinel - Checkov Wrapper v5.1
# - Centralized reports in .cloudsentinel/
# - Severity/category normalization via mapping.json
# - Fail-closed on technical/format errors (status=NOT_RUN)
################################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[Checkov][INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[Checkov][SUCCESS]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[Checkov][WARN]${NC} $*" >&2; }
log_err()     { echo -e "${RED}[Checkov][ERROR]${NC} $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib_scanner_utils.sh"

REPO_ROOT="$(cs_get_repo_root)"
OUT_DIR="$REPO_ROOT/.cloudsentinel"
mkdir -p "$OUT_DIR"

POLICIES_DIR="${SCRIPT_DIR}/policies"
MAPPING_FILE="${POLICIES_DIR}/mapping.json"
CONFIG_FILE="${SCRIPT_DIR}/.checkov.yml"

REPORT_RAW="$OUT_DIR/checkov_raw.json"
REPORT_OPA="$OUT_DIR/checkov_opa.json"
REPORT_LOG="$OUT_DIR/checkov_scan.log"

emit_not_run() {
    local reason=$1
    echo '{"results":{"failed_checks":[]}}' > "$REPORT_RAW"
    cs_emit_not_run "checkov" "$REPORT_OPA" "$reason" "$REPO_ROOT"
}

if ! command -v jq >/dev/null 2>&1; then
    emit_not_run "jq_binary_missing"
    exit 0
fi

if ! command -v checkov >/dev/null 2>&1; then
    emit_not_run "checkov_binary_missing"
    exit 0
fi

[[ -f "$MAPPING_FILE" ]] || { log_err "Mapping not found: $MAPPING_FILE"; emit_not_run "mapping_file_missing"; exit 0; }
[[ -f "$CONFIG_FILE" ]] || { log_err "Config file missing: $CONFIG_FILE"; emit_not_run "config_file_missing"; exit 0; }

SCAN_TARGET="${1:-$REPO_ROOT}"
log_info "Starting scan on: $SCAN_TARGET"

checkov_cmd=(checkov --directory "$SCAN_TARGET")
checkov_cmd+=("--config-file" "$CONFIG_FILE")
checkov_cmd+=("--external-checks-dir" "$POLICIES_DIR")

if [[ -n "${CHECKOV_SKIP_PATHS:-}" ]]; then
    IFS=',' read -r -a skip_paths <<< "$CHECKOV_SKIP_PATHS"
    for skip_path in "${skip_paths[@]}"; do
        skip_path="$(echo "$skip_path" | xargs)"
        [[ -z "$skip_path" ]] && continue
        checkov_cmd+=("--skip-path" "$skip_path")
    done
    log_info "Applied CHECKOV_SKIP_PATHS: $CHECKOV_SKIP_PATHS"
fi

set +e
"${checkov_cmd[@]}" > "$REPORT_RAW" 2> "$REPORT_LOG"
EXIT_CODE=$?
set -e

if [[ $EXIT_CODE -eq 2 ]]; then
    log_err "Technical Checkov failure. See $REPORT_LOG"
    emit_not_run "checkov_execution_error"
    exit 0
fi

if [[ ! -s "$REPORT_RAW" ]]; then
    emit_not_run "checkov_raw_output_missing"
    exit 0
fi

if ! jq -e 'type == "object" and (.results | type == "object")' "$REPORT_RAW" >/dev/null 2>&1; then
    log_err "Invalid Checkov JSON report detected."
    emit_not_run "checkov_raw_output_invalid_json"
    exit 0
fi

BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")"
COMMIT="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
CHECKOV_VERSION="$(checkov --version 2>/dev/null | head -n1 | tr -d '\r' || echo unknown)"
[[ -z "$CHECKOV_VERSION" ]] && CHECKOV_VERSION="unknown"

log_info "Normalizing results for OPA..."

jq -n \
  --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
  --arg branch "$BRANCH" \
  --arg commit "$COMMIT" \
  --arg repo "$REPO_ROOT" \
  --arg version "$CHECKOV_VERSION" \
  --slurpfile raw "$REPORT_RAW" \
  --slurpfile mapping "$MAPPING_FILE" \
'
  def get_map(id): ($mapping[0][id] // {category: "UNKNOWN", severity: null});

  ($raw | flatten | map(.results.failed_checks // []) | flatten) as $findings
  | ($findings
    | map({
        id: .check_id,
        resource: {
          name: .resource,
          path: .file_path
        },
        file: .file_path,
        line: .file_line_range[0],
        message: .check_name,
        category: (get_map(.check_id).category // (.check_class // "UNKNOWN")),
        severity: ((get_map(.check_id).severity // .severity // "MEDIUM") | ascii_upcase),
        status: "FAILED",
        fingerprint: (
          (.check_id + ":" + (.file_path // "unknown") + ":" + ((.file_line_range[0] // 0)|tostring))
          | @base64
        )
      })
    ) as $normalized

  | {
      tool: "checkov",
      version: $version,
      status: "OK",
      errors: [],
      has_findings: ($normalized | map(select(.status == "FAILED")) | length > 0),
      timestamp: $timestamp,
      branch: $branch,
      commit: $commit,
      repository: $repo,
      stats: {
        CRITICAL: ($normalized | map(select(.status == "FAILED" and .severity == "CRITICAL")) | length),
        HIGH:     ($normalized | map(select(.status == "FAILED" and .severity == "HIGH")) | length),
        MEDIUM:   ($normalized | map(select(.status == "FAILED" and .severity == "MEDIUM")) | length),
        LOW:      ($normalized | map(select(.status == "FAILED" and .severity == "LOW")) | length),
        INFO:     ($normalized | map(select(.status == "FAILED" and .severity == "INFO")) | length),
        TOTAL:    ($normalized | map(select(.status == "FAILED")) | length),
        EXEMPTED: 0,
        FAILED:   ($normalized | map(select(.status == "FAILED")) | length),
        PASSED:   0
      },
      findings: $normalized
    }
' > "$REPORT_OPA"

TOTAL_FAIL=$(jq '.stats.TOTAL' "$REPORT_OPA")

if [[ "$TOTAL_FAIL" -gt 0 ]]; then
    log_warn "Scan completed: $TOTAL_FAIL violations detected."
    jq -r '.findings[] | select(.status == "FAILED") | "  [\(.severity)] \(.id) -> \(.resource.name // .resource)"' "$REPORT_OPA" | head -n 5
else
    log_success "Scan completed: no violations detected."
fi

log_success "Report available: $REPORT_OPA"
exit 0