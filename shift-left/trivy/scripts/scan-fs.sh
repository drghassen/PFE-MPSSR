#!/usr/bin/env bash
set -euo pipefail

################################################################################
# CloudSentinel — Trivy Filesystem / SCA Scanner
# Scope  : Language package vulnerabilities (npm, pip, maven, go, etc.)
#          + Secrets in source files (complement to Gitleaks for CI layers)
# Output : reports/raw/trivy-fs-raw.json
# Note   : Source-level secret enforcement → Gitleaks (pre-commit + CI)
#          Trivy secret scan here catches CI-stage secrets missed by Gitleaks
################################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_DIR="$BASE_DIR/configs"
REPORT_DIR="$BASE_DIR/reports/raw"
IGNORE_FILE="$BASE_DIR/.trivyignore"
IGNORE_ARGS=()
if [[ -f "$IGNORE_FILE" ]]; then
  IGNORE_ARGS=(--ignorefile "$IGNORE_FILE")
fi

log()  { echo -e "\033[1;34m[CloudSentinel][Trivy][FS]\033[0m $*"; }
warn() { echo -e "\033[1;33m[CloudSentinel][Trivy][FS][WARN]\033[0m $*" >&2; }
err()  { echo -e "\033[1;31m[CloudSentinel][Trivy][FS][ERROR]\033[0m $*" >&2; }

# ── Argument validation ──────────────────────────────────────────────────────
TARGET="${1:-.}"

[[ ! -d "$TARGET" ]] && { err "Target directory not found: $TARGET"; exit 1; }
TARGET="$(realpath "$TARGET")"

# Detect CI mode
SCAN_MODE="${SCAN_MODE:-local}"
[[ -n "${CI:-}" ]] && SCAN_MODE="ci"

CONFIG_FILE="$CONFIG_DIR/trivy.yaml"
[[ "$SCAN_MODE" == "ci" ]] && CONFIG_FILE="$CONFIG_DIR/trivy-ci.yaml"

# ── Setup ────────────────────────────────────────────────────────────────────
mkdir -p "$REPORT_DIR"
OUTPUT_FILE="$REPORT_DIR/trivy-fs-raw.json"

log "Mode      : $SCAN_MODE"
log "Config    : $CONFIG_FILE"
log "Target    : $TARGET"
log "Output    : $OUTPUT_FILE"
[[ -f "$IGNORE_FILE" ]] && log "Ignore   : $IGNORE_FILE"

# ── Scan ─────────────────────────────────────────────────────────────────────
# --scanners: vuln for SCA, secret for files containing credentials
if ! trivy fs \
    --config "$CONFIG_FILE" \
    "${IGNORE_ARGS[@]}" \
    --scanners vuln,secret \
    --format json \
    --output "$OUTPUT_FILE" \
    "$TARGET"; then
  err "Trivy encountered an internal error scanning filesystem: $TARGET"
  exit 1
fi

FINDING_COUNT=$(jq '[.Results[]? | (.Vulnerabilities // []) + (.Secrets // []) | length] | add // 0' "$OUTPUT_FILE" 2>/dev/null || echo "?")
log "Scan complete. Findings: $FINDING_COUNT → $OUTPUT_FILE"
