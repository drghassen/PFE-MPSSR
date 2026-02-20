#!/usr/bin/env bash
set -euo pipefail

################################################################################
# CloudSentinel — Trivy Dockerfile Misconfig Scanner
# Scope  : Dockerfile security misconfiguration (CIS Docker Benchmark)
# Output : reports/raw/trivy-config-raw.json
# Note   : Terraform IaC scanning → Checkov (out of Trivy scope)
#          Container image vulnerabilities → scan-image.sh
################################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_DIR="$BASE_DIR/configs"
REPORT_DIR="$BASE_DIR/reports/raw"

log()  { echo -e "\033[1;34m[CloudSentinel][Trivy][CONFIG]\033[0m $*"; }
warn() { echo -e "\033[1;33m[CloudSentinel][Trivy][CONFIG][WARN]\033[0m $*" >&2; }
err()  { echo -e "\033[1;31m[CloudSentinel][Trivy][CONFIG][ERROR]\033[0m $*" >&2; }

# ── Argument validation ──────────────────────────────────────────────────────
TARGET="${1:-}"
[[ -z "$TARGET" ]] && { err "Usage: $0 <Dockerfile_path_or_directory>"; exit 1; }

if [[ -f "$TARGET" ]]; then
  TARGET="$(realpath "$TARGET")"
elif [[ -d "$TARGET" ]]; then
  TARGET="$(realpath "$TARGET")"
else
  err "Target not found: $TARGET (expected Dockerfile or directory)"
  exit 1
fi

# Detect CI mode
SCAN_MODE="${SCAN_MODE:-local}"
[[ -n "${CI:-}" ]] && SCAN_MODE="ci"

CONFIG_FILE="$CONFIG_DIR/trivy.yaml"
[[ "$SCAN_MODE" == "ci" ]] && CONFIG_FILE="$CONFIG_DIR/trivy-ci.yaml"

# ── Setup ────────────────────────────────────────────────────────────────────
mkdir -p "$REPORT_DIR"
OUTPUT_FILE="$REPORT_DIR/trivy-config-raw.json"

log "Mode      : $SCAN_MODE"
log "Config    : $CONFIG_FILE"
log "Target    : $TARGET"
log "Output    : $OUTPUT_FILE"

# ── Scan ─────────────────────────────────────────────────────────────────────
# trivy config scans Dockerfiles for misconfigurations (CIS Docker Benchmark)
# --scanners misconfig is implicit with 'trivy config' subcommand
if ! trivy config \
    --config "$CONFIG_FILE" \
    --format json \
    --output "$OUTPUT_FILE" \
    "$TARGET"; then
  err "Trivy encountered an internal error during config scan: $TARGET"
  exit 1
fi

FINDING_COUNT=$(jq '[.Results[]? | (.Misconfigurations // []) | length] | add // 0' "$OUTPUT_FILE" 2>/dev/null || echo "?")
log "Scan complete. Misconfigurations: $FINDING_COUNT → $OUTPUT_FILE"
