#!/usr/bin/env bash
set -euo pipefail

################################################################################
# CloudSentinel — Trivy Image Scanner
# Scope  : Container image vulnerability scanning (OS pkgs + library pkgs)
#          + Secrets embedded in image layers
# Output : reports/raw/trivy-image-raw.json
# Note   : Dockerfile config scanning → scan-config.sh
#          Source-level secrets        → Gitleaks
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

log()  { echo -e "\033[1;34m[CloudSentinel][Trivy][IMAGE]\033[0m $*"; }
warn() { echo -e "\033[1;33m[CloudSentinel][Trivy][IMAGE][WARN]\033[0m $*" >&2; }
err()  { echo -e "\033[1;31m[CloudSentinel][Trivy][IMAGE][ERROR]\033[0m $*" >&2; }

# ── Argument validation ──────────────────────────────────────────────────────
TARGET="${1:-}"
[[ -z "$TARGET" ]] && { err "Usage: $0 <image_name[:tag]>"; exit 1; }

# Detect CI mode to select appropriate config
SCAN_MODE="${SCAN_MODE:-local}"
[[ -n "${CI:-}" ]] && SCAN_MODE="ci"

CONFIG_FILE="$CONFIG_DIR/trivy.yaml"
[[ "$SCAN_MODE" == "ci" ]] && CONFIG_FILE="$CONFIG_DIR/trivy-ci.yaml"

# ── Setup ────────────────────────────────────────────────────────────────────
mkdir -p "$REPORT_DIR"
OUTPUT_FILE="$REPORT_DIR/trivy-image-raw.json"

log "Mode      : $SCAN_MODE"
log "Config    : $CONFIG_FILE"
log "Target    : $TARGET"
log "Output    : $OUTPUT_FILE"
[[ -f "$IGNORE_FILE" ]] && log "Ignore   : $IGNORE_FILE"

# ── Scan ─────────────────────────────────────────────────────────────────────
# exit-code: 0 always — OPA is the enforcement layer
# --scanners: vuln covers OS+lib, secret covers embedded secrets
if ! trivy image \
    --config "$CONFIG_FILE" \
    "${IGNORE_ARGS[@]}" \
    --scanners vuln,secret \
    --format json \
    --output "$OUTPUT_FILE" \
    "$TARGET"; then
  # Trivy internal failure (not "found vulnerabilities") — this is a real error
  err "Trivy encountered an internal error scanning image: $TARGET"
  exit 1
fi

FINDING_COUNT=$(jq '[.Results[]? | (.Vulnerabilities // []) + (.Secrets // []) | length] | add // 0' "$OUTPUT_FILE" 2>/dev/null || echo "?")
log "Scan complete. Findings: $FINDING_COUNT → $OUTPUT_FILE"
