#!/usr/bin/env bash
set -euo pipefail

################################################################################
# CloudSentinel — Trivy Filesystem / SCA Scanner
# Scope  : Language package vulnerabilities (npm, pip, maven, go, etc.)
# Output : reports/raw/trivy-fs-raw.json
# Note   : Source-level secret enforcement is handled exclusively by Gitleaks
#          (pre-commit + CI). Trivy FS here is vuln-only.
################################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_DIR="$BASE_DIR/configs"
REPORT_DIR="$BASE_DIR/reports/raw"
SBOM_DIR="$BASE_DIR/reports/sbom"
SCAN_MODE="${SCAN_MODE:-local}"
[[ -n "${CI:-}" ]] && SCAN_MODE="ci"

IGNORE_FILE="$BASE_DIR/.trivyignore"
IGNORE_ARGS=()
if [[ -f "$IGNORE_FILE" ]]; then
  if [[ "$SCAN_MODE" == "ci" ]]; then
    echo -e "\033[1;33m[CloudSentinel][Trivy][WARN]\033[0m .trivyignore is IGNORED in CI mode. Use DefectDojo/OPA for exceptions." >&2
  else
    IGNORE_ARGS=(--ignorefile "$IGNORE_FILE")
  fi
fi

SKIP_ARGS=()
SKIP_DIRS_CSV="${TRIVY_SKIP_DIRS:-}"
if [[ -n "$SKIP_DIRS_CSV" ]]; then
  IFS=',' read -r -a _skip_dirs <<< "$SKIP_DIRS_CSV"
  for _dir in "${_skip_dirs[@]}"; do
    _dir="$(echo "$_dir" | xargs)"
    [[ -z "$_dir" ]] && continue
    SKIP_ARGS+=(--skip-dirs "$_dir")
  done
fi

log()  { echo -e "\033[1;34m[CloudSentinel][Trivy][FS]\033[0m $*"; }
warn() { echo -e "\033[1;33m[CloudSentinel][Trivy][FS][WARN]\033[0m $*" >&2; }
err()  { echo -e "\033[1;31m[CloudSentinel][Trivy][FS][ERROR]\033[0m $*" >&2; }

# ── Argument validation ──────────────────────────────────────────────────────
TARGET="${1:-.}"

[[ ! -d "$TARGET" ]] && { err "Target directory not found: $TARGET"; exit 1; }
TARGET="$(realpath "$TARGET")"

# SCAN_MODE already detected above

CONFIG_FILE="$CONFIG_DIR/trivy.yaml"
[[ "$SCAN_MODE" == "ci" ]] && CONFIG_FILE="$CONFIG_DIR/trivy-ci.yaml"

# ── Setup ────────────────────────────────────────────────────────────────────
mkdir -p "$REPORT_DIR"
mkdir -p "$SBOM_DIR"
OUTPUT_FILE="$REPORT_DIR/trivy-fs-raw.json"
SBOM_FILE="$SBOM_DIR/trivy-fs.cdx.json"

log "Mode      : $SCAN_MODE"
log "Config    : $CONFIG_FILE"
log "Target    : $TARGET"
log "Output    : $OUTPUT_FILE"
log "SBOM      : $SBOM_FILE"
[[ -f "$IGNORE_FILE" ]] && log "Ignore   : $IGNORE_FILE"
[[ ${#SKIP_ARGS[@]} -gt 0 ]] && log "Skip dirs: $SKIP_DIRS_CSV"

# ── SBOM Generation ──────────────────────────────────────────────────────────
log "Generating SBOM (CycloneDX)..."
trivy fs \
  --config "$CONFIG_FILE" \
  --format cyclonedx \
  --output "$SBOM_FILE" \
  "$TARGET" || warn "Failed to generate SBOM, continuing scan."

# ── Scan ─────────────────────────────────────────────────────────────────────
# --scanners: vuln only (secrets are scanned by Gitleaks only)
# RC handling:
#   0/1 -> scan executed (findings may exist)
#   >1  -> technical failure
set +e
trivy fs \
  --config "$CONFIG_FILE" \
  "${IGNORE_ARGS[@]}" \
  "${SKIP_ARGS[@]}" \
  --scanners vuln \
  --format json \
  --output "$OUTPUT_FILE" \
  "$TARGET"
TRIVY_RC=$?
set -e

if [[ "$TRIVY_RC" -gt 1 ]]; then
  err "Trivy technical error during filesystem scan (rc=$TRIVY_RC): $TARGET"
  exit 1
fi

FINDING_COUNT=$(jq '[.Results[]? | (.Vulnerabilities // []) | length] | add // 0' "$OUTPUT_FILE" 2>/dev/null || echo "?")
log "Scan complete. Findings: $FINDING_COUNT → $OUTPUT_FILE"
