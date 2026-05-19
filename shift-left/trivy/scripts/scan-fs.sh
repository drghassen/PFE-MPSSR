#!/usr/bin/env bash
set -euo pipefail

################################################################################
# CloudSentinel — Trivy Filesystem / SCA Scanner
# Scope  : CVE vulnerabilities in OS packages + language libraries
# Output : reports/raw/trivy-fs-raw.json
# Note   : IaC misconfigs → Checkov | Secrets → Gitleaks
#          Container/image misconfigs → trivy image scan (TRIVY_IMAGE_TARGETS)
################################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_DIR="$BASE_DIR/configs"
REPORT_DIR="$BASE_DIR/reports/raw"
SBOM_DIR="$BASE_DIR/reports/sbom"
SCAN_MODE="${SCAN_MODE:-local}"
[[ -n "${CI:-}" ]] && SCAN_MODE="ci"
TRIVY_CACHE_DIR_EFF="${TRIVY_CACHE_DIR:-.trivy-cache}"
TRIVY_DB_REPOSITORIES_EFF="${TRIVY_DB_REPOSITORIES:-ghcr.io/aquasecurity/trivy-db:2,mirror.gcr.io/aquasec/trivy-db:2}"

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
mkdir -p "$TRIVY_CACHE_DIR_EFF"
OUTPUT_FILE="$REPORT_DIR/trivy-fs-raw.json"
SBOM_FILE="$SBOM_DIR/trivy-fs.cdx.json"

DB_REPO_ARGS=()
IFS=',' read -r -a _raw_db_repos <<< "$TRIVY_DB_REPOSITORIES_EFF"
for _repo in "${_raw_db_repos[@]}"; do
  _repo="$(echo "$_repo" | xargs)"
  [[ -z "$_repo" ]] && continue
  DB_REPO_ARGS+=(--db-repository "$_repo")
done

use_warmed_db_cache() {
  case "${TRIVY_SKIP_DB_UPDATE_IN_SCAN:-}" in
    1|true|TRUE|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

warmed_db_cache_available() {
  local db_file="${TRIVY_CACHE_DIR_EFF}/db/trivy.db"
  local metadata_file="${TRIVY_CACHE_DIR_EFF}/db/metadata.json"

  [[ -s "$db_file" ]] || return 1
  [[ -s "$metadata_file" ]] || return 1
  jq -e '
    type == "object"
    and (.Version | tostring == "2")
    and (.NextUpdate | type == "string")
    and (.DownloadedAt | type == "string")
  ' "$metadata_file" >/dev/null 2>&1 || return 1
}

SKIP_DB_UPDATE_ARGS=()
if use_warmed_db_cache; then
  if warmed_db_cache_available; then
    SKIP_DB_UPDATE_ARGS=(--skip-db-update)
  else
    # TRIVY_SKIP_DB_UPDATE_IN_SCAN=true but no valid DB found at the expected path.
    # Known safe causes — all recoverable via live download:
    #   - First pipeline run: GitLab cache key has never been uploaded by trivy-db-warm.
    #   - Cache evicted: GitLab purges caches after ~14 days of inactivity (configurable).
    #   - Runner mis-config: cache storage not shared across runner pool members.
    # The scan job falls back to a live download. This adds 2-8 min but is correct.
    # trivy-db-warm will populate the cache key for all subsequent pipeline runs.
    # A true hard-fail is still enforced below when trivy itself exits rc>1 (no DB
    # source reachable at all — network down, all mirrors exhausted, etc.).
    warn "Warmed Trivy DB cache miss at ${TRIVY_CACHE_DIR_EFF}/db — falling back to live DB download."
    if [[ -n "${CI:-}" ]]; then
      warn "Expected on first pipeline run or after cache eviction. Check trivy-db-warm logs if this recurs."
    fi
  fi
fi

skip_java_db_update() {
  case "${TRIVY_SKIP_JAVA_DB_UPDATE_IN_SCAN:-}" in
    1|true|TRUE|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

JAVA_DB_UPDATE_ARGS=()
if skip_java_db_update; then
  JAVA_DB_UPDATE_ARGS=(--skip-java-db-update)
fi

log "Mode      : $SCAN_MODE"
log "Config    : $CONFIG_FILE"
log "Target    : $TARGET"
log "Output    : $OUTPUT_FILE"
log "SBOM      : $SBOM_FILE"
log "Cache dir : $TRIVY_CACHE_DIR_EFF"
log "DB repos  : $TRIVY_DB_REPOSITORIES_EFF"
if use_warmed_db_cache; then
  if [[ ${#SKIP_DB_UPDATE_ARGS[@]} -gt 0 ]]; then
    log "DB update : disabled (using warmed DB cache)"
  else
    log "DB update : enabled (cache miss — downloading fresh DB)"
  fi
else
  log "DB update : enabled"
fi
if skip_java_db_update; then
  log "Java DB   : disabled"
else
  log "Java DB   : enabled"
fi
[[ -f "$IGNORE_FILE" ]] && log "Ignore   : $IGNORE_FILE"
[[ ${#SKIP_ARGS[@]} -gt 0 ]] && log "Skip dirs: $SKIP_DIRS_CSV"

# ── SBOM Generation ──────────────────────────────────────────────────────────
log "Generating SBOM (CycloneDX)..."
if ! trivy fs \
  --config "$CONFIG_FILE" \
  --cache-dir "$TRIVY_CACHE_DIR_EFF" \
  "${DB_REPO_ARGS[@]}" \
  "${SKIP_DB_UPDATE_ARGS[@]}" \
  "${JAVA_DB_UPDATE_ARGS[@]}" \
  --format cyclonedx \
  --output "$SBOM_FILE" \
  "$TARGET"; then
  if use_warmed_db_cache; then
    warn "Failed to generate SBOM with warmed DB cache, continuing scan."
  else
    warn "SBOM generation with DB update failed, retrying with cached DB (--skip-db-update)."
    trivy fs \
      --config "$CONFIG_FILE" \
      --cache-dir "$TRIVY_CACHE_DIR_EFF" \
      --skip-db-update \
      "${JAVA_DB_UPDATE_ARGS[@]}" \
      --format cyclonedx \
      --output "$SBOM_FILE" \
      "$TARGET" || warn "Failed to generate SBOM, continuing scan."
  fi
fi

# ── Scan ─────────────────────────────────────────────────────────────────────
# --scanners vuln: CVE in OS packages + language libraries
# IaC misconfigs → Checkov | Container misconfigs → image scan
# RC handling:
#   0/1 -> scan executed (findings may exist)
#   >1  -> technical failure
set +e
trivy fs \
  --config "$CONFIG_FILE" \
  --cache-dir "$TRIVY_CACHE_DIR_EFF" \
  "${DB_REPO_ARGS[@]}" \
  "${SKIP_DB_UPDATE_ARGS[@]}" \
  "${JAVA_DB_UPDATE_ARGS[@]}" \
  "${IGNORE_ARGS[@]}" \
  "${SKIP_ARGS[@]}" \
  --scanners vuln \
  --format json \
  --output "$OUTPUT_FILE" \
  "$TARGET"
TRIVY_RC=$?

if [[ "$TRIVY_RC" -gt 1 ]] && [[ -n "${CI:-}" ]] && ! use_warmed_db_cache; then
  warn "Trivy DB update failed in CI; retrying scan with cached DB (--skip-db-update)."
  trivy fs \
    --config "$CONFIG_FILE" \
    --cache-dir "$TRIVY_CACHE_DIR_EFF" \
    --skip-db-update \
    "${JAVA_DB_UPDATE_ARGS[@]}" \
    "${IGNORE_ARGS[@]}" \
    "${SKIP_ARGS[@]}" \
    --scanners vuln \
    --format json \
    --output "$OUTPUT_FILE" \
    "$TARGET"
  TRIVY_RC=$?
fi
set -e

if [[ "$TRIVY_RC" -gt 1 ]]; then
  err "Trivy technical error during filesystem scan (rc=$TRIVY_RC): $TARGET"
  exit 1
fi

if jq -e 'type == "object" and ((has("Results") | not) or (.Results == null))' "$OUTPUT_FILE" >/dev/null 2>&1; then
  tmp_output="$(mktemp)"
  jq '.Results = []' "$OUTPUT_FILE" > "$tmp_output"
  mv "$tmp_output" "$OUTPUT_FILE"
fi

if ! jq -e 'type == "object" and (.Results | type == "array")' "$OUTPUT_FILE" >/dev/null 2>&1; then
  err "Trivy filesystem scan produced an invalid raw report: $OUTPUT_FILE"
  exit 1
fi

FINDING_COUNT=$(jq '[.Results[]? | (.Vulnerabilities // []) | length] | add // 0' "$OUTPUT_FILE" 2>/dev/null || echo "?")
log "Scan complete. Findings: $FINDING_COUNT → $OUTPUT_FILE"
