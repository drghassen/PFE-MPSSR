#!/usr/bin/env bash
set -euo pipefail

log()  { echo "[CloudSentinel][Gitleaks] $*"; }
err()  { echo "[CloudSentinel][Gitleaks][ERROR] $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib_scanner_utils.sh"

REPO_ROOT="$(cs_get_repo_root)"
OUT_DIR="$REPO_ROOT/.cloudsentinel"
REPORT_RAW_OUT="$OUT_DIR/gitleaks_raw.json"
CONFIG_PATH="${CONFIG_PATH:-$REPO_ROOT/shift-left/gitleaks/gitleaks.toml}"
SCAN_TARGET="${SCAN_TARGET:-staged}"
MAX_SIZE_MB="${GITLEAKS_MAX_SIZE:-5}"

if [[ -n "${CI:-}" ]]; then
  TIMEOUT_SEC="${CLOUDSENTINEL_TIMEOUT:-300}"
else
  TIMEOUT_SEC="${CLOUDSENTINEL_TIMEOUT:-60}"
fi

mkdir -p "$OUT_DIR"

command -v git >/dev/null 2>&1 || { err "git binary missing"; exit 2; }
command -v jq >/dev/null 2>&1 || { err "jq binary missing"; exit 2; }
command -v gitleaks >/dev/null 2>&1 || { err "gitleaks binary missing"; exit 2; }
[[ -f "$CONFIG_PATH" ]] || { err "gitleaks config missing: $CONFIG_PATH"; exit 2; }

TIMEOUT_BIN=""
command -v timeout >/dev/null 2>&1 && TIMEOUT_BIN="timeout"

run_cmd() {
  if [[ "$TIMEOUT_SEC" -gt 0 && -n "$TIMEOUT_BIN" ]]; then
    timeout "$TIMEOUT_SEC" "$@"
  else
    "$@"
  fi
}

SCAN_MODE="${SCAN_MODE:-}"
if [[ "$SCAN_MODE" != "ci" && "$SCAN_MODE" != "local" ]]; then
  [[ -n "${CI:-}" ]] && SCAN_MODE="ci" || SCAN_MODE="local"
fi

log "Starting raw scan (mode=$SCAN_MODE, max_size=${MAX_SIZE_MB}MB)..."

set +e
if [[ "$SCAN_MODE" == "local" ]]; then
  if [[ "$SCAN_TARGET" == "repo" ]]; then
    run_cmd gitleaks detect --source "$REPO_ROOT" --redact --config "$CONFIG_PATH" --report-format json --report-path "$REPORT_RAW_OUT" --max-target-megabytes "$MAX_SIZE_MB"
  else
    run_cmd gitleaks protect --staged --redact --config "$CONFIG_PATH" --report-format json --report-path "$REPORT_RAW_OUT" --max-target-megabytes "$MAX_SIZE_MB"
  fi
else
  # CI must scan the full checked-out repository snapshot (no commit history).
  run_cmd gitleaks detect --no-git --source "$REPO_ROOT" --redact --config "$CONFIG_PATH" --report-format json --report-path "$REPORT_RAW_OUT" --max-target-megabytes "$MAX_SIZE_MB"
fi
RC=$?
set -e

if [[ "$RC" -gt 1 ]]; then
  err "gitleaks execution error rc=$RC"
  exit 2
fi

[[ -s "$REPORT_RAW_OUT" ]] || { err "gitleaks raw output missing: $REPORT_RAW_OUT"; exit 2; }
jq -e 'type=="array"' "$REPORT_RAW_OUT" >/dev/null || { err "gitleaks raw output invalid JSON array"; exit 2; }

log "Raw report ready: $REPORT_RAW_OUT"

# --- Scan range secondaire (enrichissement metadata — non-gating) ---
# ENRICHISSEMENT UNIQUEMENT : gitleaks_range_raw.json n'alimente jamais OPA.
# Signal OPA = gitleaks_raw.json (scan principal --no-git) uniquement.
if [[ -n "${CI:-}" ]]; then
  RANGE_OUT="$OUT_DIR/gitleaks_range_raw.json"
  LOG_OPTS=""
  ZERO_SHA="0000000000000000000000000000000000000000"

  if [[ -n "${CI_MERGE_REQUEST_TARGET_BRANCH_SHA:-}" \
        && "${CI_MERGE_REQUEST_TARGET_BRANCH_SHA}" != "$ZERO_SHA" ]]; then
    LOG_OPTS="${CI_MERGE_REQUEST_TARGET_BRANCH_SHA}..${CI_COMMIT_SHA:-HEAD}"
  elif [[ -n "${CI_COMMIT_BEFORE_SHA:-}" \
          && "${CI_COMMIT_BEFORE_SHA}" != "$ZERO_SHA" ]]; then
    LOG_OPTS="${CI_COMMIT_BEFORE_SHA}..${CI_COMMIT_SHA:-HEAD}"
  else
    LOG_OPTS="--max-count=200"
  fi

  log "Starting range scan (enrichissement, best-effort, log-opts='$LOG_OPTS')..."
  set +e
  run_cmd gitleaks detect \
    --source "$REPO_ROOT" \
    --log-opts "$LOG_OPTS" \
    --redact \
    --config "$CONFIG_PATH" \
    --report-format json \
    --report-path "$RANGE_OUT" \
    --max-target-megabytes "$MAX_SIZE_MB"
  RC_RANGE=$?
  set -e

  if [[ "$RC_RANGE" -gt 1 ]]; then
    log "WARN: range scan failed rc=$RC_RANGE — skipping enrichment"
  else
    if jq -e 'type=="array"' "$RANGE_OUT" >/dev/null 2>&1; then
      log "Range report ready: $RANGE_OUT"
      # Merge range findings into the main report for OPA gate evaluation.
      # Deduplication is handled by normalize.py fingerprint.
      if [[ -s "$RANGE_OUT" ]] && jq -e 'length > 0' "$RANGE_OUT" >/dev/null 2>&1; then
        MERGED_COUNT=$(jq -s '.[0] + .[1] | unique_by(.Fingerprint // .fingerprint // .)' \
          "$REPORT_RAW_OUT" "$RANGE_OUT" | jq 'length')
        jq -s '.[0] + .[1] | unique_by(.Fingerprint // .fingerprint // .)' \
          "$REPORT_RAW_OUT" "$RANGE_OUT" > "${REPORT_RAW_OUT}.merged"
        mv "${REPORT_RAW_OUT}.merged" "$REPORT_RAW_OUT"
        log "Merged range findings into main report. Total unique findings: $MERGED_COUNT"
      fi
    else
      log "WARN: range report invalid JSON — skipping enrichment"
      rm -f "$RANGE_OUT"
    fi
  fi
fi

exit 0
