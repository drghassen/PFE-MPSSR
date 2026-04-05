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

USE_RANGE="false"
BEFORE=""
CURRENT=""
ZERO_SHA="0000000000000000000000000000000000000000"

if [[ "$SCAN_MODE" == "ci" ]]; then
  BEFORE="${CI_COMMIT_BEFORE_SHA:-}"
  CURRENT="${CI_COMMIT_SHA:-HEAD}"

  if [[ -n "$BEFORE" && "$BEFORE" != "$ZERO_SHA" ]]; then
    if ! git cat-file -e "$BEFORE^{commit}" 2>/dev/null || ! git cat-file -e "$CURRENT^{commit}" 2>/dev/null; then
      if git remote get-url origin >/dev/null 2>&1; then
        git fetch --no-tags --depth="${GITLEAKS_FETCH_DEPTH:-200}" origin "$CURRENT" "$BEFORE" >/dev/null 2>&1 || true
      fi
    fi

    if git cat-file -e "$BEFORE^{commit}" 2>/dev/null && git cat-file -e "$CURRENT^{commit}" 2>/dev/null; then
      USE_RANGE="true"
    fi
  fi
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
  if [[ "$USE_RANGE" == "true" ]]; then
    run_cmd gitleaks detect --source "$REPO_ROOT" --log-opts="${BEFORE}..${CURRENT}" --redact --config "$CONFIG_PATH" --report-format json --report-path "$REPORT_RAW_OUT" --max-target-megabytes "$MAX_SIZE_MB"
  else
    run_cmd gitleaks detect --source "$REPO_ROOT" --redact --config "$CONFIG_PATH" --report-format json --report-path "$REPORT_RAW_OUT" --max-target-megabytes "$MAX_SIZE_MB"
  fi
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
exit 0
