#!/usr/bin/env bash
set -euo pipefail

############################################
# CloudSentinel - Gitleaks Wrapper v5.0 (PFE)
# - Local/CI dual mode
# - Produces OPA-ready JSON
# - Baseline supported (optional)
# - NEVER blocks on findings (exit 0). OPA decides.
############################################

log()  { echo "[CloudSentinel][Gitleaks] $*"; }
warn() { echo "[CloudSentinel][Gitleaks][WARN] $*" >&2; }
err()  { echo "[CloudSentinel][Gitleaks][ERROR] $*" >&2; }

need() { command -v "$1" >/dev/null 2>&1 || { err "$1 not installed"; exit 2; }; }

need git
need jq
need gitleaks

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || { err "Not a git repo"; exit 2; }

CONFIG_PATH="${CONFIG_PATH:-$REPO_ROOT/shift-left/gitleaks/gitleaks.toml}"
BASELINE_PATH="${BASELINE_PATH:-$REPO_ROOT/shift-left/gitleaks/.gitleaks-baseline.json}"

# Paramètres de performance et timeout
USE_BASELINE="${USE_BASELINE:-true}"
SCAN_TARGET="${SCAN_TARGET:-staged}"
MAX_SIZE_MB="${GITLEAKS_MAX_SIZE:-5}"

if [[ -n "${CI:-}" ]]; then
  TIMEOUT_SEC="${CLOUDSENTINEL_TIMEOUT:-300}"
else
  TIMEOUT_SEC="${CLOUDSENTINEL_TIMEOUT:-0}"
fi

REAL_REPO_ROOT=$(git rev-parse --show-toplevel)
OUT_DIR="$REAL_REPO_ROOT/.cloudsentinel"
mkdir -p "$OUT_DIR"

REPORT_RAW_TMP="$(mktemp -t gitleaks-raw.XXXXXX.json)"
REPORT_NORM_TMP="$(mktemp -t gitleaks-findings.XXXXXX.json)"
trap 'rm -f "$REPORT_RAW_TMP" "$REPORT_NORM_TMP"' EXIT

REPORT_RAW_OUT="$OUT_DIR/gitleaks_raw.json"
REPORT_OUT="$OUT_DIR/gitleaks_opa.json"

[[ -f "$CONFIG_PATH" ]] || { err "Config missing: $CONFIG_PATH"; exit 2; }

TIMEOUT_BIN=""
command -v timeout >/dev/null 2>&1 && TIMEOUT_BIN="timeout"

run_cmd() {
  if [[ "$TIMEOUT_SEC" -gt 0 && -n "$TIMEOUT_BIN" ]]; then
    timeout "$TIMEOUT_SEC" "$@"
  else
    "$@"
  fi
}

# Détection du mode de scan
SCAN_MODE="${SCAN_MODE:-}"
if [[ "$SCAN_MODE" != "ci" && "$SCAN_MODE" != "local" ]]; then
  [[ -n "${CI:-}" ]] && SCAN_MODE="ci" || SCAN_MODE="local"
fi

USE_RANGE="false"
BASE=""
HEAD=""

if [[ "$SCAN_MODE" == "ci" ]]; then
  if [[ -n "${GITHUB_BASE_SHA:-}" && -n "${GITHUB_SHA:-}" ]]; then
    BASE="$GITHUB_BASE_SHA"; HEAD="$GITHUB_SHA"; USE_RANGE="true"
  elif [[ -n "${CI_MERGE_REQUEST_TARGET_BRANCH_SHA:-}" && -n "${CI_COMMIT_SHA:-}" ]]; then
    BASE="$CI_MERGE_REQUEST_TARGET_BRANCH_SHA"; HEAD="$CI_COMMIT_SHA"; USE_RANGE="true"
  fi

  if [[ "$USE_RANGE" == "true" ]]; then
    if ! git cat-file -e "$BASE^{commit}" 2>/dev/null || ! git cat-file -e "$HEAD^{commit}" 2>/dev/null; then
      warn "Commits missing (shallow clone). Fallback to full scan."
      USE_RANGE="false"
    fi
  fi
fi

log "Starting scan (mode=$SCAN_MODE, max_size=${MAX_SIZE_MB}MB)..."

set +e
if [[ "$SCAN_MODE" == "local" ]]; then
  if [[ "$SCAN_TARGET" == "repo" ]]; then
    run_cmd gitleaks detect --source "$REPO_ROOT" --redact --config "$CONFIG_PATH" --report-format json --report-path "$REPORT_RAW_TMP" --max-target-megabytes "$MAX_SIZE_MB"
  else
    run_cmd gitleaks protect --staged --redact --config "$CONFIG_PATH" --report-format json --report-path "$REPORT_RAW_TMP" --max-target-megabytes "$MAX_SIZE_MB"
  fi
else
  if [[ "$USE_RANGE" == "true" ]]; then
    run_cmd gitleaks detect --source "$REPO_ROOT" --commit-range "$BASE...$HEAD" --redact --config "$CONFIG_PATH" --report-format json --report-path "$REPORT_RAW_TMP" --max-target-megabytes "$MAX_SIZE_MB"
  else
    run_cmd gitleaks detect --source "$REPO_ROOT" --redact --config "$CONFIG_PATH" --report-format json --report-path "$REPORT_RAW_TMP" --max-target-megabytes "$MAX_SIZE_MB"
  fi
fi
RC=$?
set -e

[[ "$RC" -gt 1 ]] && { err "gitleaks failed (rc=$RC)"; exit 2; }

# Validation du JSON
jq -e 'type=="array"' "$REPORT_RAW_TMP" >/dev/null 2>&1 || { echo "[]" > "$REPORT_RAW_TMP"; }
cp "$REPORT_RAW_TMP" "$REPORT_RAW_OUT"

# Normalisation et Enrichissement (Auteur, Date, Commit)
jq '
  def norm_sev(x): if (x|type)=="string" and (x|length)>0 then (x|ascii_upcase) else "MEDIUM" end;
  def mk_fp(x):
    if (x.Fingerprint? and (x.Fingerprint|type)=="string" and (x.Fingerprint|length)>0) then x.Fingerprint
    else "fp:" + ([ (x.RuleID // "unknown"), (x.File // "unknown"), ((x.StartLine // 0)|tostring) ] | join("|")) end;

  map({
    rule_id: (.RuleID // "unknown"),
    description: (.Description // "unknown"),
    file: (.File // "unknown"),
    start_line: (.StartLine // 0),
    severity: norm_sev(.Severity // "MEDIUM"),
    fingerprint: mk_fp(.),
    secret: "REDACTED",
    author: (.Email // "unknown"),
    commit: (.Commit // "unknown"),
    date: (.Date // "unknown")
  }) | unique_by(.fingerprint)
' "$REPORT_RAW_TMP" > "$REPORT_NORM_TMP"

# Gestion de la Baseline (Vérification robuste du format)
if [[ "$USE_BASELINE" == "true" && -f "$BASELINE_PATH" ]]; then
  if jq -e 'type=="array" and (if length > 0 then .[0].fingerprint? else true end)' "$BASELINE_PATH" >/dev/null 2>&1; then
    BEFORE_COUNT="$(jq 'length' "$REPORT_NORM_TMP")"
    jq -s '.[0] as $base | .[1] | map(select(.fingerprint as $f | ($base | map(.fingerprint) | index($f) | not)))' "$BASELINE_PATH" "$REPORT_NORM_TMP" > "${REPORT_NORM_TMP}.tmp"
    mv "${REPORT_NORM_TMP}.tmp" "$REPORT_NORM_TMP"
    log "Baseline applied: $((BEFORE_COUNT - $(jq 'length' "$REPORT_NORM_TMP"))) findings ignored."
  else
    warn "Baseline invalid or malformed; skipping."
  fi
fi

# Statistiques et Rapport Final OPA
STATS=$(jq -n --argjson f "$(cat "$REPORT_NORM_TMP")" '{
  CRITICAL: ($f | map(select(.severity=="CRITICAL")) | length),
  HIGH: ($f | map(select(.severity=="HIGH")) | length),
  MEDIUM: ($f | map(select(.severity=="MEDIUM")) | length),
  LOW: ($f | map(select(.severity=="LOW")) | length),
  TOTAL: ($f | length)
}')

jq -n \
  --arg tool "gitleaks" \
  --arg branch "${CI_COMMIT_REF_NAME:-$(git rev-parse --abbrev-ref HEAD 2>/dev/null)}" \
  --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson stats "$STATS" \
  --argjson findings "$(cat "$REPORT_NORM_TMP")" \
  '{tool: $tool, branch: $branch, timestamp: $timestamp, stats: $stats, findings: $findings}' > "$REPORT_OUT"

log "Done. Findings: $(jq -r '.stats.TOTAL' "$REPORT_OUT") | Report: $REPORT_OUT"
exit 0