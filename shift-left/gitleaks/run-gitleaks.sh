#!/usr/bin/env bash
set -euo pipefail

############################################
# CloudSentinel - Gitleaks Wrapper v5.0 (PFE)
# - Local/CI dual mode
# - Produces OPA-ready JSON
# - Baseline supported (optional)
# - NEVER blocks on findings (exit 0). OPA decides.
# - Exit 2 only on technical errors.
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

# Controls
USE_BASELINE="${USE_BASELINE:-true}"          # true|false
SCAN_TARGET="${SCAN_TARGET:-staged}"          # staged|repo (local only)
# CI default: 300s (5min) to prevent pipeline stalls; local: unlimited
if [[ -n "${CI:-}" ]]; then
  TIMEOUT_SEC="${CLOUDSENTINEL_TIMEOUT:-300}"
else
  TIMEOUT_SEC="${CLOUDSENTINEL_TIMEOUT:-0}"
fi

OUT_DIR="${OUT_DIR:-$REPO_ROOT/.cloudsentinel}"
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

# Determine mode/range (accept from env, validate, fallback to CI detection)
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

log "Starting scan (mode=$SCAN_MODE)..."

set +e
RC=0

if [[ "$SCAN_MODE" == "local" ]]; then
  if [[ "$SCAN_TARGET" == "repo" ]]; then
    log "Local: full repository"
    run_cmd gitleaks detect --source "$REPO_ROOT" --redact --config "$CONFIG_PATH" --report-format json --report-path "$REPORT_RAW_TMP"
    RC=$?
  else
    log "Local: staged files"
    run_cmd gitleaks protect --staged --redact --config "$CONFIG_PATH" --report-format json --report-path "$REPORT_RAW_TMP"
    RC=$?
  fi
else
  if [[ "$USE_RANGE" == "true" ]]; then
    log "CI: commit range $BASE...$HEAD"
    run_cmd gitleaks detect --source "$REPO_ROOT" --commit-range "$BASE...$HEAD" --redact --config "$CONFIG_PATH" --report-format json --report-path "$REPORT_RAW_TMP"
    RC=$?
  else
    log "CI: full repository"
    run_cmd gitleaks detect --source "$REPO_ROOT" --redact --config "$CONFIG_PATH" --report-format json --report-path "$REPORT_RAW_TMP"
    RC=$?
  fi
fi
set -e

[[ "${RC:-0}" -gt 1 ]] && { err "gitleaks failed (rc=$RC)"; exit 2; }

jq -e 'type=="array"' "$REPORT_RAW_TMP" >/dev/null 2>&1 || { err "Invalid JSON report"; exit 2; }

cp "$REPORT_RAW_TMP" "$REPORT_RAW_OUT"

# Normalize
jq '
  def norm_sev(x):
    if (x|type)=="string" and (x|length)>0 then (x|ascii_upcase) else "MEDIUM" end;

  def mk_fp(x):
    if (x.Fingerprint? and (x.Fingerprint|type)=="string" and (x.Fingerprint|length)>0) then
      x.Fingerprint
    else
      "fp:" + ([
        (x.RuleID // "unknown"),
        (x.File // "unknown"),
        ((x.StartLine // 0)|tostring),
        ((x.EndLine // 0)|tostring)
      ] | join("|"))
    end;

  map({
    rule_id: (.RuleID // "unknown"),
    description: (.Description // "unknown"),
    file: (.File // "unknown"),
    start_line: (.StartLine // 0),
    end_line: (.EndLine // 0),
    severity: norm_sev(.Severity // "MEDIUM"),
    fingerprint: mk_fp(.),
    secret: "REDACTED"
  })
  | unique_by(.fingerprint + "|" + .file + "|" + (.start_line|tostring))
' "$REPORT_RAW_TMP" > "$REPORT_NORM_TMP"

# Baseline (optional)
if [[ "$USE_BASELINE" == "true" && -f "$BASELINE_PATH" ]]; then
  if jq -e 'type=="array"' "$BASELINE_PATH" >/dev/null 2>&1; then
    BEFORE_COUNT="$(jq 'length' "$REPORT_NORM_TMP")"
    log "Applying baseline..."
    jq -s '
      .[0] as $baseline | .[1] as $current |
      $current | map(select(.fingerprint as $fp | ($baseline | map(.fingerprint) | index($fp)) | not))
    ' "$BASELINE_PATH" "$REPORT_NORM_TMP" > "${REPORT_NORM_TMP}.filtered"
    mv "${REPORT_NORM_TMP}.filtered" "$REPORT_NORM_TMP"
    AFTER_COUNT="$(jq 'length' "$REPORT_NORM_TMP")"
    log "Baseline excluded $((BEFORE_COUNT - AFTER_COUNT)) finding(s); remaining=$AFTER_COUNT"
  else
    warn "Baseline invalid; skipping"
  fi
fi

# Stats
CRITICAL_COUNT="$(jq '[.[] | select(.severity=="CRITICAL")] | length' "$REPORT_NORM_TMP")"
HIGH_COUNT="$(jq '[.[] | select(.severity=="HIGH")] | length' "$REPORT_NORM_TMP")"
MEDIUM_COUNT="$(jq '[.[] | select(.severity=="MEDIUM")] | length' "$REPORT_NORM_TMP")"
LOW_COUNT="$(jq '[.[] | select(.severity=="LOW")] | length' "$REPORT_NORM_TMP")"
TOTAL_COUNT="$(jq 'length' "$REPORT_NORM_TMP")"

# Metadata
GITLEAKS_VERSION="$(gitleaks version 2>/dev/null | head -n1 || echo "unknown")"
BRANCH="${CI_COMMIT_REF_NAME:-${GITHUB_REF_NAME:-$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")}}"
COMMIT="${CI_COMMIT_SHA:-${GITHUB_SHA:-$(git rev-parse HEAD 2>/dev/null || echo "unknown")}}"
EVENT_TYPE="${CI_PIPELINE_SOURCE:-${GITHUB_EVENT_NAME:-unknown}}"

# Output
jq -n \
  --arg tool "gitleaks" \
  --arg version "$GITLEAKS_VERSION" \
  --arg scan_mode "$SCAN_MODE" \
  --arg repository "$REPO_ROOT" \
  --arg branch "$BRANCH" \
  --arg commit "$COMMIT" \
  --arg event_type "$EVENT_TYPE" \
  --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson findings "$(cat "$REPORT_NORM_TMP")" \
  --argjson critical "$CRITICAL_COUNT" \
  --argjson high "$HIGH_COUNT" \
  --argjson medium "$MEDIUM_COUNT" \
  --argjson low "$LOW_COUNT" \
  --argjson total "$TOTAL_COUNT" \
'{
  tool: $tool,
  version: $version,
  scan_mode: $scan_mode,
  repository: $repository,
  branch: $branch,
  commit: $commit,
  event_type: $event_type,
  timestamp: $timestamp,
  findings: $findings,
  stats: {CRITICAL: $critical, HIGH: $high, MEDIUM: $medium, LOW: $low, TOTAL: $total}
}' > "$REPORT_OUT"

# Summary
if [[ "$TOTAL_COUNT" -eq 0 ]]; then
  log "OK: No secrets detected"
else
  warn "Found $TOTAL_COUNT finding(s) (CRITICAL=$CRITICAL_COUNT, HIGH=$HIGH_COUNT, MEDIUM=$MEDIUM_COUNT, LOW=$LOW_COUNT)"
  jq -r '
    sort_by(.file, .severity, .description, .start_line)
    | group_by(.file + "|" + .description + "|" + .severity)
    | map({file: .[0].file, type: .[0].description, severity: .[0].severity, lines: ([.[].start_line] | unique | sort)})
    | .[]
    | "[" + .severity + "] " + .file + " | " + .type + " | lines: " + (.lines | map(tostring) | join(","))
  ' "$REPORT_NORM_TMP"
fi

log "Reports: raw=$REPORT_RAW_OUT, opa=$REPORT_OUT"
exit 0