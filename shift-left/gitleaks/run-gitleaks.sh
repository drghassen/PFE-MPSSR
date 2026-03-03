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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib_scanner_utils.sh"

REPO_ROOT="$(cs_get_repo_root)"

CONFIG_PATH="${CONFIG_PATH:-$REPO_ROOT/shift-left/gitleaks/gitleaks.toml}"
BASELINE_PATH="${BASELINE_PATH:-$REPO_ROOT/shift-left/gitleaks/.gitleaks-baseline.json}"

# Paramètres de performance et timeout
USE_BASELINE="${USE_BASELINE:-true}"
SCAN_TARGET="${SCAN_TARGET:-staged}"
MAX_SIZE_MB="${GITLEAKS_MAX_SIZE:-5}"

if [[ -n "${CI:-}" ]]; then
  TIMEOUT_SEC="${CLOUDSENTINEL_TIMEOUT:-300}"
else
  TIMEOUT_SEC="${CLOUDSENTINEL_TIMEOUT:-60}"
fi

OUT_DIR="$REPO_ROOT/.cloudsentinel"
mkdir -p "$OUT_DIR"

REPORT_RAW_TMP="$(mktemp -t gitleaks-raw.XXXXXX.json)"
REPORT_NORM_TMP="$(mktemp -t gitleaks-findings.XXXXXX.json)"
# Rule severity mapping artifacts (built from gitleaks.toml at runtime).
RULE_SEV_TSV_TMP="$(mktemp -t gitleaks-rule-sev.XXXXXX.tsv)"
RULE_SEV_MAP_TMP="$(mktemp -t gitleaks-rule-sev-map.XXXXXX.json)"
trap 'rm -f "$REPORT_RAW_TMP" "$REPORT_NORM_TMP" "$RULE_SEV_TSV_TMP" "$RULE_SEV_MAP_TMP"' EXIT

REPORT_RAW_OUT="$OUT_DIR/gitleaks_raw.json"
REPORT_OUT="$OUT_DIR/gitleaks_opa.json"

emit_not_run() {
  local reason=$1
  echo "[]" > "$REPORT_RAW_OUT"
  cs_emit_not_run "gitleaks" "$REPORT_OUT" "$reason" "$REPO_ROOT"
}

command -v gitleaks >/dev/null 2>&1 || { emit_not_run "gitleaks_binary_missing"; exit 0; }
[[ -f "$CONFIG_PATH" ]] || { emit_not_run "gitleaks_config_missing:$CONFIG_PATH"; exit 0; }

# Build an authoritative rule_id -> severity lookup directly from gitleaks.toml.
# This prevents downgrading findings when raw Gitleaks output omits `.Severity`.
awk '
  function trim(s) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s }
  function unquote(s) { s=trim(s); sub(/^"/, "", s); sub(/"$/, "", s); return s }
  function emit_rule(  sev_norm,tags_norm) {
    if (rule_id == "") { return }
    sev_norm = toupper(trim(rule_sev))
    tags_norm = tolower(rule_tags)

    # Severity is authoritative when defined in the rule.
    # If absent, infer from tags (critical/high/medium/low/info) to keep policy intent.
    if (sev_norm == "") {
      if (tags_norm ~ /critical/) sev_norm = "CRITICAL"
      else if (tags_norm ~ /high/) sev_norm = "HIGH"
      else if (tags_norm ~ /medium/) sev_norm = "MEDIUM"
      else if (tags_norm ~ /low/) sev_norm = "LOW"
      else if (tags_norm ~ /info|informational/) sev_norm = "INFO"
      else sev_norm = "MEDIUM"
    }

    # Enforce CloudSentinel severity enum values only.
    if (sev_norm != "CRITICAL" && sev_norm != "HIGH" && sev_norm != "MEDIUM" && sev_norm != "LOW" && sev_norm != "INFO") {
      sev_norm = "MEDIUM"
    }
    printf "%s\t%s\n", rule_id, sev_norm
  }

  /^\[\[rules\]\]/ {
    if (in_rules_block) emit_rule()
    in_rules_block = 1
    rule_id = ""
    rule_sev = ""
    rule_tags = ""
    next
  }

  in_rules_block {
    if ($0 ~ /^[[:space:]]*id[[:space:]]*=/) {
      split($0, p, "=")
      rule_id = unquote(substr($0, index($0, "=") + 1))
    } else if ($0 ~ /^[[:space:]]*severity[[:space:]]*=/) {
      split($0, p, "=")
      rule_sev = unquote(substr($0, index($0, "=") + 1))
    } else if ($0 ~ /^[[:space:]]*tags[[:space:]]*=/) {
      # Keep raw tags line for keyword inference when severity is not set.
      rule_tags = substr($0, index($0, "=") + 1)
    }
  }

  END {
    if (in_rules_block) emit_rule()
  }
' "$CONFIG_PATH" > "$RULE_SEV_TSV_TMP"

jq -Rn '
  reduce inputs as $line ({};
    ($line | split("\t")) as $parts
    | if ($parts | length) == 2 then . + { ($parts[0]): ($parts[1]) } else . end
  )
' "$RULE_SEV_TSV_TMP" > "$RULE_SEV_MAP_TMP"

GITLEAKS_VERSION="$(gitleaks version 2>/dev/null | head -n 1 | tr -d '\r' || echo unknown)"
[[ -z "$GITLEAKS_VERSION" ]] && GITLEAKS_VERSION="unknown"

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

if [[ "$RC" -gt 1 ]]; then
  emit_not_run "gitleaks_execution_error:rc=$RC"
  exit 2
fi

# Validation du JSON
jq -e 'type=="array"' "$REPORT_RAW_TMP" >/dev/null 2>&1 || { echo "[]" > "$REPORT_RAW_TMP"; }
cp "$REPORT_RAW_TMP" "$REPORT_RAW_OUT"

# Normalisation et Enrichissement (Auteur, Date, Commit)
jq --argjson rule_sev_map "$(cat "$RULE_SEV_MAP_TMP")" '
  def norm_sev(x):
    if (x|type)!="string" or (x|length)==0 then ""
    else
      (x
       | ascii_upcase
       | gsub("[^A-Z0-9_]"; ""))
      | if . == "CRITICAL" or . == "CRIT" or . == "SEV5" or . == "SEVERITY5" or . == "VERY_HIGH" then "CRITICAL"
        elif . == "HIGH" or . == "SEV4" or . == "SEVERITY4" then "HIGH"
        elif . == "MEDIUM" or . == "MODERATE" or . == "SEV3" or . == "SEVERITY3" then "MEDIUM"
        elif . == "LOW" or . == "MINOR" or . == "SEV2" or . == "SEVERITY2" then "LOW"
        elif . == "INFO" or . == "INFORMATIONAL" or . == "SEV1" or . == "SEVERITY1" or . == "UNKNOWN" then "INFO"
        else "" end
    end;

  # Resolve severity with strict precedence:
  # 1) gitleaks.toml rule mapping (authoritative for known rule_id)
  # 2) raw finding severity
  # 3) MEDIUM fallback for unknown/unmapped values
  def resolve_sev(x):
    (x.RuleID // "unknown") as $rule_id
    | (norm_sev($rule_sev_map[$rule_id] // "")) as $from_rule
    | (norm_sev(x.Severity // "")) as $from_finding
    | if $from_rule != "" then $from_rule
      elif $from_finding != "" then $from_finding
      else "MEDIUM" end;

  def mk_fp(x):
    if (x.Fingerprint? and (x.Fingerprint|type)=="string" and (x.Fingerprint|length)>0) then x.Fingerprint
    else "fp:" + ([ (x.RuleID // "unknown"), (x.File // "unknown"), ((x.StartLine // 0)|tostring) ] | join("|")) end;

  map({
    rule_id: (.RuleID // "unknown"),
    description: (.Description // "unknown"),
    file: (.File // "unknown"),
    start_line: (.StartLine // 0),
    severity: resolve_sev(.),
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
  INFO: ($f | map(select(.severity=="INFO")) | length),
  TOTAL: ($f | length),
  EXEMPTED: 0,
  FAILED: ($f | length),
  PASSED: 0
}')

# NOTE: has_findings is a SCAN OBSERVATION, not a gate decision.
# The block/allow decision is EXCLUSIVELY made by OPA (run-opa.sh).
jq -n \
  --arg tool "gitleaks" \
  --arg version "$GITLEAKS_VERSION" \
  --arg branch "${CI_COMMIT_REF_NAME:-$(git rev-parse --abbrev-ref HEAD 2>/dev/null)}" \
  --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson stats "$STATS" \
  --argjson findings "$(cat "$REPORT_NORM_TMP")" \
  '{tool: $tool, version: $version, has_findings: ($stats.TOTAL > 0), branch: $branch, timestamp: $timestamp, stats: $stats, findings: $findings}' > "$REPORT_OUT"

log "Done. Findings: $(jq -r '.stats.TOTAL' "$REPORT_OUT") | Report: $REPORT_OUT"
exit 0
