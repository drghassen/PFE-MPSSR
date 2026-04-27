#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# CloudSentinel CI — Cross-Signal Correlation (G6)
#
# Correlates Prowler compliance findings with Terraform drift items that share
# the same Azure resource. When both signals target the same resource in a
# single pipeline run, the combined risk exceeds either signal in isolation.
#
# Matching criteria (either condition triggers a correlation):
#   1. Direct UID   — prowler finding's component_name equals a drift item's
#                     address or resource_id field
#   2. Type prefix  — drift item's resource type maps (via correlation_mappings.json)
#                     to a Prowler check-ID prefix that matches the finding
#
# Inputs (produced by upstream decide-stage jobs):
#   .cloudsentinel/prowler_generic_findings.json
#   shift-right/drift-engine/output/drift-report.json
#   .cloudsentinel/opa_prowler_decision.json   (severity enrichment)
#   .cloudsentinel/opa_drift_decision.json     (severity enrichment)
#
# Outputs:
#   .cloudsentinel/correlation_report.json
#   .cloudsentinel/correlation.env
#
# This step is enrichment only — it NEVER exits non-zero for missing or
# malformed inputs. The pipeline gate for CRITICAL_CONFIRMED is the env file.
#
# Required tools: bash, jq, sha256sum (all present in the scan-tools image).
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[correlate]${NC} INFO  $*"; }
log_ok()   { echo -e "${GREEN}[correlate]${NC} ${BOLD}OK${NC}    $*"; }
log_warn() { echo -e "${YELLOW}[correlate]${NC} WARN  $*" >&2; }
log_err()  { echo -e "${RED}[correlate]${NC} ${BOLD}ERROR${NC} $*" >&2; }

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

PROWLER_FINDINGS="${PROWLER_FINDINGS_PATH:-.cloudsentinel/prowler_generic_findings.json}"
DRIFT_REPORT="${DRIFT_REPORT_PATH:-shift-right/drift-engine/output/drift-report.json}"
OPA_PROWLER_DECISION="${OPA_PROWLER_DECISION_PATH:-.cloudsentinel/opa_prowler_decision.json}"
OPA_DRIFT_DECISION="${OPA_DRIFT_DECISION_PATH:-.cloudsentinel/opa_drift_decision.json}"
MAPPINGS_FILE="${CORRELATION_MAPPINGS_PATH:-ci/scripts/shift-right/correlation_mappings.json}"
OUTPUT_DIR="${CORRELATION_OUTPUT_DIR:-.cloudsentinel}"
CORRELATION_REPORT="${OUTPUT_DIR}/correlation_report.json"
CORRELATION_ENV="${OUTPUT_DIR}/correlation.env"

GENERATED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

command -v jq       >/dev/null 2>&1 || { log_err "jq is required but not found in PATH";       exit 1; }
command -v sha256sum >/dev/null 2>&1 || { log_err "sha256sum is required but not found in PATH"; exit 1; }

mkdir -p "${OUTPUT_DIR}"

# ── _write_empty_report ───────────────────────────────────────────────────────
# Writes a valid report with correlations: [] and the correct counts.
_write_empty_report() {
  local prowler_count="${1:-0}"
  local drift_count="${2:-0}"
  jq -n \
    --arg   generated_at   "${GENERATED_AT}" \
    --argjson prowler_count "${prowler_count}" \
    --argjson drift_count   "${drift_count}" \
    '{
      meta: {
        generated_at:               $generated_at,
        prowler_findings_evaluated: $prowler_count,
        drift_items_evaluated:      $drift_count,
        correlations_found:         0
      },
      correlations: []
    }' > "${CORRELATION_REPORT}"
  {
    echo "CORRELATION_COUNT=0"
    echo "CORRELATION_CRITICAL_CONFIRMED=0"
    echo "CORRELATION_HIGH_CONFIRMED=0"
  } > "${CORRELATION_ENV}"
}

# ── _write_degraded_report ────────────────────────────────────────────────────
# Written only on jq parse errors so downstream jobs can detect degraded state.
_write_degraded_report() {
  local reason="${1:-parse_error}"
  log_warn "Writing DEGRADED correlation report (reason: ${reason})"
  jq -n \
    --arg generated_at "${GENERATED_AT}" \
    --arg reason        "${reason}" \
    '{
      meta: {
        generated_at:               $generated_at,
        mode:                       "DEGRADED",
        reason:                     $reason,
        prowler_findings_evaluated: 0,
        drift_items_evaluated:      0,
        correlations_found:         0
      },
      correlations: []
    }' > "${CORRELATION_REPORT}"
  {
    echo "CORRELATION_COUNT=0"
    echo "CORRELATION_CRITICAL_CONFIRMED=0"
    echo "CORRELATION_HIGH_CONFIRMED=0"
  } > "${CORRELATION_ENV}"
}

# ── Load Prowler findings ──────────────────────────────────────────────────────
PROWLER_COUNT=0
PROWLER_FINDINGS_DATA="[]"

if [[ ! -f "${PROWLER_FINDINGS}" ]]; then
  log_warn "Prowler findings absent: ${PROWLER_FINDINGS}"
else
  if ! PROWLER_FINDINGS_DATA="$(jq '.findings // []' "${PROWLER_FINDINGS}" 2>/dev/null)"; then
    log_warn "jq parse error on ${PROWLER_FINDINGS}"
    _write_degraded_report "prowler_parse_error"
    exit 0
  fi
  PROWLER_COUNT="$(printf '%s' "${PROWLER_FINDINGS_DATA}" | jq 'length' 2>/dev/null || echo 0)"
fi

# ── Load drift report ─────────────────────────────────────────────────────────
DRIFT_COUNT=0
DRIFT_ITEMS_DATA="[]"

if [[ ! -f "${DRIFT_REPORT}" ]]; then
  log_warn "Drift report absent: ${DRIFT_REPORT}"
else
  if ! DRIFT_ITEMS_DATA="$(jq '.drift.items // []' "${DRIFT_REPORT}" 2>/dev/null)"; then
    log_warn "jq parse error on ${DRIFT_REPORT}"
    _write_degraded_report "drift_parse_error"
    exit 0
  fi
  DRIFT_COUNT="$(printf '%s' "${DRIFT_ITEMS_DATA}" | jq 'length' 2>/dev/null || echo 0)"
fi

# ── Short-circuit: nothing to correlate ───────────────────────────────────────
if [[ "${PROWLER_COUNT}" -eq 0 ]] || [[ "${DRIFT_COUNT}" -eq 0 ]]; then
  log_info "No correlations possible (prowler_findings=${PROWLER_COUNT}, drift_items=${DRIFT_COUNT})"
  _write_empty_report "${PROWLER_COUNT}" "${DRIFT_COUNT}"
  exit 0
fi

log_info "Evaluating ${PROWLER_COUNT} Prowler finding(s) against ${DRIFT_COUNT} drift item(s)"

# ── Drift severity lookup from OPA decision ────────────────────────────────────
# Builds { "terraform_address": "CRITICAL|HIGH|MEDIUM|LOW" } from OPA output.
DRIFT_SEVERITY_MAP="{}"
if [[ -f "${OPA_DRIFT_DECISION}" ]]; then
  if ! DRIFT_SEVERITY_MAP="$(jq '
    (.result.effective_violations // [])
    | map(select(.resource_id != null and .resource_id != ""))
    | map({ key: .resource_id, value: (.severity // "MEDIUM") })
    | from_entries
  ' "${OPA_DRIFT_DECISION}" 2>/dev/null)"; then
    log_warn "Could not parse ${OPA_DRIFT_DECISION} — defaulting all drift severities to MEDIUM"
    DRIFT_SEVERITY_MAP="{}"
  fi
fi

# ── Resource type → Prowler check prefix mappings ─────────────────────────────
# Read at runtime so the mapping file is independently updatable.
MAPPINGS="{}"
if [[ ! -f "${MAPPINGS_FILE}" ]]; then
  log_warn "Mappings file absent: ${MAPPINGS_FILE} — type-prefix matching disabled"
else
  if ! MAPPINGS="$(jq '.' "${MAPPINGS_FILE}" 2>/dev/null)"; then
    log_warn "jq parse error on ${MAPPINGS_FILE} — type-prefix matching disabled"
    MAPPINGS="{}"
  fi
fi

# ── Correlation engine ─────────────────────────────────────────────────────────
# Produces a JSON array of raw records (correlation_id added in the bash loop below).
#
# Matching (any condition triggers a correlated pair):
#   • Direct UID   — p.component_name == d.address  OR  p.component_name == d.resource_id
#   • Type prefix  — mappings[d.type] contains a prefix that p's check_id starts with
#
# combined_risk escalation (highest matching rule wins):
#   CRITICAL (prowler) + any drift            → CRITICAL_CONFIRMED
#   HIGH     (prowler) + CRITICAL|HIGH drift  → HIGH_CONFIRMED
#   MEDIUM   (prowler) + CRITICAL drift       → HIGH_CONFIRMED
#   otherwise                                 → CORRELATED
RAW_CORRELATIONS="$(jq -n \
  --argjson prowler          "${PROWLER_FINDINGS_DATA}" \
  --argjson drift            "${DRIFT_ITEMS_DATA}" \
  --argjson drift_severities "${DRIFT_SEVERITY_MAP}" \
  --argjson mappings         "${MAPPINGS}" \
  '
  [
    $drift[]   as $d |
    $prowler[] as $p |

    # Strip "prowler:" prefix from vuln_id_from_tool to get the bare check_id.
    (
      if (($p.vuln_id_from_tool // "") | startswith("prowler:"))
      then ($p.vuln_id_from_tool)[8:]
      else ($p.vuln_id_from_tool // "")
      end
    ) as $check_id |

    # Normalize prowler severity to uppercase for risk-escalation comparison.
    (($p.severity // "medium") | ascii_upcase) as $psev |

    # Drift severity comes from OPA decision (already uppercase); default MEDIUM.
    ($drift_severities[$d.address] // "MEDIUM") as $dsev |

    # Type-prefix match: does the drift resource type map to a prefix the
    # check_id starts with? Uses $mappings loaded at runtime from mappings file.
    (($mappings[($d.type // "")] // []) | any(. as $pfx | $check_id | startswith($pfx))) as $type_match |

    select(
      ($p.component_name != null and $p.component_name != "") and (
        ($p.component_name == ($d.address // ""))
        or ($d.resource_id != null and $d.resource_id != ""
            and $p.component_name == $d.resource_id)
        or $type_match
      )
    ) |

    # combined_risk: highest-priority rule wins.
    (
      if   ($psev == "CRITICAL") then "CRITICAL_CONFIRMED"
      elif ($psev == "HIGH"   and ($dsev == "CRITICAL" or $dsev == "HIGH")) then "HIGH_CONFIRMED"
      elif ($psev == "MEDIUM" and  $dsev == "CRITICAL") then "HIGH_CONFIRMED"
      else "CORRELATED"
      end
    ) as $combined_risk |

    {
      prowler_uid:      ($p.unique_id_from_tool // ""),
      prowler_check_id: $check_id,
      prowler_severity: ($p.severity // "medium"),
      drift_address:    ($d.address  // ""),
      drift_severity:   $dsev,
      resource_uid: (
        if   ($p.component_name == ($d.address // "")) then ($d.address // "")
        elif ($d.resource_id != null and $d.resource_id != ""
              and $p.component_name == $d.resource_id) then $d.resource_id
        else ($d.address // "")
        end
      ),
      combined_risk: $combined_risk
    }
  ]
  # One record per (prowler_finding, drift_item) pair — no duplicates from
  # multiple match conditions triggering on the same pair.
  | unique_by(.prowler_uid + "::" + .drift_address)
  '
)"

CORRELATION_COUNT="$(printf '%s' "${RAW_CORRELATIONS}" | jq 'length' 2>/dev/null || echo 0)"

if [[ "${CORRELATION_COUNT}" -eq 0 ]]; then
  log_info "No correlations found between ${PROWLER_COUNT} Prowler finding(s) and ${DRIFT_COUNT} drift item(s)"
  _write_empty_report "${PROWLER_COUNT}" "${DRIFT_COUNT}"
  exit 0
fi

log_info "Found ${CORRELATION_COUNT} correlation(s) — computing deterministic IDs"

# ── Add correlation_id (sha256, deterministic) ────────────────────────────────
# Format: sha256("<unique_id_from_tool>:<drift_address>") | first 16 hex chars
# Same inputs always yield the same ID regardless of run order.
FINAL_CORRELATIONS="[]"
while IFS= read -r raw_record; do
  prowler_uid="$(printf '%s' "${raw_record}" | jq -r '.prowler_uid')"
  drift_address="$(printf '%s' "${raw_record}" | jq -r '.drift_address')"
  corr_id="$(printf '%s:%s' "${prowler_uid}" "${drift_address}" | sha256sum | cut -c1-16)"
  enriched="$(printf '%s' "${raw_record}" | jq \
    --arg cid "${corr_id}" \
    --arg ts  "${GENERATED_AT}" \
    '. + { correlation_id: $cid, correlated_at: $ts }')"
  FINAL_CORRELATIONS="$(printf '%s' "${FINAL_CORRELATIONS}" | jq \
    --argjson rec "${enriched}" '. + [$rec]')"
done < <(printf '%s' "${RAW_CORRELATIONS}" | jq -c '.[]')

# ── Write correlation report ───────────────────────────────────────────────────
CRITICAL_CONFIRMED="$(printf '%s' "${FINAL_CORRELATIONS}" | \
  jq '[.[] | select(.combined_risk == "CRITICAL_CONFIRMED")] | length')"
HIGH_CONFIRMED="$(printf '%s' "${FINAL_CORRELATIONS}" | \
  jq '[.[] | select(.combined_risk == "HIGH_CONFIRMED")] | length')"

jq -n \
  --arg   generated_at   "${GENERATED_AT}" \
  --argjson prowler_count "${PROWLER_COUNT}" \
  --argjson drift_count   "${DRIFT_COUNT}" \
  --argjson corr_count    "${CORRELATION_COUNT}" \
  --argjson correlations  "${FINAL_CORRELATIONS}" \
  '{
    meta: {
      generated_at:               $generated_at,
      prowler_findings_evaluated: $prowler_count,
      drift_items_evaluated:      $drift_count,
      correlations_found:         $corr_count
    },
    correlations: $correlations
  }' > "${CORRELATION_REPORT}"

{
  echo "CORRELATION_COUNT=${CORRELATION_COUNT}"
  echo "CORRELATION_CRITICAL_CONFIRMED=${CRITICAL_CONFIRMED}"
  echo "CORRELATION_HIGH_CONFIRMED=${HIGH_CONFIRMED}"
} > "${CORRELATION_ENV}"

log_ok "Correlation report: ${CORRELATION_REPORT}"
log_ok "  Total correlations    : ${CORRELATION_COUNT}"
if [[ "${CRITICAL_CONFIRMED}" -gt 0 ]]; then
  log_warn "  CRITICAL_CONFIRMED    : ${CRITICAL_CONFIRMED}  ← high-priority triage required"
else
  log_info "  CRITICAL_CONFIRMED    : ${CRITICAL_CONFIRMED}"
fi
log_info "  HIGH_CONFIRMED        : ${HIGH_CONFIRMED}"
log_info "Env file: ${CORRELATION_ENV}"
