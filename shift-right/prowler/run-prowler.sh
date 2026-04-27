#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# CloudSentinel — Prowler v4 Azure Compliance Sensor
#
# Runs Prowler against the live Azure subscription (CIS Azure 2.0 + additional
# check families), converts OCSF output to DefectDojo Generic Findings format,
# and writes .cloudsentinel/prowler_generic_findings.json for the upload job.
#
# This script is the sensor layer: it detects live misconfigurations that
# Terraform drift detection cannot see (IAM over-privilege, missing MFA,
# unencrypted disks, exposed storage, disabled audit logs).
#
# Exit codes from Prowler that require special handling:
#   0 — scan complete, no findings above severity threshold
#   3 — scan complete, FAIL findings exist (this is the NORMAL state)
#   other — hard failure: auth error, network, config mismatch
#
# Required env vars:
#   ARM_CLIENT_ID, ARM_CLIENT_SECRET, ARM_TENANT_ID, ARM_SUBSCRIPTION_ID,
#   PROWLER_OUTPUT_DIR
# =============================================================================

# ── Colors & log helpers ─────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[prowler]${NC} INFO  $*"; }
log_ok()   { echo -e "${GREEN}[prowler]${NC} ${BOLD}OK${NC}    $*"; }
log_warn() { echo -e "${YELLOW}[prowler]${NC} WARN  $*" >&2; }
log_err()  { echo -e "${RED}[prowler]${NC} ${BOLD}ERROR${NC} $*" >&2; }

# ── _write_degraded ───────────────────────────────────────────────────────────
# Writes a valid empty Generic Findings payload with DEGRADED metadata.
# Mirrors the DEGRADED pattern used by fetch_drift_exceptions.py so downstream
# upload job can always import (zero findings is a valid DefectDojo import).
_write_degraded() {
  local reason="${1:-unknown}"
  jq -n \
    --arg reason "$reason" \
    --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg tool "prowler" \
    '{
      meta: {
        mode: "DEGRADED",
        reason: $reason,
        tool: $tool,
        timestamp: $timestamp
      },
      findings: []
    }' > "${GENERIC_FINDINGS_FILE}"
  log_warn "DEGRADED payload written → ${GENERIC_FINDINGS_FILE} (reason: ${reason})"
}

# ── Variables ────────────────────────────────────────────────────────────────

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

TIMESTAMP="$(date -u +"%Y%m%dT%H%M%SZ")"
OUTPUT_DIR="${PROWLER_OUTPUT_DIR:-shift-right/prowler/output}"
CLOUDSENTINEL_DIR=".cloudsentinel"
GENERIC_FINDINGS_FILE="${CLOUDSENTINEL_DIR}/prowler_generic_findings.json"
CONFIG_FILE="shift-right/prowler/config-azure.yaml"

# ── Validate required env vars ────────────────────────────────────────────────
# Fail immediately with a clear message rather than letting Prowler crash mid-run
# with an opaque Azure SDK authentication error.

REQUIRED_VARS=(
  ARM_CLIENT_ID
  ARM_CLIENT_SECRET
  ARM_TENANT_ID
  ARM_SUBSCRIPTION_ID
  PROWLER_OUTPUT_DIR
)

for var in "${REQUIRED_VARS[@]}"; do
  if [[ -z "${!var:-}" ]]; then
    log_err "Required environment variable '${var}' is not set."
    log_err "Set all of: ${REQUIRED_VARS[*]}"
    exit 1
  fi
done

command -v jq  >/dev/null 2>&1 || { log_err "jq is required but not found in PATH"; exit 1; }
command -v prowler >/dev/null 2>&1 || { log_err "prowler is required but not found in PATH"; exit 1; }

mkdir -p "${OUTPUT_DIR}" "${CLOUDSENTINEL_DIR}/dojo-responses"

# ── Azure SDK credential mapping ──────────────────────────────────────────────
# Prowler v4 --sp-env-auth reads AZURE_* env vars via the Azure Identity SDK.
# Terraform uses ARM_* convention. Map here; never hardcode values.
export AZURE_CLIENT_ID="${ARM_CLIENT_ID}"
export AZURE_CLIENT_SECRET="${ARM_CLIENT_SECRET}"
export AZURE_TENANT_ID="${ARM_TENANT_ID}"

log_info "Prowler v4 compliance sensor starting"
log_info "Subscription : ${ARM_SUBSCRIPTION_ID}"
log_info "Tenant       : ${ARM_TENANT_ID}"
log_info "Output dir   : ${OUTPUT_DIR}"
log_info "Config file  : ${CONFIG_FILE}"
log_info "Run ID       : ${TIMESTAMP}"

# ── Run Prowler ───────────────────────────────────────────────────────────────
# --sp-env-auth    : authenticate via AZURE_CLIENT_ID/SECRET/TENANT_ID
# --compliance     : CIS Azure Foundations Benchmark 2.0
# --severity       : Medium and above only (Info/Low excluded — too noisy for DefectDojo)
# --output-formats : OCSF schema (Prowler v4 native); consumed by post-processing below
# --config-file    : check-level parameters (thresholds, trusted CIDRs, etc.)
# --mutelist-file  : dynamic exception list generated from DefectDojo risk acceptances
#                    (present only when fetch_prowler_exceptions.py ran successfully)

MUTELIST_FILE="shift-right/prowler/mutelist-azure.yaml"
PROWLER_EXTRA_ARGS=()
if [[ -f "${MUTELIST_FILE}" ]]; then
  PROWLER_EXTRA_ARGS+=("--mutelist-file" "${MUTELIST_FILE}")
  log_info "Mutelist     : ${MUTELIST_FILE} (risk-accepted exceptions active)"
else
  log_info "Mutelist     : not found — scan without exceptions"
fi

set +e
prowler azure \
  --subscription-ids "${ARM_SUBSCRIPTION_ID}" \
  --tenant-id "${ARM_TENANT_ID}" \
  --sp-env-auth \
  --compliance cis_azure_2.0 \
  --severity medium high critical \
  --output-formats json-ocsf \
  --output-path "${OUTPUT_DIR}" \
  --output-filename "prowler-output-${TIMESTAMP}" \
  --config-file "${CONFIG_FILE}" \
  "${PROWLER_EXTRA_ARGS[@]}"
PROWLER_EXIT="${?}"
set -e

# ── Exit code handling ────────────────────────────────────────────────────────
# Prowler signals "scan ran successfully + findings exist" via exit code 3.
# This is the expected state for any real Azure environment. Treating it as
# failure would permanently break the sensor job.

case "${PROWLER_EXIT}" in
  0)
    log_ok "Prowler scan complete — no findings above severity threshold"
    ;;
  3)
    # Findings exist: normal for compliance sensors. The findings are in the
    # OCSF output file and will be uploaded to DefectDojo by the upload job.
    log_warn "Prowler scan complete — FAIL findings detected (exit 3, treated as success)"
    ;;
  *)
    log_err "Prowler terminated with unexpected exit code ${PROWLER_EXIT}"
    log_err "Likely causes: Azure auth failure, network unreachable, invalid config."
    log_err "Check output above for Azure SDK or Prowler startup errors."
    exit 1
    ;;
esac

# ── Locate OCSF output file ───────────────────────────────────────────────────
# Try the explicitly-named timestamped file first. Fall back to newest *.ocsf.json
# in the output dir in case Prowler generated its own filename (version-dependent).

OCSF_FILE=""
if [[ -f "${OUTPUT_DIR}/prowler-output-${TIMESTAMP}.ocsf.json" ]]; then
  OCSF_FILE="${OUTPUT_DIR}/prowler-output-${TIMESTAMP}.ocsf.json"
elif ls "${OUTPUT_DIR}"/*.ocsf.json > /dev/null 2>&1; then
  OCSF_FILE="$(ls -t "${OUTPUT_DIR}"/*.ocsf.json | head -n1)"
fi

if [[ -z "${OCSF_FILE}" ]]; then
  # Prowler ran (exit 0/3) but produced no file — unexpected but not fatal.
  # Write a DEGRADED payload so the upload job can close stale DefectDojo findings.
  log_warn "No *.ocsf.json found in ${OUTPUT_DIR} — writing DEGRADED findings payload."
  _write_degraded "ocsf_file_missing"
  exit 0
fi

log_info "OCSF source  : ${OCSF_FILE}"

# ── OCSF → DefectDojo Generic Findings conversion ─────────────────────────────
# OCSF severity_id (Prowler v4):
#   1 = Informational  2 = Low  3 = Medium  4 = High  5 = Critical
#
# Filter: status_id == 2 (FAIL) only. Passing checks are NOT DefectDojo findings.
#
# unique_id_from_tool format guarantees per-resource deduplication across runs:
#   prowler:{check_id}:{azure_arm_resource_uid}
# This lets DefectDojo close findings whose resources no longer exist.

jq -c \
  --arg scan_date "$(date -u +"%Y-%m-%d")" \
  --arg subscription_id "${ARM_SUBSCRIPTION_ID}" \
  '
  def dojo_severity($id):
    if   $id == 1 then "Info"
    elif $id == 2 then "Low"
    elif $id == 3 then "Medium"
    elif $id == 4 then "High"
    elif $id == 5 then "Critical"
    else "Medium"
    end;

  def safe($v): ($v // "" | tostring);

  # Support both JSON array (Prowler v4 default) and single-object OCSF output.
  (if type == "array" then .[] else . end)

  # Only FAIL findings become DefectDojo records.
  | select(
      .status_id == 2
      or ((.status // "") | ascii_downcase) == "fail"
    )

  | {
      title: (
        "Prowler: " + safe(.finding_info.title // .metadata.event_code // "Unknown check")
      ),
      severity:         dojo_severity(.severity_id),
      date:             $scan_date,
      description: (
        "**CloudSentinel Prowler CIS Azure 2.0 Finding**\n\n"
        + "- Check ID : " + safe(.metadata.event_code // .finding_info.uid) + "\n"
        + "- Resource : " + safe(.resources[0].uid // .resources[0].name // "unknown") + "\n"
        + "- Region   : " + safe(.resources[0].region // .cloud.region // "global") + "\n"
        + "- Sub      : " + $subscription_id + "\n"
        + "- Detail   : " + safe(.status_detail // .finding_info.desc) + "\n\n"
        + safe(.finding_info.desc // .status_detail)
      ),
      mitigation: safe(
        .remediation.desc
        // .remediation.recommendation.text
        // "See Prowler remediation guidance for check " + safe(.metadata.event_code)
      ),
      references: safe(
        ((.remediation.references // []) | join(", "))
      ),
      unique_id_from_tool: (
        "prowler:"
        + safe(.metadata.event_code // .finding_info.uid)
        + ":"
        + safe(.resources[0].uid // .resources[0].name // "unknown")
      ),
      vuln_id_from_tool: (
        "prowler:" + safe(.metadata.event_code // .finding_info.uid)
      ),
      component_name: safe(
        .resources[0].uid // .resources[0].name // "unknown"
      )
    }
  ' "${OCSF_FILE}" \
  | jq -s '{findings: .}' \
  > "${GENERIC_FINDINGS_FILE}"

FINDING_COUNT="$(jq '.findings | length' "${GENERIC_FINDINGS_FILE}")"
log_ok "Converted ${FINDING_COUNT} FAIL finding(s) → ${GENERIC_FINDINGS_FILE}"
