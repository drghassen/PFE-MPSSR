#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# CloudSentinel - Risk Acceptance Request Tool (DX)
# Description: Helper script for developers to request security exceptions in DefectDojo.
#              Provides a seamless CLI experience without touching the Git Repo.
# ==============================================================================

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

log_info() { echo -e "${CYAN}[INFO]${NC} $*"; }
log_err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_ok()   { echo -e "${GREEN}[OK]${NC} $*"; }

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --rule-id <ID>          The Rule ID (e.g., CKV_AWS_25) (Required)
  --resource <PATH|NAME>  The exact resource path or name (Required)
  --justification <TEXT>  Technical reason for the exception (Required)
  --expires-in-days <N>   Number of days until expiration (Default: 30)
  --urgent                Mark as Break Glass / Urgent

Environment:
  DOJO_URL         DefectDojo URL (e.g., https://dojo.internal)
  DOJO_API_KEY     Your personal or service API key
EOF
    exit 1
}

RULE_ID=""
RESOURCE=""
JUSTIFICATION=""
EXPIRES_IN=30
URGENT=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --rule-id) RULE_ID="$2"; shift 2 ;;
    --resource) RESOURCE="$2"; shift 2 ;;
    --justification) JUSTIFICATION="$2"; shift 2 ;;
    --expires-in-days) EXPIRES_IN="$2"; shift 2 ;;
    --urgent) URGENT=true; shift 1 ;;
    -h|--help) usage ;;
    *) log_err "Unknown option: $1"; usage ;;
  esac
done

[[ -z "$RULE_ID" ]] && { log_err "Missing --rule-id"; usage; }
[[ -z "$RESOURCE" ]] && { log_err "Missing --resource"; usage; }
[[ -z "$JUSTIFICATION" ]] && { log_err "Missing --justification"; usage; }

DOJO_URL="${DOJO_URL:-}"
DOJO_API_KEY="${DOJO_API_KEY:-}"

echo -e "${BOLD}Generating Risk Acceptance Request${NC}"
echo "-----------------------------------"
echo -e "Rule ID       : ${YELLOW}$RULE_ID${NC}"
echo -e "Resource      : ${YELLOW}$RESOURCE${NC}"
echo -e "Expiration    : ${YELLOW}$EXPIRES_IN days${NC}"
echo -e "Justification : $JUSTIFICATION"
[[ "$URGENT" == "true" ]] && echo -e "Mode          : ${RED}🚨 URGENT / BREAK GLASS 🚨${NC}"
echo "-----------------------------------"

if [[ -z "$DOJO_URL" || -z "$DOJO_API_KEY" ]]; then
    log_err "DOJO_URL or DOJO_API_KEY environment variables are not set."
    log_info "Simulating the request (Dry-run mode)..."
    sleep 1
    log_ok "Simulation successful. In production, this would be Sent to DefectDojo."
    exit 0
fi

log_info "Contacting DefectDojo API at $DOJO_URL..."

# In a real environment, you might need to create an Engagement, a Finding, 
# and then link the Risk Acceptance to that Finding.
# The Dojo v2 API handles Risk Acceptance payload structure.
PAYLOAD=$(cat <<EOF
{
  "name": "$RULE_ID",
  "description": "$JUSTIFICATION",
  "path": "$RESOURCE",
  "expiration_date": "$(date -u -d "+${EXPIRES_IN} days" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -v+${EXPIRES_IN}d +"%Y-%m-%dT%H:%M:%SZ")",
  "owner": "dev-system@example.com",
  "is_active": false
}
EOF
)

# NOTE: For PFE demonstration purposes we send a POST to the RA endpoint.
# The response would typically be intercepted and sent to an AppSec team
# for approval ('is_active' becomes true once approved).
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${DOJO_URL}/api/v2/risk_acceptance/" \
     -H "Authorization: Token ${DOJO_API_KEY}" \
     -H "Content-Type: application/json" \
     -d "$PAYLOAD")

if [[ "$HTTP_STATUS" == "201" || "$HTTP_STATUS" == "200" ]]; then
    log_ok "Risk Acceptance successfully submitted."
    log_info "Status is currently PENDING. Wait for AppSec Approval."
else
    log_err "Failed to submit RA. DefectDojo HTTP Status: $HTTP_STATUS"
    exit 1
fi
