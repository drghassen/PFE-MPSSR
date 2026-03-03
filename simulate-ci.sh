#!/bin/bash
# ==============================================================================
# CloudSentinel CI Simulator
# This script simulates the GitLab CI pipeline locally in WSL.
# ==============================================================================

set -eo pipefail

# Configuration
export SCAN_TARGET="."
export TRIVY_TARGET="."
export TRIVY_SCAN_TYPE="fs"
export SECURITY_TOOLS_IMAGE="cloudsentinel-tools:local" # Not used in script but for context

safe_kill() {
    local pid="${1:-}"
    if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
        kill "${pid}" 2>/dev/null || true
        wait "${pid}" 2>/dev/null || true
    fi
}

handle_expired_exceptions() {
    local dropped_file=".cloudsentinel/dropped_exceptions.json"
    local auto_renew="${AUTO_RENEW_EXPIRED_RA:-false}"

    [[ -f "${dropped_file}" ]] || return 0

    mapfile -t expired_ids < <(
        jq -r '.dropped_exceptions[]? | select(.reason=="exception already expired") | .id' "${dropped_file}" 2>/dev/null || true
    )
    [[ ${#expired_ids[@]} -gt 0 ]] || return 0

    echo "[WARN] Expired risk acceptances detected: ${expired_ids[*]}"

    if [[ "${auto_renew}" != "true" ]]; then
        echo "[INFO] Set AUTO_RENEW_EXPIRED_RA=true to auto-renew expired RA in DefectDojo."
        return 0
    fi

    if [[ -z "${DOJO_URL:-}" || -z "${DOJO_API_KEY:-}" ]]; then
        echo "[WARN] AUTO_RENEW_EXPIRED_RA=true but DOJO_URL/DOJO_API_KEY are missing."
        return 0
    fi

    local new_exp
    new_exp="$(date -u -d '+30 days' +%Y-%m-%dT00:00:00Z)"
    for ra_id in "${expired_ids[@]}"; do
        local numeric_id="${ra_id#RA-}"
        if [[ ! "${numeric_id}" =~ ^[0-9]+$ ]]; then
            echo "[WARN] Invalid RA id format: ${ra_id}"
            continue
        fi
        echo "[INFO] Auto-renewing ${ra_id} until ${new_exp}"
        curl -sS -X PATCH \
            -H "Authorization: Token ${DOJO_API_KEY}" \
            -H "Content-Type: application/json" \
            "${DOJO_URL}/api/v2/risk_acceptance/${numeric_id}/" \
            -d "{\"expiration_date\":\"${new_exp}\"}" >/dev/null || {
            echo "[WARN] Failed to renew ${ra_id}"
            continue
        }
    done

    echo "[INFO] Re-fetching exceptions after auto-renew..."
    python3 shift-left/opa/fetch-exceptions.py || true
}

# 1. SCAN STAGE
echo "--- [1/4] SCAN STAGE ---"
mkdir -p .cloudsentinel
bash shift-left/gitleaks/run-gitleaks.sh || true
bash shift-left/checkov/run-checkov.sh "${SCAN_TARGET}" || true
bash shift-left/trivy/scripts/run-trivy.sh "${TRIVY_TARGET}" "${TRIVY_SCAN_TYPE}" || true

# 2. NORMALIZE STAGE
echo "--- [2/4] NORMALIZE STAGE ---"
export ENVIRONMENT="dev"
export CLOUDSENTINEL_EXECUTION_MODE="ci"
export CLOUDSENTINEL_SCHEMA_STRICT="true"
python3 shift-left/normalizer/normalize.py

# Fetch exceptions (Requires DOJO_URL and DOJO_API_KEY)
if [ -n "${DOJO_URL:-}" ] && [ -n "${DOJO_API_KEY:-}" ]; then
    python3 shift-left/opa/fetch-exceptions.py
    handle_expired_exceptions
else
    echo "[WARN] DOJO_URL or DOJO_API_KEY missing. Creating empty exceptions.json"
    echo '{"cloudsentinel":{"exceptions":{"exceptions":[]}}}' > .cloudsentinel/exceptions.json
fi

# 3. OPA STAGE (The Fix Test)
echo "--- [3/4] OPA STAGE (Smoke Test) ---"
opa run --server --addr=127.0.0.1:8181 \
    --log-level=error \
    policies/opa/pipeline_decision.rego \
    .cloudsentinel/exceptions.json \
    > .cloudsentinel/opa-smoke.log 2>&1 &
SERVER_PID=$!

echo "Waiting for OPA (Enterprise retry loop)..."
OPA_READY=false
for i in {1..10}; do
    if curl -sf "http://127.0.0.1:8181/health" > /dev/null; then
        echo "[smoke] OPA server is UP"
        OPA_READY=true
        break
    fi
    echo "[smoke] Waiting for OPA... ($i/10)"
    sleep 2
done

if [ "$OPA_READY" = false ]; then
    echo "[ERROR] OPA smoke test failed!"
    safe_kill "$SERVER_PID"
    exit 1
fi

echo "--- [3.1/4] OPA DECISION ---"
export OPA_SERVER_URL="http://127.0.0.1:8181"
bash shift-left/opa/run-opa.sh --enforce || true
safe_kill "$SERVER_PID"

# 4. REPORT STAGE
echo "--- [4/4] REPORT STAGE (Dojo Simulation) ---"
if [ -n "${DOJO_URL:-}" ] && [ -n "${DOJO_API_KEY:-}" ] && [ -n "${DOJO_ENGAGEMENT_ID:-}" ]; then
    echo "Simulating upload..."
    # Test Trivy FS Path
    if [ -f "shift-left/trivy/reports/raw/trivy-fs-raw.json" ]; then
        echo "[dojo] Trivy (FS/SCA) path found: shift-left/trivy/reports/raw/trivy-fs-raw.json"
        # We don't actually upload in simulation unless explicitly asked, 
        # but the path check confirms the fix.
    else
        echo "[ERROR] Trivy FS report not found! Fix failed."
        exit 1
    fi
else
    echo "[INFO] Dojo credentials missing. Report stage skipped (Simulation only)."
fi

echo "--- SIMULATION COMPLETE ---"
