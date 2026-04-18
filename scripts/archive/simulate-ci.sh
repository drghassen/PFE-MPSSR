#!/usr/bin/env bash
# ==============================================================================
# CloudSentinel CI Simulator
# This script simulates the GitLab CI pipeline locally in WSL.
# ==============================================================================

set -euo pipefail

# Configuration
export SCAN_TARGET="."
export TRIVY_TARGET="."
export SECURITY_TOOLS_IMAGE="cloudsentinel-tools:local" # Not used in script but for context

# Simulate GitLab CI commit-range variables for Gitleaks
export CI_COMMIT_SHA="$(git rev-parse HEAD)"
export CI_COMMIT_BEFORE_SHA="$(git rev-parse HEAD~1 2>/dev/null || echo '0000000000000000000000000000000000000000')"

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
    python3 shift-left/opa/fetch-exceptions.py
}

# 1. SCAN STAGE
echo "--- [1/4] SCAN STAGE ---"
mkdir -p .cloudsentinel
bash shift-left/gitleaks/run-gitleaks.sh
bash shift-left/checkov/run-checkov.sh "${SCAN_TARGET}"
bash shift-left/trivy/scripts/run-trivy.sh "${TRIVY_TARGET}" "fs"
cp .cloudsentinel/trivy_opa.json .cloudsentinel/trivy_fs_opa.json
bash shift-left/trivy/scripts/run-trivy.sh "${TRIVY_TARGET}" "config"
cp .cloudsentinel/trivy_opa.json .cloudsentinel/trivy_config_opa.json
if [[ -n "${TRIVY_IMAGE_TARGET:-}" ]]; then
    bash shift-left/trivy/scripts/run-trivy.sh "${TRIVY_IMAGE_TARGET}" "image"
else
    bash shift-left/trivy/scripts/run-trivy.sh
fi
cp .cloudsentinel/trivy_opa.json .cloudsentinel/trivy_image_opa.json

python3 - <<'PY'
import json
from pathlib import Path

root = Path(".cloudsentinel")
reports = {
    "fs": root / "trivy_fs_opa.json",
    "config": root / "trivy_config_opa.json",
    "image": root / "trivy_image_opa.json",
}
loaded = {}
for name, path in reports.items():
    if not path.exists():
        loaded[name] = {"status": "NOT_RUN", "errors": [f"missing_report:{path}"], "findings": [], "stats": {"TOTAL": 0}}
        continue
    try:
        loaded[name] = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        loaded[name] = {"status": "NOT_RUN", "errors": [f"invalid_json:{path}"], "findings": [], "stats": {"TOTAL": 0}}

if any(str(r.get("status", "")).upper() == "NOT_RUN" for r in loaded.values()):
    errors = []
    for name, report in loaded.items():
        if str(report.get("status", "")).upper() == "NOT_RUN":
            errs = report.get("errors", [])
            if isinstance(errs, list):
                errors.extend([f"{name}:{e}" for e in errs])
            else:
                errors.append(f"{name}:not_run")
    merged = {
        "tool": "trivy",
        "version": "multi",
        "status": "NOT_RUN",
        "errors": errors or ["trivy_subscan_not_run"],
        "has_findings": False,
        "stats": {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
            "TOTAL": 0, "EXEMPTED": 0, "FAILED": 0, "PASSED": 0,
            "by_type": {"vulnerability": 0, "secret": 0, "misconfig": 0},
            "by_category": {"INFRASTRUCTURE": 0, "APPLICATION": 0, "CONFIGURATION": 0, "SECRET": 0}
        },
        "findings": []
    }
else:
    findings = []
    sev_keys = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "TOTAL", "EXEMPTED", "FAILED", "PASSED"]
    by_type_keys = ["vulnerability", "secret", "misconfig"]
    by_cat_keys = ["INFRASTRUCTURE", "APPLICATION", "CONFIGURATION", "SECRET"]
    stats = {k: 0 for k in sev_keys}
    by_type = {k: 0 for k in by_type_keys}
    by_cat = {k: 0 for k in by_cat_keys}
    for report in loaded.values():
        findings.extend(report.get("findings", []))
        rstats = report.get("stats", {})
        for key in sev_keys:
            stats[key] += int(rstats.get(key, 0) or 0)
        for key in by_type_keys:
            by_type[key] += int((rstats.get("by_type", {}) or {}).get(key, 0) or 0)
        for key in by_cat_keys:
            by_cat[key] += int((rstats.get("by_category", {}) or {}).get(key, 0) or 0)
    stats["by_type"] = by_type
    stats["by_category"] = by_cat
    merged = {
        "tool": "trivy",
        "version": "multi",
        "status": "OK",
        "errors": [],
        "has_findings": len(findings) > 0,
        "stats": stats,
        "findings": findings
    }

(root / "trivy_opa.json").write_text(json.dumps(merged, indent=2), encoding="utf-8")
print("[simulate] merged trivy subscans")
PY

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
    cat > .cloudsentinel/exceptions.json <<'JSON'
{"cloudsentinel":{"exceptions":{"schema_version":"2.0.0","generated_at":"2026-01-01T00:00:00Z","metadata":{},"exceptions":[]}}}
JSON
fi

# 3. OPA STAGE (The Fix Test)
echo "--- [3/4] OPA STAGE (Smoke Test) ---"
opa run --server --addr=127.0.0.1:8181 \
    --log-level=error \
    policies/opa/gate \
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
bash shift-left/opa/run-opa.sh --enforce
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
