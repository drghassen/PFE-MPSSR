#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# CloudSentinel CI — OPA Decision (Zero Trust PDP)
#
# Starts an ephemeral OPA server inside the CI job, with the same Zero Trust
# hardening as the docker-compose deployment:
#   - 127.0.0.1 binding (already the case)
#   - Bearer token authentication
#   - system.authz policy (read-only API, no policy injection)
#
# The token is ephemeral — generated per CI job and discarded after.
# ==============================================================================

# --- Artifact integrity pre-gate: fail fast before starting OPA ---
artifact=".cloudsentinel/golden_report.json"

if [[ ! -s "${artifact}" ]]; then
  echo "[opa-decision][ERROR] Missing/empty golden_report: ${artifact}" >&2
  exit 1
fi

if ! jq -e '
  type == "object"
  and (.metadata | type == "object")
  and ((.metadata.scan_id // .metadata.git.commit // "") | type == "string" and length > 0)
  and (.findings | type == "array")
  and (.summary | type == "object")
  and (.summary.global | type == "object")
  and ((.summary.global.TOTAL // -1) == (.findings | length))
' "${artifact}" >/dev/null 2>&1; then
  echo "[opa-decision][ERROR] Invalid or non-correlated golden_report.json. Refusing OPA evaluation." >&2
  exit 1
fi

# Distributed integrity model: the consumer verifies before using the artifact.
bash ci/scripts/verify-hmac.sh "${artifact}"

# Generate ephemeral auth token for this CI run
OPA_AUTH_TOKEN="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
export OPA_AUTH_TOKEN

# Write token config for OPA's system.authz policy (data.opa_config.auth_token)
mkdir -p .cloudsentinel
cat > .cloudsentinel/opa_auth_config.json <<EOF
{"opa_config":{"auth_token":"${OPA_AUTH_TOKEN}","generated_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)"}}
EOF

# Start OPA server with authentication + authorization
opa run --server --addr=127.0.0.1:8181 \
  --authentication=token \
  --authorization=basic \
  --log-level=info \
  --log-format=json \
  --set=decision_logs.console=true \
  policies/opa/gate \
  policies/opa/system/authz.rego \
  .cloudsentinel/exceptions.json \
  .cloudsentinel/opa_auth_config.json \
  > /tmp/opa-server.log 2>&1 &

for i in {1..10}; do
  if curl -sf "http://127.0.0.1:8181/health" >/dev/null; then
    echo "[opa] OPA server is UP (Zero Trust: token auth + read-only API)"
    break
  fi
  echo "[opa] Waiting for OPA... ($i/10)"
  sleep 2
done
OPA_SERVER_URL="http://127.0.0.1:8181" bash shift-left/opa/run-opa.sh --enforce

# Sign OPA decision so downstream consumers (deploy/reporting) can verify integrity.
decision_artifact=".cloudsentinel/opa_decision.json"
if [[ -n "${CLOUDSENTINEL_HMAC_SECRET:-}" ]]; then
  openssl dgst -sha256 -hmac "${CLOUDSENTINEL_HMAC_SECRET}" "${decision_artifact}" | awk '{print $NF}' > "${decision_artifact}.hmac"
  echo "[artifact-hmac] Signed   ${decision_artifact} → ${decision_artifact}.hmac"
elif [[ -n "${CI:-}" ]]; then
  echo "[opa-decision][ERROR] CLOUDSENTINEL_HMAC_SECRET is not set in CI." >&2
  echo "[opa-decision][ERROR] Cannot sign decision artifact for downstream integrity checks." >&2
  exit 1
else
  echo "[opa-decision][WARN] CLOUDSENTINEL_HMAC_SECRET not set — skipping decision artifact signing (non-CI mode)."
fi

if [[ -n "${CI:-}" ]] && [[ ! -s "${decision_artifact}.hmac" ]]; then
  echo "[opa-decision][ERROR] Missing/empty HMAC sidecar after signing: ${decision_artifact}.hmac" >&2
  exit 1
fi

# Ensure downstream jobs can read decision artifacts.
chmod a+r .cloudsentinel/opa_decision.json .cloudsentinel/opa_decision.json.hmac .cloudsentinel/decision_audit_events.jsonl .cloudsentinel/audit_events.jsonl 2>/dev/null || true
