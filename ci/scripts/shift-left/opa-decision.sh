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

source ci/scripts/shift-left/audit-utils.sh
cleanup() { :; }
on_exit() {
  local rc="$?"
  cleanup
  cloudsentinel_finalize_audit "$rc" "opa-decision" "decide" "opa" ".cloudsentinel/golden_report.json" ".cloudsentinel/exceptions.json" ".cloudsentinel/opa_decision.json" ".cloudsentinel/decision_audit_events.jsonl" ".cloudsentinel/audit_events.jsonl"
}
trap on_exit EXIT

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
  and ((.summary.global.TOTAL // -1) == ([.findings[] | select(((.context.deduplication.is_duplicate // false) | not))] | length))
  and ((.summary.global.EXEMPTED // 0) == ([.findings[] | select((.context.deduplication.is_duplicate // false) == true)] | length))
' "${artifact}" >/dev/null 2>&1; then
  echo "[opa-decision][ERROR] Invalid or non-correlated golden_report.json. Refusing OPA evaluation." >&2
  exit 1
fi

# Distributed integrity model: the consumer verifies before using the artifact.
bash ci/scripts/verify-hmac.sh "${artifact}"

sign_decision_artifact() {
  local decision_artifact=".cloudsentinel/opa_decision.json"

  if [[ ! -s "${decision_artifact}" ]]; then
    echo "[opa-decision][ERROR] Missing/empty decision artifact: ${decision_artifact}" >&2
    return 1
  fi

  if [[ -n "${CLOUDSENTINEL_HMAC_SECRET:-}" ]]; then
    if command -v python3 >/dev/null 2>&1; then
      python3 ci/scripts/shift-left/artifact_hmac.py sign "${decision_artifact}"
    else
      openssl dgst -sha256 -hmac "${CLOUDSENTINEL_HMAC_SECRET}" "${decision_artifact}" | awk '{print $NF}' > "${decision_artifact}.hmac"
      echo "[artifact-hmac] Signed   ${decision_artifact} -> ${decision_artifact}.hmac"
    fi
  elif [[ -n "${CI:-}" ]]; then
    echo "[opa-decision][ERROR] CLOUDSENTINEL_HMAC_SECRET is not set in CI." >&2
    echo "[opa-decision][ERROR] Cannot sign decision artifact for downstream integrity checks." >&2
    return 1
  else
    echo "[opa-decision][WARN] CLOUDSENTINEL_HMAC_SECRET not set — skipping decision artifact signing (non-CI mode)."
  fi

  if [[ -n "${CI:-}" ]] && [[ ! -s "${decision_artifact}.hmac" ]]; then
    echo "[opa-decision][ERROR] Missing/empty HMAC sidecar after signing: ${decision_artifact}.hmac" >&2
    return 1
  fi

  # Ensure downstream jobs can read decision artifacts.
  chmod a+r .cloudsentinel/opa_decision.json .cloudsentinel/opa_decision.json.hmac .cloudsentinel/decision_audit_events.jsonl .cloudsentinel/audit_events.jsonl 2>/dev/null || true
}

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
  --set=decision_logs.console=false \
  policies/opa/gate \
  policies/opa/system/authz.rego \
  .cloudsentinel/exceptions.json \
  .cloudsentinel/opa_auth_config.json \
  > /tmp/opa-server.log 2>&1 &
OPA_PID=$!

cleanup() {
  if [[ -n "${OPA_PID:-}" ]] && kill -0 "${OPA_PID}" >/dev/null 2>&1; then
    kill "${OPA_PID}" >/dev/null 2>&1 || true
  fi
}

OPA_READY=false
for i in {1..10}; do
  if curl -sf "http://127.0.0.1:8181/health" >/dev/null; then
    echo "[opa] OPA server is UP (Zero Trust: token auth + read-only API)"
    OPA_READY=true
    break
  fi
  echo "[opa] Waiting for OPA... ($i/10)"
  sleep 2
done

if [[ "${OPA_READY}" != "true" ]]; then
  echo "[opa-decision][ERROR] OPA server failed to start after 20s." >&2
  echo "[opa-decision][ERROR] OPA log: /tmp/opa-server.log" >&2
  if [[ -s /tmp/opa-server.log ]]; then
    tail -n 80 /tmp/opa-server.log >&2 || true
  fi
  exit 1
fi

_opa_rc=0
OPA_REQUIRE_SERVER=true OPA_SERVER_URL="http://127.0.0.1:8181" bash shift-left/opa/run-opa.sh --enforce || _opa_rc=$?
if [[ "$_opa_rc" -ne 0 ]]; then
  if [[ -s ".cloudsentinel/opa_decision.json" ]]; then
    sign_decision_artifact
    exit "$_opa_rc"
  fi

  echo "[opa-decision][ERROR] run-opa.sh exited with code ${_opa_rc} before producing a decision artifact. OPA server log:" >&2
  if [[ -s /tmp/opa-server.log ]]; then
    tail -n 100 /tmp/opa-server.log >&2
  else
    echo "[opa-decision] /tmp/opa-server.log is empty or missing" >&2
  fi
  exit "$_opa_rc"
fi

# Sign OPA decision so downstream consumers (deploy/reporting) can verify integrity.
sign_decision_artifact
