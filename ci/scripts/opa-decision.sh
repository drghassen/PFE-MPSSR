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
  policies/opa/pipeline_decision.rego \
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
