#!/usr/bin/env bash
set -euo pipefail

opa test policies/opa -v
opa run --server --addr=127.0.0.1:8181 \
  --log-level=info \
  --log-format=json \
  --set=decision_logs.console=true \
  policies/opa/pipeline_decision.rego \
  .cloudsentinel/exceptions.json \
  > /tmp/opa-server.log 2>&1 &
for i in {1..10}; do
  if curl -sf "http://127.0.0.1:8181/health" >/dev/null; then
    echo "[opa] OPA server is UP"
    break
  fi
  echo "[opa] Waiting for OPA... ($i/10)"
  sleep 2
done
OPA_SERVER_URL="http://127.0.0.1:8181" bash shift-left/opa/run-opa.sh --enforce
