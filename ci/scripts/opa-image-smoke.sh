#!/usr/bin/env bash
mkdir -p .cloudsentinel
opa version
bash --version | head -n1
curl --version | head -n1
jq --version
git --version
opa run --server --addr=127.0.0.1:8181 \
  --log-level=error \
  --set=decision_logs.console=true \
  policies/opa/pipeline_decision.rego \
  .cloudsentinel/exceptions.json \
  > .cloudsentinel/opa-image-smoke.log 2>&1 &
for i in {1..10}; do
  if curl -sf "http://127.0.0.1:8181/health"; then
    echo "[smoke] OPA server is UP"
    break
  fi
  echo "[smoke] Waiting for OPA... ($i/10)"
  sleep 2
done
curl -sf "http://127.0.0.1:8181/v1/policies" >/dev/null
