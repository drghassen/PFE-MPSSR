#!/usr/bin/env bash
set -euo pipefail

python3 ci/libs/cloudsentinel_contracts.py validate-scanner-contract \
  --report .cloudsentinel/gitleaks_opa.json \
  --report .cloudsentinel/checkov_opa.json \
  --report .cloudsentinel/trivy_fs_opa.json \
  --report .cloudsentinel/trivy_config_opa.json \
  --report .cloudsentinel/trivy_image_opa.json

python3 ci/libs/cloudsentinel_contracts.py merge-trivy \
  --fs .cloudsentinel/trivy_fs_opa.json \
  --config .cloudsentinel/trivy_config_opa.json \
  --image .cloudsentinel/trivy_image_opa.json \
  --output .cloudsentinel/trivy_opa.json

export ENVIRONMENT="${CI_ENVIRONMENT_NAME:-dev}"
export CLOUDSENTINEL_EXECUTION_MODE="ci"
export CLOUDSENTINEL_SCHEMA_STRICT="true"
python3 shift-left/normalizer/normalize.py

opa test policies/opa -v
opa run --server --addr=127.0.0.1:8181 \
  --log-level=info \
  --log-format=json \
  --set=decision_logs.console=true \
  policies/opa/pipeline_decision.rego \
  .cloudsentinel/exceptions.json \
  > .cloudsentinel/opa-server.log 2>&1 &
for i in {1..10}; do
  if curl -sf "http://127.0.0.1:8181/health" >/dev/null; then
    echo "[opa] OPA server is UP"
    break
  fi
  echo "[opa] Waiting for OPA... ($i/10)"
  sleep 2
done
OPA_SERVER_URL="http://127.0.0.1:8181" bash shift-left/opa/run-opa.sh --enforce
