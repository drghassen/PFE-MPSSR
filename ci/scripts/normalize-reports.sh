#!/usr/bin/env bash
set -euo pipefail

python3 ci/libs/cloudsentinel_contracts.py merge-trivy \
  --fs .cloudsentinel/trivy_fs_opa.json \
  --config .cloudsentinel/trivy_config_opa.json \
  --image .cloudsentinel/trivy_image_opa.json \
  --output .cloudsentinel/trivy_opa.json
chmod +x shift-left/normalizer/normalize.py
export ENVIRONMENT="${CI_ENVIRONMENT_NAME:-dev}"
export CLOUDSENTINEL_EXECUTION_MODE="ci"
export CLOUDSENTINEL_SCHEMA_STRICT="true"
export DOJO_URL="${DOJO_URL:-${DEFECTDOJO_URL:-}}"
export DOJO_API_KEY="${DOJO_API_KEY:-${DEFECTDOJO_API_KEY:-${DEFECTDOJO_API_TOKEN:-}}}"
python3 shift-left/normalizer/normalize.py
jq '.summary' .cloudsentinel/golden_report.json
jq '.quality_gate' .cloudsentinel/golden_report.json
timeout 30 python3 shift-left/opa/fetch-exceptions.py
