#!/usr/bin/env bash
set -euo pipefail

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
