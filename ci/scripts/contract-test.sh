#!/usr/bin/env bash
set -euo pipefail

test -f .cloudsentinel/gitleaks_raw.json
test -f .cloudsentinel/checkov_raw.json
test -f shift-left/trivy/reports/raw/trivy-fs-raw.json
test -f shift-left/trivy/reports/raw/trivy-config-raw.json
test -f shift-left/trivy/reports/raw/image/trivy-image-scan-tools-raw.json
test -f shift-left/trivy/reports/raw/image/trivy-image-deploy-tools-raw.json
test -f shift-left/trivy/reports/raw/image/trivy-image-opa-raw.json
test -f .cloudsentinel/golden_report.json
test -f .cloudsentinel/exceptions.json

jq -e 'type=="array"' .cloudsentinel/gitleaks_raw.json >/dev/null
jq -e 'type=="object" and (.results | type=="object")' .cloudsentinel/checkov_raw.json >/dev/null
jq -e 'type=="object"' shift-left/trivy/reports/raw/trivy-fs-raw.json >/dev/null
jq -e 'type=="object"' shift-left/trivy/reports/raw/trivy-config-raw.json >/dev/null
jq -e 'type=="object"' shift-left/trivy/reports/raw/image/trivy-image-scan-tools-raw.json >/dev/null
jq -e 'type=="object"' shift-left/trivy/reports/raw/image/trivy-image-deploy-tools-raw.json >/dev/null
jq -e 'type=="object"' shift-left/trivy/reports/raw/image/trivy-image-opa-raw.json >/dev/null

python3 ci/libs/cloudsentinel_contracts.py validate-schema \
  --document .cloudsentinel/golden_report.json \
  --schema shift-left/normalizer/schema/cloudsentinel_report.schema.json \
  --success-message "[contract] schema validation passed"

python3 ci/libs/cloudsentinel_contracts.py validate-schema \
  --document .cloudsentinel/exceptions.json \
  --schema shift-left/opa/schema/exceptions_v2.schema.json \
  --success-message "[contract] exceptions schema validation passed"

python3 -m unittest discover -s shift-left/opa/tests -p "test_fetch_exceptions.py"
python3 -m unittest discover -s shift-left/normalizer/tests -p "test_normalize.py"
bash shift-left/checkov/tests/smoke.sh
bash shift-left/gitleaks/tests/smoke.sh
bash shift-left/normalizer/tests/smoke.sh
