#!/usr/bin/env bash
set -euo pipefail

test -f .cloudsentinel/gitleaks_opa.json
test -f .cloudsentinel/checkov_opa.json
test -f .cloudsentinel/trivy_opa.json
test -f .cloudsentinel/golden_report.json
test -f .cloudsentinel/exceptions.json
python3 ci/libs/cloudsentinel_contracts.py validate-scanner-contract \
  --report .cloudsentinel/gitleaks_opa.json \
  --report .cloudsentinel/checkov_opa.json \
  --report .cloudsentinel/trivy_opa.json

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
