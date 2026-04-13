# CloudSentinel CI Wrappers

These scripts are CI entrypoints. They stay intentionally thin and delegate reusable logic to:

- `shift-left/*` scanner/policy engines
- `ci/libs/cloudsentinel_contracts.py` for shared contract operations

## Wrapper Inventory

| Wrapper | Role | Dependencies | Shared Lib Called |
|---|---|---|---|
| `retry-guard.sh` | enforce retry governance guard | bash, `shift-left/ci/retry-guard.sh` | n/a |
| `policies-immutability.sh` | enforce policy immutability guard | bash, `shift-left/ci/enforce-policies-immutability.sh` | n/a |
| `build-scan-tools-image.sh` | build/push scan-tools image | `/kaniko/executor` | n/a |
| `build-deploy-tools-image.sh` | build/push deploy-tools image | `/kaniko/executor` | n/a |
| `gitleaks-scan.sh` | run gitleaks wrapper and emit summary | gitleaks, jq, `shift-left/gitleaks/run-gitleaks.sh` | n/a |
| `checkov-scan.sh` | run checkov wrapper and emit summary | checkov, jq, `shift-left/checkov/run-checkov.sh` | n/a |
| `trivy-fs-scan.sh` | run trivy fs wrapper and emit summary | trivy, jq, `shift-left/trivy/scripts/run-trivy.sh` | n/a |
| `trivy-config-scan.sh` | run trivy config wrapper and emit summary | trivy, jq, `shift-left/trivy/scripts/run-trivy.sh` | n/a |
| `trivy-image-scan.sh` | run trivy image wrapper and emit summary | trivy, jq, `shift-left/trivy/scripts/run-trivy.sh` | n/a |
| `normalize-reports.sh` | merge trivy sub-reports, run normalizer, fetch exceptions | python3, jq, `shift-left/normalizer/normalize.py`, `shift-left/opa/fetch-exceptions.py` | `cloudsentinel_contracts.py merge-trivy` |
| `contract-test.sh` | validate wrapper contracts, schema, and smoke tests | python3, bash | `cloudsentinel_contracts.py validate-scanner-contract`, `validate-schema` |
| `opa-image-smoke.sh` | smoke test OPA runtime image | opa, curl, jq, git | n/a |
| `opa-decision.sh` | execute OPA tests + enforce decision | opa, curl, `shift-left/opa/run-opa.sh` | n/a |
| `opa-drift-decision.sh` | evaluate shift-right drift report with OPA and export remediation gate variables | opa, curl, jq, git | n/a |
| `upload-to-defectdojo.sh` | upload scanner raw reports to DefectDojo | curl, scanner artifacts | n/a |
| `deploy-infrastructure.sh` | run fail-closed OpenTofu deploy | tofu, cosign | n/a |
