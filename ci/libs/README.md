# CloudSentinel CI Shared Libraries

This directory contains shared logic used by both CI wrappers (`ci/scripts/*`) and strict local verification (`scripts/verify-student-secure.sh`).

## Library Modules

- `cloudsentinel_contracts.py`
  - `merge-trivy`: merges Trivy sub-scan OPA wrapper reports (`fs`, `config`, `image`) into a single `trivy_opa.json`.
  - `validate-schema`: validates JSON payloads against a JSON Schema using `jsonschema`.
  - `validate-scanner-contract`: validates scanner wrapper contract fields (`tool`, `version`, `status`, `findings`, `errors`).
  - `stamp-artifact-metadata`: injects `scan_id`, `scan_status`, `scan_completed`, `findings_count`, `executed_targets`.
  - `validate-artifact-contract`: validates detection/normalization/decision required artifacts and writes `artifact_contract_report.json`.

## Design Rules

- Shared decision/contract logic must live here.
- Shell wrappers should only orchestrate, not reimplement JSON rules.
- Behavior remains fail-closed: invalid/missing inputs trigger explicit failures.
