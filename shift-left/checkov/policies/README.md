# CloudSentinel Custom Checkov Policies

This directory contains enterprise-specific security policies tailored for the PFE project.

## Directory Structure

- `azure/`: CloudSentinel Azure custom checks (`.yaml` + `.py`) loaded by Checkov.
- `mapping.json`: Severity/category mapping consumed by the normalizer (not a Checkov policy file).

## How to use

Checkov loads the Azure custom checks via the wrapper `run-checkov.sh`:

```yaml
external-checks-dir:
  - shift-left/checkov/policies/azure
```

## Adding a new policy

1. Create a YAML policy in the appropriate sub-directory.
2. Define a unique ID following `CKV2_CS_AZ_###`.
3. Validate severity/category in `mapping.json`.

## Governance checks

Run the catalog guard after adding or changing policies:

```bash
python3 shift-left/checkov/tests/validate-policy-catalog.py
```

The guard verifies unique policy IDs, complete `mapping.json` coverage, absence
of orphan mappings, Python syntax, and rejects weak YAML `operator: exists`
checks. Use Python policies when a control must validate non-empty values,
nested blocks, or multiple accepted secure states.
