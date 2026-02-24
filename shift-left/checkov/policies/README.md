# CloudSentinel Custom Checkov Policies

This directory contains enterprise-specific security policies tailored for the PFE project.

## Directory Structure

- `azure/`: Security checks for Azure resources (Storage, KeyVault, SQL).
- `aks/`: Security checks for Kubernetes manifests and Helm charts.
- `terraform/`: General IaC security checks.

## How to use

Checkov automatically loads these policies because they are referenced in `.checkov.yml`:

```yaml
external-checks-dir:
  - shift-left/checkov/policies
```

## Adding a new policy

1. Create a YAML policy in the appropriate sub-directory.
2. Define a unique ID following `CKV2_CS_AZ_###`.
3. Validate severity/category in `mapping.json`.
