# CloudSentinel Custom Checkov Policies

This directory contains enterprise-specific security policies tailored for the PFE project.

## Directory Structure

- `azure/`: Security checks for Azure resources (Storage, KeyVault, SQL).
- `aks/`: Security checks for Kubernetes manifests and Helm charts.
- `terraform/`: General IaC security checks.

## How to use

Checkov automatically loads these policies because they are referenced in `.checkov.yaml`:

```yaml
external-checks-dir:
  - shift-left/checkov/policies
```

## Adding a new policy

1. Create a Python file in the appropriate sub-directory.
2. Inherit from the relevant base check class (e.g., `BaseResourceCheck`).
3. Define a unique ID starting with `CS_` (CloudSentinel).
4. Implement the `scan_` method.
