# CloudSentinel Azure IaC (Modular)

Enterprise-grade Terraform architecture for a secure health/finance enclave aligned with CloudSentinel shift-left and shift-right governance.

## Structure

```text
infra/azure/
├── modules/
│   ├── resource_group/
│   ├── network/
│   ├── monitoring/
│   ├── compute/
│   ├── key_vault/
│   ├── postgresql/
│   └── bastion/
└── envs/
    └── dev/
```

## Design choices

- Strong separation of concerns: each module owns one responsibility.
- Private-first architecture: no public IP on app VM, private access for Key Vault and PostgreSQL.
- Zero Trust posture: subnet segmentation + strict NSG controls + managed identity.
- Auditability: diagnostic settings wired to Log Analytics for governance and traceability.

## Target deployment flow

1. Shift-left scanners (Gitleaks/Checkov/Trivy) validate IaC before apply.
2. OPA gate enforces policy intent.
3. Terraform deploys Azure enclave from `envs/dev`.
4. Shift-right controls (Prowler/Drift/OPA/Custodian) operate on live state.
