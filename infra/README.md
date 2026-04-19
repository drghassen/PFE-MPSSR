# CloudSentinel OpenTofu Infrastructure (Azure)

Enterprise-ready, modular OpenTofu/Terraform-compatible infrastructure for CloudSentinel pipeline validation.

## Folder structure

```text
infra/
├── modules/
│   ├── vpc/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   ├── compute/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   ├── iam/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   └── security/
│       ├── main.tf
│       ├── variables.tf
│       └── outputs.tf
└── envs/
    └── dev/
        ├── backend.tf
        ├── main.tf
        ├── outputs.tf
        ├── providers.tf
        ├── terraform.tfvars.example
        ├── variables.tf
        ├── versions.tf
        └── README.md
```

## Design principles

- Least privilege by default (RBAC Reader only, scoped to RG)
- Private-by-default compute (`assign_public_ip = false`)
- Strict SSH ingress source filtering
- Baseline observability (Log Analytics + diagnostics)
- No hardcoded credentials or secrets
- Clean module boundaries for network, security, identity, and compute

## Quick start

```bash
cd infra/envs/dev
cp terraform.tfvars.example terraform.tfvars
tofu init -backend-config="resource_group_name=<rg>" -backend-config="storage_account_name=<sa>" -backend-config="container_name=<container>" -backend-config="key=cloudsentinel-dev.tfstate"
tofu plan -var-file="terraform.tfvars"
tofu apply -var-file="terraform.tfvars"
```
