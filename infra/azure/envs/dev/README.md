# CloudSentinel Azure Enclave - Dev

This environment deploys a modular, private-by-default Azure enclave aligned with CloudSentinel objectives:

- Segmented VNet (`snet-app`, `snet-pe`, `snet-data`, `AzureBastionSubnet`)
- Linux application VM without public IP + system-assigned managed identity
- Key Vault with public access disabled + private endpoint
- Azure Database for PostgreSQL Flexible Server in delegated private subnet
- Azure Bastion as the only public administration entrypoint
- Log Analytics diagnostics for auditability and governance

## Prerequisites

- Terraform/OpenTofu >= 1.6
- Azure subscription permissions to create network, compute, DB, and RBAC resources
- Remote state storage for the `azurerm` backend

## Usage

```bash
cd infra/azure/envs/dev
cp terraform.tfvars.example terraform.tfvars

terraform init \
  -backend-config="resource_group_name=<tfstate-rg>" \
  -backend-config="storage_account_name=<tfstate-sa>" \
  -backend-config="container_name=<tfstate-container>" \
  -backend-config="key=cloudsentinel-azure-dev.tfstate"

terraform plan -var-file=terraform.tfvars
terraform apply -var-file=terraform.tfvars
```

## Security notes

- Keep `terraform.tfvars` out of Git.
- Prefer injecting `postgres_admin_password` from CI secret store.
- Bastion public IP is expected; application/data plane resources remain private.
