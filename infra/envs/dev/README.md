# CloudSentinel Azure Dev Environment (OpenTofu)

This environment deploys a secure-by-default Azure baseline used to validate CloudSentinel Shift-Left controls (Gitleaks, Checkov, Trivy, OPA).

## What gets deployed

- Resource Group
- Virtual Network with one public and one private subnet
- NAT Gateway for private subnet egress (optional, enabled by default)
- Network Security Group with least-privilege inbound and outbound rules
- Log Analytics Workspace + diagnostics for NSG and VM logs/metrics
- One hardened Linux VM in private subnet
- User-assigned managed identity for VM with read-only RBAC
- Optional dedicated CI/CD managed identity with read-only RBAC

## Prerequisites

- OpenTofu `>= 1.6`
- Azure CLI authenticated (`az login`)
- Access rights to create resources in target subscription

## Init

```bash
cd infra/envs/dev
cp terraform.tfvars.example terraform.tfvars
```

Use remote backend config at init time (do not hardcode credentials):

```bash
tofu init \
  -backend-config="resource_group_name=<tfstate-rg>" \
  -backend-config="storage_account_name=<tfstateaccount>" \
  -backend-config="container_name=<tfstate-container>" \
  -backend-config="key=cloudsentinel-dev.tfstate"
```

## Plan

```bash
tofu plan -var-file="terraform.tfvars"
```

## Apply

```bash
tofu apply -var-file="terraform.tfvars"
```

## Destroy

```bash
tofu destroy -var-file="terraform.tfvars"
```

## Security notes

- `assign_public_ip = false` by default to keep the VM private.
- SSH is limited by `ssh_allowed_cidr`; do not use `0.0.0.0/0` outside temporary dev troubleshooting.
- Password auth is disabled; SSH key auth only.
- NSG egress is restricted to HTTPS and DNS, then explicit deny-all.
- IAM/RBAC uses managed identities with `Reader` role scope-limited to this resource group.
- No secrets are stored in code; all configurable values are variables.
