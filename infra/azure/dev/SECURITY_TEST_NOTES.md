# Enterprise Test Infrastructure Notes

This environment deploys enterprise-like Azure resources with intentional
misconfigurations so CloudSentinel scanners can detect realistic risks.

## What is deployed

- Resource group for app workloads.
- Network stack (VNet, app/data subnets, NSG).
- Storage account with data containers.
- User-assigned managed identity and role assignment.
- Linux VM with public exposure and bootstrap extension.

## Intentional risks introduced

- NSG allows SSH, RDP, and all inbound traffic from internet.
- Storage account allows HTTP, legacy TLS1.0, and public blob access.
- Contributor role assignment to workload identity at RG scope.
- VM allows password-based login and uses a hardcoded password in tfvars.
- VM extension downloads payload over plain HTTP.

## Deployment behavior

A `tofu plan/apply` from `infra/azure/dev` will create all resources above,
plus the state backend resources already modeled in `state_storage.tf`.
