# Cloud Custodian Integration (Phase 2)

Cloud Custodian is a policy-as-code engine for cloud governance that can continuously detect and remediate misconfigurations across cloud resources. In CloudSentinel Shift-Right, Custodian is planned as the runtime remediation executor for already-deployed Azure resources, complementing Terraform drift detection and posture findings.

## OPA Integration Contract

CloudSentinel OPA drift decisions include a `custodian_policy` field per effective violation. That value is the routing key for remediation in `ci/scripts/shift-right/custodian-autofix.sh`. In Phase 1, routing and audit are implemented. In Phase 2, each routed policy name must map to a real Cloud Custodian YAML and be executed with safe controls (dry-run first, scoped targeting, full audit logs).

## Phase 2 Policies To Implement

1. `enforce-storage-tls`
2. `deny-public-storage`
3. `enforce-nsg-no-open-inbound`
4. `enforce-keyvault-access-policy`
5. `enforce-keyvault-network-acls`
6. `enforce-vm-no-password-auth`
7. `enforce-sql-password-rotation`
8. `enforce-nsg-rule-deny-all`

## Local Dry-Run Testing

Example local execution (dry-run):

```bash
export ARM_CLIENT_ID=...
export ARM_CLIENT_SECRET=...
export ARM_TENANT_ID=...
export ARM_SUBSCRIPTION_ID=...

custodian run --dryrun \
  --output-dir .cloudsentinel/custodian-output \
  --cache-period 0 \
  shift-right/custodian/policies/enforce-storage-tls.yml
```

Use targeted filters in each policy to scope remediation to the exact resource(s) identified by OPA.

Reference: https://cloudcustodian.io/docs/azure/policy/resources/storage.html
