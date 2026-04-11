# Checkov Policy Mapping — mapping.json

## Purpose
Maps Checkov rule IDs to CloudSentinel severity overrides used by the normalizer.

## Two categories of entries

### Custom CloudSentinel policies (CKV2_CS_AZ_*)
Have a corresponding `.yaml` or `.py` file under `azure/*/`.
These are CloudSentinel-authored rules that extend Checkov's built-in coverage.
Total: 29 policies

### Native Checkov rules (CKV_AZURE_*, CKV_K8S_*)
NO custom policy file — these are built-in Checkov rules that run automatically.
The mapping entry overrides their default severity to align with the
Azure Student security baseline used by CloudSentinel.
Do NOT create custom policy files for these entries.
Total: 29 rules

## Governance
Any modification to mapping.json requires AppSec approval (CLOUDSENTINEL_APPSEC_USERS).
The file is protected by the policies-immutability guard.
