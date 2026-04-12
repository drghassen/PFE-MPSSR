# Checkov Policy Mapping — mapping.json

## Purpose
Maps Checkov rule IDs to CloudSentinel severity overrides used by the normalizer.

## Two categories of entries

### Custom CloudSentinel policies (CKV2_CS_AZ_*)
Have a corresponding `.yaml` or `.py` file under `azure/*/`.
These are CloudSentinel-authored rules that extend Checkov's built-in coverage.
Total: 32 policies

### Native Checkov rules (CKV_AZURE_*, CKV_K8S_*)
NO custom policy file — these are built-in Checkov rules that run automatically.
The mapping entry overrides their default severity to align with the
Azure Student security baseline used by CloudSentinel.
Do NOT create custom policy files for these entries.
Total: 29 rules

## Governance
Any modification to mapping.json requires AppSec approval (CLOUDSENTINEL_APPSEC_USERS).
The file is protected by the policies-immutability guard.

## MySQL Flexible Server coverage (added 2026-04-12)
CKV2_CS_AZ_032 — SSL enforcement (require_secure_transport = ON)
CKV2_CS_AZ_033 — Backup retention >= 7 days
CKV2_CS_AZ_034 — Version >= 8.0 (MySQL 5.7 EOL October 2025)
Reference: CIS Azure Foundations Benchmark 4.13 / 4.14

## Service Principal governance (added 2026-04-12)
CKV2_CS_AZ_035 — SP secret must have expiry date (end_date or end_date_relative)
Pipeline: ARM_CLIENT_SECRET age check in deploy-infrastructure.sh
          Set ARM_CLIENT_SECRET_CREATED_AT in GitLab CI variables (YYYY-MM-DD)
          ARM_MAX_SECRET_AGE_DAYS (default: 90) triggers hard FAIL when exceeded
Reference: NIST 800-53 IA-5 / CIS Azure 1.x
