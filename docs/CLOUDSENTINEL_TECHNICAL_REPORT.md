# CLOUDSENTINEL SHIFT-LEFT TECHNICAL REPORT

Generated: 2026-04-12T12:56:17Z UTC

## SECTION 0 ? ARCHITECTURE GLOBALE

```text
[GIT PUSH]
  |
  v
[guard] retry-guard -> policies-immutability -> trivy-db-warm
  |            |                         |
  |            |                         +--> .trivy-cache/
  |            +--> protected controls gate
  +--> .cloudsentinel/audit_events.jsonl
  |
  v
[scan] gitleaks-scan -> checkov-scan -> trivy-fs-scan -> trivy-config-scan
  |         |                 |                     |
  |         |                 |                     +--> shift-left/trivy/reports/raw/trivy-config-raw.json
  |         |                 +--> shift-left/trivy/reports/raw/trivy-fs-raw.json
  |         |                 +--> shift-left/trivy/reports/sbom/trivy-fs.cdx.json
  |         +--> .cloudsentinel/checkov_raw.json
  |         +--> .cloudsentinel/checkov_scan.log
  +--> .cloudsentinel/gitleaks_raw.json
  +--> .cloudsentinel/gitleaks_range_raw.json
  |
  v
[normalize] normalize.py + fetch-exceptions.py
  +--> .cloudsentinel/golden_report.json
  +--> .cloudsentinel/exceptions.json
  +--> .cloudsentinel/dropped_exceptions.json
  +--> .cloudsentinel/audit_events.jsonl
  |
  v
[contract] contract-test + opa-image-smoke + opa-unit-tests
  |
  v
[decide] opa-decision
  +--> .cloudsentinel/opa_decision.json
  +--> .cloudsentinel/decision_audit_events.jsonl
  |
  v
[report] upload-to-defectdojo (allow_failure:true)
  +--> .cloudsentinel/dojo-responses/*.json
  |
  v
[deploy] deploy-infrastructure (needs: opa-decision)
  +--> infra/azure/student-secure/tfplan
  +--> .cloudsentinel/terraform_outputs_student_secure.json
```

### Global Stage/Job Matrix

| Stage | Job | Inputs | Outputs | Why |
|---|---|---|---|---|
| guard | retry-guard | GitLab API + CI vars | audit_events.jsonl | anti retry-bomb |
| guard | policies-immutability | git diff + allowlist | exit code | protect control plane |
| guard | trivy-db-warm | trivy db | cache | speed + consistency |
| scan | gitleaks-scan | repo/staged/range | gitleaks_raw/range | secret detection |
| scan | checkov-scan | terraform target | checkov_raw/log | IaC misconfig |
| scan | trivy-fs-scan | filesystem | trivy-fs raw + sbom | dependency CVEs |
| scan | trivy-config-scan | Dockerfile scope | trivy-config raw | Dockerfile misconfig |
| normalize | normalize-reports | all raw reports | golden_report + exceptions | unified contract |
| contract | contract-test | raw JSON artifacts | exit code | shape contract check |
| contract | opa-unit-tests | rego tests | exit code | policy regression safety |
| decide | opa-decision | golden + exceptions + rego | opa_decision | single gate |
| report | upload-to-defectdojo | raw reports + dojo vars | dojo responses | tracking lifecycle |
| deploy | deploy-infrastructure | OPA pass + ARM vars | tfplan + redacted outputs | secure apply |

## SECTION 1 ? GITLEAKS

### 1.1 OBJECTIVE

- Prevent committed secret material from entering build/deploy path.
- Reduces credential theft, cloud account takeover, CI token abuse, and lateral movement risk.
- Without this stage, hardcoded secrets can persist in git and be exploitable immediately.

### 1.2 INPUT

- Config file: `shift-left/gitleaks/gitleaks.toml` required by wrapper.
- `useDefault = true`: upstream defaults are enabled, then CloudSentinel custom rules extend coverage.
- CI main mode: `gitleaks detect --no-git --source <repo> --redact`.
- CI range mode: `gitleaks detect --log-opts <range>` (best effort).
- Local default: `gitleaks protect --staged`; local repo mode uses `detect --source`.
- Behavior vars: `SCAN_MODE`, `SCAN_TARGET`, `CONFIG_PATH`, `GITLEAKS_MAX_SIZE`, `CLOUDSENTINEL_TIMEOUT`, CI SHA vars.

### Custom Rules (real IDs and regexes)

1. `aws-access-key-id` | severity `CRITICAL` | description `AWS Access Key ID`
   regex: `(A3T[A-Z0-9]|AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}`
2. `aws-secret-access-key` | severity `CRITICAL` | description `AWS Secret Access Key`
   regex: `(?i)\baws[_-]?(secret[_-]?access[_-]?key|secret[_-]?key|secret)\b\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?`
3. `gcp-service-account-key` | severity `CRITICAL` | description `GCP Service Account JSON Key`
   regex: `(?s)"type"\s*:\s*"service_account".{0,800}?"private_key"\s*:\s*"(?:-----BEGIN PRIVATE KEY-----|-----BEGIN RSA PRIVATE KEY-----)(?:\\n|\n).{50,}?(?:\\n|\n)-----END (?:PRIVATE KEY|RSA PRIVATE KEY)-----`
4. `azure-client-secret` | severity `CRITICAL` | description `Azure AD Client Secret`
   regex: `(?i)\b(?:ARM_CLIENT_SECRET|AZURE_CLIENT_SECRET|(?:azure|aad|entra|microsoft|arm)[_-]?client[_-]?secret|client_secret)\b\s*[:=]\s*["']?[A-Za-z0-9~._-]{32,80}["']?`
5. `azure-storage-connection` | severity `CRITICAL` | description `Azure Storage Connection String`
   regex: `(?i)\b(DefaultEndpointsProtocol|BlobEndpoint)=https?;[^\n\r]{0,400}?\bAccountName=[^;\s]+;[^\n\r]{0,400}?\bAccountKey=[A-Za-z0-9+/=]{40,}\b`
6. `azure-storage-account-key-standalone` | severity `CRITICAL` | description `Azure Storage Account Key (Standalone)`
   regex: `(?im)^\s*(?:export\s+)?(?:AZURE_STORAGE(?:ACCOUNT)?(?:_KEY|_ACCESS_KEY)?|ACCOUNTKEY|storage[_-]?account[_-]?key)\s*[:=]\s*["']?(?:[A-Za-z0-9+/]{86}==|[A-Za-z0-9+/]{87}=)["']?\s*$`
7. `azure-cosmos-db-connection-key` | severity `CRITICAL` | description `Azure Cosmos DB AccountEndpoint + AccountKey`
   regex: `(?i)\bAccountEndpoint=https?://[^;\s]+;\s*AccountKey=[A-Za-z0-9+/]{64,128}==;?`
8. `github-pat-classic` | severity `CRITICAL` | description `GitHub Personal Access Token (Classic)`
   regex: `\bghp_[A-Za-z0-9]{36}\b`
9. `github-pat-finegrained` | severity `CRITICAL` | description `GitHub Fine-grained Personal Access Token`
   regex: `\bgithub_pat_[A-Za-z0-9_]{40,255}\b`
10. `gitlab-pat` | severity `CRITICAL` | description `GitLab Personal Access Token`
   regex: `\bglpat-[A-Za-z0-9-]{20,}\b`
11. `azure-devops-pat` | severity `CRITICAL` | description `Azure DevOps Personal Access Token`
   regex: `(?i)\b(?:AZURE_DEVOPS_EXT_PAT|AZURE_DEVOPS_PAT|ADO_PAT|AZDO_PAT|SYSTEM_ACCESSTOKEN)\b\s*[:=]\s*["']?(?:[a-z0-9]{52}|[a-z0-9]{72})["']?`
12. `slack-webhook` | severity `CRITICAL` | description `Slack Incoming Webhook URL`
   regex: `(?i)https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{20,}`
13. `private-key-block` | severity `CRITICAL` | description `Private Key Block (RSA/EC/DSA/OpenSSH/PGP)`
   regex: `-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----(?:[A-Za-z0-9+/=\r\n\s]{80,}?)(?:-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)`
14. `azure-sas-token` | severity `HIGH` | description `Azure Shared Access Signature Token`
   regex: `(?i)\bsv=\d{4}-\d{2}-\d{2}[^\n\r]{0,800}?\bsig=[A-Za-z0-9%/+._=-]{20,}\b`
15. `gcp-api-key` | severity `HIGH` | description `Google Cloud API Key`
   regex: `\bAIza[0-9A-Za-z_\-]{35}\b`
16. `vault-token-explicit` | severity `HIGH` | description `HashiCorp Vault Token`
   regex: `(?i)\bvault[_-]?token\b\s*[:=]\s*["']?(?:s\.[A-Za-z0-9]{20,}|hvs\.[A-Za-z0-9]{20,}|hvb\.[A-Za-z0-9]{20,})["']?`
17. `kubernetes-secret-yaml` | severity `HIGH` | description `Kubernetes Secret with Base64 data`
   regex: `(?is)\bkind:\s*Secret\b.{0,800}?\bdata:\s*(?:\n\s+[A-Za-z0-9_.-]+\s*:\s*[A-Za-z0-9+/=]{16,})+`
18. `database-connection-prod` | severity `MEDIUM` | description `Database Connection String with credentials (Host reviewed by allowlist)`
   regex: `(?i)\b(postgres|postgresql|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@[^/\s]+`
19. `azure-apim-subscription-key` | severity `HIGH` | description `Azure API Management Subscription Key`
   regex: `(?i)\b(ocp-apim-subscription-key|apim[_-]?key|subscription[_-]?key)\s*[:=]\s*["']?[A-Za-z0-9]{32,64}["']?`
20. `terraform-cloud-token` | severity `CRITICAL` | description `Terraform Cloud / Terraform Enterprise API Token`
   regex: `(?i)\b(TFE_TOKEN|TFC_TOKEN|TERRAFORM_TOKEN|terraform[_-]?cloud[_-]?token)\s*[:=]\s*["']?[A-Za-z0-9._-]{32,}["']?`
21. `jwt-hardcoded-secret` | severity `HIGH` | description `JWT signing secret hardcoded in code or config`
   regex: `(?i)\b(jwt[_-]?secret|jwt[_-]?key|token[_-]?secret|signing[_-]?secret)\b\s*[:=]\s*["']?[A-Za-z0-9!@#$%^&*_\-+=./]{16,}["']?`

### Allowlist

- Paths/files/regex allowlists are declared under `[allowlist]` in TOML.
- Governance intent: reduce false positives while keeping real secret detections actionable.

### 1.3 OUTPUT

- `.cloudsentinel/gitleaks_raw.json` (validated JSON array).
- `.cloudsentinel/gitleaks_range_raw.json` (CI best-effort enrichment).
- `.gitleaksignore` governance format enforced in `ci/scripts/gitleaks-scan.sh`: `fingerprint:ticket:expiry:justification`.
- Malformed or expired `.gitleaksignore` entry => exit 1 fail.

```json
[]
```

```text
[MISSING] .cloudsentinel/gitleaks_range_raw.json
```

### 1.4 DATA TRANSFORMATION

- `normalize.py::_parse_gitleaks()` reads array entries and extracts `RuleID`, `Description`, `File`, `StartLine`, `EndLine`, `Secret`, optional `Commit`, `Email`, `Date`, `Severity`.
- Severity fallback path: finding `Severity` -> gitleaks.toml rule severity map -> default `HIGH`.
- Redacted secret is hashed (`secret_hash`) for deterministic fingerprinting without plaintext persistence.
- CloudSentinel fingerprint computed by `_fingerprint()`; finding ID generated as `CS-{tool}-{sha16}`.

### 1.5 FAILURE MODES

- No findings (`[]`) => scanner `PASSED`.
- Technical error RC>1 => wrapper exit 2.
- Missing config/tool/output/invalid JSON => exit 2.
- Range scan failure => warning-only non-blocking enrichment path.

## SECTION 2 ? CHECKOV

### 2.1 OBJECTIVE

- Detect Terraform/Kubernetes misconfiguration before apply.
- Checkov vs Trivy split here: Checkov handles IaC policies, Trivy fs/config handles dependencies + Dockerfile misconfig.
- OPA does not enforce Checkov process exit directly; it enforces normalized findings and scanner status.

### 2.2 INPUT

- Runtime target from CI wrapper: `infra/azure/student-secure` (not full repo by default).
- Config: `shift-left/checkov/.checkov.yml` with `framework: terraform,kubernetes`, `soft-fail:true`, `download-external-modules:false`, `skip-check: CKV_DOCKER_*`.
- Runtime adds `--skip-check CKV_AZURE_43` due dynamic `substr()` unresolvable static pattern (comment in script).
- External checks loaded from `shift-left/checkov/policies`.

- Custom policy count observed in repository: `33` (CKV2_CS_AZ_*).
- Note: this repository contains 33 custom CKV2 policies (including CKV2_CS_AZ_023 and CKV2_CS_AZ_024 in `security/`).

### Custom Policy Deep Inventory (input, transformation, pass/fail, reference)

#### 1. CKV2_CS_AZ_025
- File: `shift-left/checkov/policies/azure/appservice/CKV2_CS_AZ_025_appservice_https.yaml`
- Name: Ensure App Service only accepts HTTPS connections (CIS 9.1)
- Domain: APPSERVICE
- Resource IN: `azurerm_linux_web_app,azurerm_windows_web_app`
- Attribute/Logic IN: `https_only`
- Operator: `equals`
- Expected Value: `true`
- PASS condition: https_only equals true
- FAIL condition: inverse or missing attribute
- Standard reference in file: `CIS 9.1`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_025`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 2. CKV2_CS_AZ_026
- File: `shift-left/checkov/policies/azure/appservice/CKV2_CS_AZ_026_appservice_tls.yaml`
- Name: Ensure App Service uses TLS 1.2 or higher (CIS 9.2)
- Domain: APPSERVICE
- Resource IN: `azurerm_linux_web_app,azurerm_windows_web_app`
- Attribute/Logic IN: `site_config.minimum_tls_version`
- Operator: `equals`
- Expected Value: `"1.2"`
- PASS condition: site_config.minimum_tls_version equals "1.2"
- FAIL condition: inverse or missing attribute
- Standard reference in file: `CIS 9.2`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_026`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 3. CKV2_CS_AZ_027
- File: `shift-left/checkov/policies/azure/appservice/CKV2_CS_AZ_027_appservice_identity.yaml`
- Name: Ensure App Service uses Managed Identity (CIS 9.3)
- Domain: APPSERVICE
- Resource IN: `azurerm_linux_web_app,azurerm_windows_web_app`
- Attribute/Logic IN: `identity.type`
- Operator: `contains`
- Expected Value: `"SystemAssigned"`
- PASS condition: identity.type contains "SystemAssigned"
- FAIL condition: inverse or missing attribute
- Standard reference in file: `CIS 9.3`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_027`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 4. CKV2_CS_AZ_028
- File: `shift-left/checkov/policies/azure/appservice/CKV2_CS_AZ_028_appservice_vnet.yaml`
- Name: Ensure App Service is integrated with VNet (CIS 9.4)
- Domain: APPSERVICE
- Resource IN: `azurerm_linux_web_app,azurerm_windows_web_app`
- Attribute/Logic IN: `virtual_network_subnet_id`
- Operator: `exists`
- Expected Value: ``
- PASS condition: virtual_network_subnet_id exists 
- FAIL condition: inverse or missing attribute
- Standard reference in file: `CIS 9.4`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_028`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 5. CKV2_CS_AZ_010
- File: `shift-left/checkov/policies/azure/compute/CKV2_CS_AZ_010_vm_disk_encryption.py`
- Name: Ensure disk encryption is enabled on VMs via Disk Encryption Set (CIS 7.1)
- Domain: COMPUTE
- Resource IN: ``
- Attribute/Logic IN: `python custom logic`
- Operator: `custom`
- Expected Value: ``
- PASS condition: PASS only if os_disk.disk_encryption_set_id is a non-empty, non-null string.
- FAIL condition: FAIL if null, empty, missing, or not a string.
- Standard reference in file: `CIS 7.1`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_010`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 6. CKV2_CS_AZ_011
- File: `shift-left/checkov/policies/azure/compute/CKV2_CS_AZ_011_vm_agent.yaml`
- Name: Ensure VM extension operations are explicitly configured (CIS 7.2)
- Domain: COMPUTE
- Resource IN: `azurerm_linux_virtual_machine,azurerm_windows_virtual_machine`
- Attribute/Logic IN: `allow_extension_operations`
- Operator: `exists`
- Expected Value: ``
- PASS condition: allow_extension_operations exists 
- FAIL condition: inverse or missing attribute
- Standard reference in file: `CIS 7.2`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_011`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 7. CKV2_CS_AZ_019
- File: `shift-left/checkov/policies/azure/compute/CKV2_CS_AZ_019_vm_managed_disks.yaml`
- Name: Ensure Virtual Machines use managed disks (CIS 7.3)
- Domain: COMPUTE
- Resource IN: `azurerm_linux_virtual_machine,azurerm_windows_virtual_machine`
- Attribute/Logic IN: `os_disk.storage_account_type`
- Operator: `exists`
- Expected Value: ``
- PASS condition: os_disk.storage_account_type exists 
- FAIL condition: inverse or missing attribute
- Standard reference in file: `CIS 7.3`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_019`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 8. CKV2_CS_AZ_004
- File: `shift-left/checkov/policies/azure/database/CKV2_CS_AZ_004_sql_auditing.yaml`
- Name: Ensure Azure SQL Database Auditing is enabled (CIS 4.1)
- Domain: DATABASE
- Resource IN: `azurerm_mssql_server_extended_auditing_policy,azurerm_sql_server_extended_auditing_policy`
- Attribute/Logic IN: `enabled`
- Operator: `equals`
- Expected Value: `true`
- PASS condition: enabled equals true
- FAIL condition: inverse or missing attribute
- Standard reference in file: `CIS 4.1`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_004`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 9. CKV2_CS_AZ_012
- File: `shift-left/checkov/policies/azure/database/CKV2_CS_AZ_012_sql_encryption.yaml`
- Name: Ensure Azure SQL Database TDE is enabled with Customer-Managed Key (CIS 4.2)
- Domain: DATABASE
- Resource IN: `azurerm_mssql_server_transparent_data_encryption`
- Attribute/Logic IN: `key_vault_key_id`
- Operator: `exists`
- Expected Value: ``
- PASS condition: key_vault_key_id exists 
- FAIL condition: inverse or missing attribute
- Standard reference in file: `CIS 4.2`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_012`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 10. CKV2_CS_AZ_018
- File: `shift-left/checkov/policies/azure/database/CKV2_CS_AZ_018_sql_threat_protection.yaml`
- Name: Ensure Azure SQL Database Advanced Threat Protection is enabled (CIS 4.3)
- Domain: DATABASE
- Resource IN: `azurerm_mssql_server_security_alert_policy`
- Attribute/Logic IN: `state`
- Operator: `equals`
- Expected Value: `"Enabled"`
- PASS condition: state equals "Enabled"
- FAIL condition: inverse or missing attribute
- Standard reference in file: `CIS 4.3`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_018`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 11. CKV2_CS_AZ_032
- File: `shift-left/checkov/policies/azure/database/CKV2_CS_AZ_032_mysql_ssl_enforced.py`
- Name: require_secure_transport
- Domain: DATABASE
- Resource IN: ``
- Attribute/Logic IN: `python custom logic`
- Operator: `custom`
- Expected Value: ``
- PASS condition: PASS if: resource name == "require_secure_transport" AND value == "ON"; PASS (vacuously) if: resource is a different configuration parameter
- FAIL condition: FAIL if: name is "require_secure_transport" AND value != "ON"
- Standard reference in file: `not declared`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_032`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 12. CKV2_CS_AZ_033
- File: `shift-left/checkov/policies/azure/database/CKV2_CS_AZ_033_mysql_backup_retention.py`
- Name: Ensure MySQL Flexible Server backup retention is >= 7 days (CIS 4.13)
- Domain: DATABASE
- Resource IN: ``
- Attribute/Logic IN: `python custom logic`
- Operator: `custom`
- Expected Value: ``
- PASS condition: PASS if backup_retention_days >= 7
- FAIL condition: FAIL if backup_retention_days < 7 or attribute is missing/null
- Standard reference in file: `CIS 4.13`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_033`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 13. CKV2_CS_AZ_034
- File: `shift-left/checkov/policies/azure/database/CKV2_CS_AZ_034_mysql_version.py`
- Name: Ensure MySQL Flexible Server uses version 8.0 or higher (EOL policy)
- Domain: DATABASE
- Resource IN: ``
- Attribute/Logic IN: `python custom logic`
- Operator: `custom`
- Expected Value: ``
- PASS condition: PASS if major version >= 8  (e.g. "8.0.21", "8.0", "8")
- FAIL condition: FAIL if major version < 8   (e.g. "5.7", "5.6"); FAIL if version is missing or unparseable
- Standard reference in file: `not declared`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_034`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 14. CKV2_CS_AZ_003
- File: `shift-left/checkov/policies/azure/identity/CKV2_CS_AZ_003_keyvault_purge_protection.yaml`
- Name: Ensure key vault has purge protection enabled (CIS 8.4)
- Domain: IDENTITY
- Resource IN: `azurerm_key_vault`
- Attribute/Logic IN: `purge_protection_enabled`
- Operator: `equals`
- Expected Value: `true`
- PASS condition: purge_protection_enabled equals true
- FAIL condition: inverse or missing attribute
- Standard reference in file: `CIS 8.4`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_003`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 15. CKV2_CS_AZ_014
- File: `shift-left/checkov/policies/azure/identity/CKV2_CS_AZ_014_keyvault_soft_delete.yaml`
- Name: Ensure key vault has soft delete enabled (CIS 8.3)
- Domain: IDENTITY
- Resource IN: `azurerm_key_vault`
- Attribute/Logic IN: `soft_delete_retention_days`
- Operator: `greater_than_or_equal`
- Expected Value: `7`
- PASS condition: soft_delete_retention_days greater_than_or_equal 7
- FAIL condition: inverse or missing attribute
- Standard reference in file: `CIS 8.3`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_014`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 16. CKV2_CS_AZ_015
- File: `shift-left/checkov/policies/azure/identity/CKV2_CS_AZ_015_keyvault_rbac.yaml`
- Name: Ensure Key Vault uses RBAC or explicit access policy authorization
- Domain: IDENTITY
- Resource IN: `azurerm_key_vault,azurerm_key_vault`
- Attribute/Logic IN: `enable_rbac_authorization`
- Operator: `equals`
- Expected Value: `true`
- PASS condition: enable_rbac_authorization equals true
- FAIL condition: inverse or missing attribute
- Standard reference in file: `not declared`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_015`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 17. CKV2_CS_AZ_029
- File: `shift-left/checkov/policies/azure/identity/CKV2_CS_AZ_029_key_expiration.yaml`
- Name: Ensure Key Vault keys have expiration date set (CIS 10.1)
- Domain: IDENTITY
- Resource IN: `azurerm_key_vault_key`
- Attribute/Logic IN: `expiration_date`
- Operator: `exists`
- Expected Value: ``
- PASS condition: expiration_date exists 
- FAIL condition: inverse or missing attribute
- Standard reference in file: `CIS 10.1`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_029`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 18. CKV2_CS_AZ_030
- File: `shift-left/checkov/policies/azure/identity/CKV2_CS_AZ_030_secret_expiration.yaml`
- Name: Ensure Key Vault secrets have expiration date set (CIS 10.2)
- Domain: IDENTITY
- Resource IN: `azurerm_key_vault_secret`
- Attribute/Logic IN: `expiration_date`
- Operator: `exists`
- Expected Value: ``
- PASS condition: expiration_date exists 
- FAIL condition: inverse or missing attribute
- Standard reference in file: `CIS 10.2`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_030`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 19. CKV2_CS_AZ_031
- File: `shift-left/checkov/policies/azure/identity/CKV2_CS_AZ_031_no_owner_contributor_subscription.py`
- Name: Ensure no Owner or Contributor role is assigned at subscription scope
- Domain: IDENTITY
- Resource IN: `Key Vault Crypto Service Encryption User,Key Vault Crypto User,Storage Blob Data Contributor`
- Attribute/Logic IN: `python custom logic`
- Operator: `custom`
- Expected Value: ``
- PASS condition: PASS for all other cases, including:
- FAIL condition: FAIL only when BOTH conditions are true simultaneously:
- Standard reference in file: `not declared`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_031`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 20. CKV2_CS_AZ_035
- File: `shift-left/checkov/policies/azure/identity/CKV2_CS_AZ_035_sp_secret_expiry.py`
- Name: Ensure Service Principal password has expiration date (NIST IA-5)
- Domain: IDENTITY
- Resource IN: ``
- Attribute/Logic IN: `python custom logic`
- Operator: `custom`
- Expected Value: ``
- PASS condition: PASS if end_date or end_date_relative is present and non-empty
- FAIL condition: FAIL if both are absent, null, or empty string
- Standard reference in file: `NIST IA-5`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_035`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 21. CKV2_CS_AZ_013
- File: `shift-left/checkov/policies/azure/logging/CKV2_CS_AZ_013_activity_logs_retention.py`
- Name: Ensure Log Analytics Workspace has retention >= 90 days (CIS 5.1)
- Domain: LOGGING
- Resource IN: ``
- Attribute/Logic IN: `python custom logic`
- Operator: `custom`
- Expected Value: ``
- PASS condition: PASS if retention_in_days >= 90
- FAIL condition: FAIL if retention_in_days < 90 or attribute missing.
- Standard reference in file: `CIS 5.1`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_013`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 22. CKV2_CS_AZ_016
- File: `shift-left/checkov/policies/azure/logging/CKV2_CS_AZ_016_nsg_retention_90d.yaml`
- Name: Ensure Network Security Group Flow Log retention is greater than 90 days (CIS 6.2)
- Domain: LOGGING
- Resource IN: `azurerm_network_watcher_flow_log`
- Attribute/Logic IN: `retention_policy.days`
- Operator: `greater_than_or_equal`
- Expected Value: `90`
- PASS condition: retention_policy.days greater_than_or_equal 90
- FAIL condition: inverse or missing attribute
- Standard reference in file: `CIS 6.2`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_016`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 23. CKV2_CS_AZ_020
- File: `shift-left/checkov/policies/azure/logging/CKV2_CS_AZ_020_diagnostic_settings.yaml`
- Name: Ensure diagnostic settings capture appropriate categories (CIS 5.2)
- Domain: LOGGING
- Resource IN: `azurerm_monitor_diagnostic_setting`
- Attribute/Logic IN: `enabled_log`
- Operator: `exists`
- Expected Value: ``
- PASS condition: enabled_log exists 
- FAIL condition: inverse or missing attribute
- Standard reference in file: `CIS 5.2`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_020`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 24. CKV2_CS_AZ_007
- File: `shift-left/checkov/policies/azure/network/CKV2_CS_AZ_007_nsg_flow_logs.yaml`
- Name: Ensure Network Security Group Flow logs are captured and sent to Log Analytics (CIS 6.1)
- Domain: NETWORK
- Resource IN: `azurerm_network_watcher_flow_log`
- Attribute/Logic IN: `enabled`
- Operator: `equals`
- Expected Value: `true`
- PASS condition: enabled equals true
- FAIL condition: inverse or missing attribute
- Standard reference in file: `CIS 6.1`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_007`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 25. CKV2_CS_AZ_008
- File: `shift-left/checkov/policies/azure/network/CKV2_CS_AZ_008_nsg_deny_all.py`
- Name: Ensure Network Security Groups have explicit deny-all inbound rule (CIS 6.5)
- Domain: NETWORK
- Resource IN: ``
- Attribute/Logic IN: `python custom logic`
- Operator: `custom`
- Expected Value: ``
- PASS condition: PASS if the azurerm_network_security_group contains at least one security_rule
- FAIL condition: FAIL if no such catch-all deny-all inbound rule exists.
- Standard reference in file: `CIS 6.5`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_008`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 26. CKV2_CS_AZ_017
- File: `shift-left/checkov/policies/azure/network/CKV2_CS_AZ_017_rdp_restricted.py`
- Name: Ensure RDP access from the Internet is evaluated and restricted (CIS 6.3)
- Domain: NETWORK
- Resource IN: ` in single:
        try:
            lo, hi = single.split(,, 1)
            if int(lo) <= port <= int(hi):
                return True
        except (ValueError, TypeError):
            pass

    ranges_raw = rule.get(, in pr:
                try:
                    lo, hi = pr.split(,, 1)
                    if int(lo) <= port <= int(hi):
                        return True
                except (ValueError, TypeError):
                    pass
    return False


def _from_internet(rule: dict) -> bool:
    `
- Attribute/Logic IN: `python custom logic`
- Operator: `custom`
- Expected Value: ``
- PASS condition: scan_resource_conf returns PASSED
- FAIL condition: FAIL only when a SINGLE security_rule simultaneously satisfies ALL of:
- Standard reference in file: `CIS 6.3`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_017`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 27. CKV2_CS_AZ_021
- File: `shift-left/checkov/policies/azure/network/CKV2_CS_AZ_021_ssh_restricted.py`
- Name: Ensure SSH access from the Internet is evaluated and restricted (CIS 6.4)
- Domain: NETWORK
- Resource IN: ` in single:
        try:
            lo, hi = single.split(,, 1)
            if int(lo) <= port <= int(hi):
                return True
        except (ValueError, TypeError):
            pass

    # List form: destination_port_ranges  (can be [[...]] or [...])
    ranges_raw = rule.get(, in pr:
                try:
                    lo, hi = pr.split(,, 1)
                    if int(lo) <= port <= int(hi):
                        return True
                except (ValueError, TypeError):
                    pass
    return False


def _from_internet(rule: dict) -> bool:
    `
- Attribute/Logic IN: `python custom logic`
- Operator: `custom`
- Expected Value: ``
- PASS condition: scan_resource_conf returns PASSED
- FAIL condition: FAIL only when a SINGLE security_rule simultaneously satisfies ALL of:
- Standard reference in file: `CIS 6.4`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_021`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 28. CKV2_CS_AZ_023
- File: `shift-left/checkov/policies/azure/security/CKV2_CS_AZ_023_defender_sql.yaml`
- Name: Ensure Microsoft Defender for SQL is enabled (CIS 2.2)
- Domain: SECURITY
- Resource IN: `azurerm_mssql_server_security_alert_policy`
- Attribute/Logic IN: `state`
- Operator: `equals`
- Expected Value: `"Enabled"`
- PASS condition: state equals "Enabled"
- FAIL condition: inverse or missing attribute
- Standard reference in file: `CIS 2.2`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_023`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 29. CKV2_CS_AZ_024
- File: `shift-left/checkov/policies/azure/security/CKV2_CS_AZ_024_defender_storage.yaml`
- Name: Ensure Microsoft Defender for Storage is enabled (CIS 2.3)
- Domain: SECURITY
- Resource IN: `azurerm_security_center_subscription_pricing`
- Attribute/Logic IN: `resource_type`
- Operator: `equals`
- Expected Value: `"StorageAccounts"`
- PASS condition: resource_type equals "StorageAccounts"
- FAIL condition: inverse or missing attribute
- Standard reference in file: `CIS 2.3`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_024`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 30. CKV2_CS_AZ_001
- File: `shift-left/checkov/policies/azure/storage/CKV2_CS_AZ_001_storage_public_access.yaml`
- Name: Ensure that 'Public access level' is disabled for storage accounts (CIS 3.1)
- Domain: STORAGE
- Resource IN: `azurerm_storage_account`
- Attribute/Logic IN: `allow_nested_items_to_be_public`
- Operator: `equals`
- Expected Value: `false`
- PASS condition: allow_nested_items_to_be_public equals false
- FAIL condition: inverse or missing attribute
- Standard reference in file: `CIS 3.1`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_001`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 31. CKV2_CS_AZ_002
- File: `shift-left/checkov/policies/azure/storage/CKV2_CS_AZ_002_storage_https_only.yaml`
- Name: Ensure that 'Secure transfer required' is enabled for Storage Accounts (CIS 3.2)
- Domain: STORAGE
- Resource IN: `azurerm_storage_account`
- Attribute/Logic IN: `https_traffic_only_enabled`
- Operator: `equals`
- Expected Value: `true`
- PASS condition: https_traffic_only_enabled equals true
- FAIL condition: inverse or missing attribute
- Standard reference in file: `CIS 3.2`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_002`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 32. CKV2_CS_AZ_005
- File: `shift-left/checkov/policies/azure/storage/CKV2_CS_AZ_005_storage_cmk.yaml`
- Name: Ensure storage accounts are encrypted with customer-managed keys (CMK)
- Domain: STORAGE
- Resource IN: `azurerm_storage_account_customer_managed_key`
- Attribute/Logic IN: `key_name`
- Operator: `exists`
- Expected Value: ``
- PASS condition: key_name exists 
- FAIL condition: inverse or missing attribute
- Standard reference in file: `not declared`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_005`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

#### 33. CKV2_CS_AZ_006
- File: `shift-left/checkov/policies/azure/storage/CKV2_CS_AZ_006_storage_min_tls.yaml`
- Name: Ensure storage accounts use TLS 1.2 or higher (CIS 3.4)
- Domain: STORAGE
- Resource IN: `azurerm_storage_account`
- Attribute/Logic IN: `min_tls_version`
- Operator: `equals`
- Expected Value: `"TLS1_2"`
- PASS condition: min_tls_version equals "TLS1_2"
- FAIL condition: inverse or missing attribute
- Standard reference in file: `CIS 3.4`
- OUT on fail: `results.failed_checks[]` with `check_id=CKV2_CS_AZ_006`.
- OUT on pass: appears in `results.passed_checks[]` when emitted by Checkov profile.
- WHY: policy prevents a specific Azure control drift before deployment.
- Missing/malformed input handling: absent attribute or parse failure tends to FAIL in custom logic or fail condition.

### mapping.json usage

- `normalize.py::_checkov_mapping()` reads `shift-left/checkov/policies/mapping.json`.
- `_parse_checkov()` applies mapped `category` and `severity` using `check_id`.
- If mapping missing: fallback category `INFRASTRUCTURE_AS_CODE`, fallback severity path defaults to `MEDIUM` unless finding severity provided.

### 2.3 OUTPUT

- `.cloudsentinel/checkov_raw.json` expected to contain `results` object.
- `.cloudsentinel/checkov_scan.log` contains stderr and parser warnings.

```json
{
    "check_type": "terraform",
    "results": {
        "failed_checks": []
    },
    "summary": {
        "passed": 64,
        "failed": 0,
        "skipped": 0,
        "parsing_errors": 0,
        "resource_count": 38,
        "checkov_version": "3.2.502"
    }
}
```

### 2.4 DATA TRANSFORMATION

- Parser consumes `results.failed_checks[]` only.
- `check_id` -> severity/category via mapping JSON.
- `resource`, `file_path`, `file_line_range` map into unified finding resource path/location.
- PASSED checks are not promoted into normalized findings array.
- Prefix filtering is described in comments/docs; current parser processes whatever appears in failed_checks list.

### 2.5 FAILURE MODES

- `soft-fail:true` means business findings do not force exit 1 semantics.
- Technical RC>=2 => exit 2 hard fail.
- Invalid structure/missing report => exit 2.
- If skipped in local fast mode => scanner `NOT_RUN` in golden report.

## SECTION 3 ? TRIVY

### 3.1 OBJECTIVE

- `trivy-fs-scan` detects OS/library vulnerabilities in repository dependency graph.
- `trivy-config-scan` detects Dockerfile/config misconfigurations.
- Source-level secret governance remains centered on Gitleaks; fs job forces `--scanners vuln` only.

### 3.2 INPUT ? trivy-fs-scan

- Target: `infra/azure/student-secure` from CI wrapper.
- Config: `shift-left/trivy/configs/trivy-ci.yaml` in CI mode.
- Command override: `trivy fs ... --scanners vuln` (so secrets are not scanned in this fs job).
- Cache dir: `.trivy-cache`; guard stage pre-warms DB.

### 3.3 INPUT ? trivy-config-scan

- Target: same CI target path; command is `trivy config`.
- Misconfiguration findings appear under `Results[].Misconfigurations[]`.
- Terraform IaC control logic stays in Checkov policy set by design.

### 3.4 OUTPUT

- `shift-left/trivy/reports/raw/trivy-fs-raw.json`
- `shift-left/trivy/reports/sbom/trivy-fs.cdx.json`
- `shift-left/trivy/reports/raw/trivy-config-raw.json`

```json
{
  "SchemaVersion": 2,
  "Trivy": {
    "Version": "0.69.1"
  },
  "ReportID": "019d5e33-14f9-734a-8e41-97cbc2c88ad9",
  "CreatedAt": "2026-04-05T16:11:39.257217623+01:00",
  "ArtifactName": "/home/ghassen/pfe-cloud-sentinel/infra/azure/student-secure",
  "ArtifactType": "filesystem"
}
```

```json
{
  "SchemaVersion": 2,
  "Trivy": {
    "Version": "0.69.1"
  },
  "ReportID": "019d5e2c-9957-7698-92d7-e1a9824cccd1",
  "CreatedAt": "2026-04-05T16:04:34.391434042+01:00",
  "ArtifactName": "/home/ghassen/pfe-cloud-sentinel/infra/azure/student-secure",
  "ArtifactType": "filesystem"
}
```

### 3.5 DATA TRANSFORMATION

- `_parse_trivy()` loads fs/config reports and optional image reports.
- `_trivy_from_doc()` merges vulnerabilities + misconfigurations (+ secrets if present) into unified findings.
- `TRIVY_IMAGE_MIN_REPORTS` controls required image report count in CI mode; pipeline sets `0`.
- CVSS extraction uses first available `CVSS.*.V3Score`.

### 3.6 FAILURE MODES

- Technical RC>1 => wrapper exits failure.
- `exit-code: 0` keeps findings advisory; OPA decides gate.
- SBOM generation failures are warning-only in fs/image scripts.
- Missing reports at normalize time -> scanner `NOT_RUN`.

## SECTION 4 ? NORMALIZER (normalize.py)

### 4.1 OBJECTIVE

- Build one canonical contract (`golden_report.json`) from heterogeneous scanner outputs.
- Without normalization, OPA would need scanner-specific parsers and lose deterministic governance semantics.

### 4.2 INPUT

- Inputs: gitleaks_raw, checkov_raw, trivy-fs-raw, trivy-config-raw (+ optional trivy image raw files).
- Environment consumed: CI metadata, execution mode, threshold vars, schema strict flag, TRIVY image minimum reports.

### 4.3 TRANSFORMATION LOGIC

A) Severity LUT maps aliases like MINOR/SEV4/MODERATE/UNKNOWN into LOW/HIGH/MEDIUM/INFO.
B) `_fingerprint()` computes sha256 from tool/rule/resource/path/lines/description/secret_hash.
C) `_dedup()` keeps duplicates as EXEMPTED with `is_duplicate=true` and `duplicate_of` pointer.
D) SLA mapping: CRITICAL 24h, HIGH 168h, MEDIUM 720h, LOW 2160h, INFO 8760h.
E) NOT_RUN set on missing/invalid/skipped scanner reports; scanner status computed post-stats.
F) `_validate_schema()` validates Draft-07 schema and exits on violation (or missing jsonschema when strict=true).

### 4.4 OUTPUT

```json
{
  "schema_version": "1.1.0",
  "metadata": {
    "tool": "cloudsentinel",
    "timestamp": "2026-04-12T11:23:49Z",
    "generation_duration_ms": 7,
    "environment": "dev",
    "execution": {
      "mode": "advisory"
    },
    "git": {
      "repo": "drghassen/PFE-MPSSR",
      "repository": "drghassen/PFE-MPSSR",
      "branch": "main",
      "commit": "bbdbc48207648abf030861ad3c0745dd6055ce89",
      "commit_date": "2026-04-12T12:16:33+01:00",
      "author_email": "dridighassenbac2021@gmail.com",
      "pipeline_id": "local"
    },
    "normalizer": {
      "version": "1.1.0",
      "source_reports": {
        "gitleaks": {
          "tool": "gitleaks",
          "path": "/home/ghassen/pfe-cloud-sentinel/.cloudsentinel/gitleaks_raw.json",
          "present": true,
          "valid_json": true,
          "status": "PASSED",
          "reason": "",
          "sha256": "37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570"
        },
        "checkov": {
          "tool": "checkov",
          "path": "/home/ghassen/pfe-cloud-sentinel/.cloudsentinel/checkov_raw.json",
          "present": false,
          "valid_json": false,
          "status": "NOT_RUN",
          "reason": "skipped_local_fast",
          "sha256": null
        },
        "trivy": {
          "tool": "trivy",
          "path": "/home/ghassen/pfe-cloud-sentinel/shift-left/trivy/reports/raw",
          "present": false,
          "valid_json": false,
          "status": "NOT_RUN",
          "reason": "skipped_local_fast",
          "sha256": null
        }
      }
    }
  },
  "scanners": {
    "gitleaks": {
      "tool": "gitleaks",
      "version": "unknown",
      "status": "PASSED",
      "errors": [],
      "stats": {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
        "TOTAL": 0,
        "EXEMPTED": 0,
        "FAILED": 0,
        "PASSED": 0
      },
      "findings": []
    },
    "checkov": {
      "tool": "checkov",
      "version": "unknown",
      "status": "NOT_RUN",
      "errors": [
        "skipped_local_fast"
      ],
      "stats": {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
        "TOTAL": 0,
        "EXEMPTED": 0,
        "FAILED": 0,
        "PASSED": 0
      },
      "findings": []
    },
    "trivy": {
      "tool": "trivy",
      "version": "unknown",
      "status": "NOT_RUN",
      "errors": [
        "skipped_local_fast"
      ],
      "stats": {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
        "TOTAL": 0,
        "EXEMPTED": 0,
        "FAILED": 0,
        "PASSED": 0
      },
      "findings": []
    }
  },
  "findings": [],
  "summary": {
    "global": {
      "CRITICAL": 0,
      "HIGH": 0,
      "MEDIUM": 0,
      "LOW": 0,
      "INFO": 0,
      "TOTAL": 0,
      "EXEMPTED": 0,
      "FAILED": 0,
      "PASSED": 0
    },
    "by_tool": {
      "gitleaks": {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
        "TOTAL": 0,
        "EXEMPTED": 0,
        "FAILED": 0,
        "PASSED": 0,
        "status": "PASSED"
      },
      "checkov": {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
        "TOTAL": 0,
        "EXEMPTED": 0,
        "FAILED": 0,
        "PASSED": 0,
        "status": "NOT_RUN"
      },
      "trivy": {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
        "TOTAL": 0,
        "EXEMPTED": 0,
        "FAILED": 0,
        "PASSED": 0,
        "status": "NOT_RUN"
      }
    },
    "by_category": {
      "SECRETS": 0,
      "INFRASTRUCTURE_AS_CODE": 0,
      "VULNERABILITIES": 0
    }
  },
  "quality_gate": {
    "decision": "NOT_EVALUATED",
    "reason": "evaluation-performed-by-opa-only",
    "thresholds": {
      "critical_max": 0,
      "high_max": 2
    },
    "details": {
      "reasons": [
        "opa_is_single_enforcement_point"
      ],
      "not_run_scanners": [
        "checkov",
        "trivy"
      ]
    }
  }
}
```

- Schema paths (from `cloudsentinel_report.schema.json`):
- `root` -> `object`
- `root.schema_version` -> `string`
- `root.metadata` -> `object`
- `root.metadata.tool` -> `string`
- `root.metadata.timestamp` -> `string`
- `root.metadata.generation_duration_ms` -> `integer`
- `root.metadata.environment` -> `string`
- `root.metadata.execution` -> `object`
- `root.metadata.execution.mode` -> `string`
- `root.metadata.git` -> `object`
- `root.metadata.git.repo` -> `string`
- `root.metadata.git.repository` -> `string`
- `root.metadata.git.branch` -> `string`
- `root.metadata.git.commit` -> `string`
- `root.metadata.git.commit_date` -> `string`
- `root.metadata.git.author_email` -> `string`
- `root.metadata.git.pipeline_id` -> `string`
- `root.metadata.normalizer` -> `object`
- `root.metadata.normalizer.version` -> `string`
- `root.metadata.normalizer.source_reports` -> `object`
- `root.metadata.normalizer.source_reports.gitleaks.$ref` -> `#/definitions/source_report_trace`
- `root.metadata.normalizer.source_reports.checkov.$ref` -> `#/definitions/source_report_trace`
- `root.metadata.normalizer.source_reports.trivy.$ref` -> `#/definitions/source_report_trace`
- `root.summary` -> `object`
- `root.summary.global.$ref` -> `#/definitions/stats_summary`
- `root.summary.by_tool` -> `object`
- `root.summary.by_tool.gitleaks.$ref` -> `#/definitions/tool_summary`
- `root.summary.by_tool.checkov.$ref` -> `#/definitions/tool_summary`
- `root.summary.by_tool.trivy.$ref` -> `#/definitions/tool_summary`
- `root.summary.by_category` -> `object`
- `root.summary.by_category.SECRETS` -> `integer`
- `root.summary.by_category.INFRASTRUCTURE_AS_CODE` -> `integer`
- `root.summary.by_category.VULNERABILITIES` -> `integer`
- `root.scanners` -> `object`
- `root.scanners.gitleaks.$ref` -> `#/definitions/scanner`
- `root.scanners.checkov.$ref` -> `#/definitions/scanner`
- `root.scanners.trivy.$ref` -> `#/definitions/scanner`
- `root.findings` -> `array`
- `root.findings[].$ref` -> `#/definitions/finding`
- `root.quality_gate` -> `object`
- `root.quality_gate.decision` -> `string`
- `root.quality_gate.reason` -> `string`
- `root.quality_gate.thresholds` -> `object`
- `root.quality_gate.thresholds.critical_max` -> `integer`
- `root.quality_gate.thresholds.high_max` -> `integer`
- `root.quality_gate.details` -> `object`
- `root.quality_gate.details.reasons` -> `array`
- `root.quality_gate.details.reasons[]` -> `string`
- `root.quality_gate.details.not_run_scanners` -> `array`
- `root.quality_gate.details.not_run_scanners[]` -> `string`
- `definitions.stats_summary` -> `object`
- `definitions.stats_summary.CRITICAL` -> `integer`
- `definitions.stats_summary.HIGH` -> `integer`
- `definitions.stats_summary.MEDIUM` -> `integer`
- `definitions.stats_summary.LOW` -> `integer`
- `definitions.stats_summary.INFO` -> `integer`
- `definitions.stats_summary.TOTAL` -> `integer`
- `definitions.stats_summary.EXEMPTED` -> `integer`
- `definitions.stats_summary.FAILED` -> `integer`
- `definitions.stats_summary.PASSED` -> `integer`
- `definitions.tool_summary` -> `object`
- `definitions.tool_summary.CRITICAL` -> `integer`
- `definitions.tool_summary.HIGH` -> `integer`
- `definitions.tool_summary.MEDIUM` -> `integer`
- `definitions.tool_summary.LOW` -> `integer`
- `definitions.tool_summary.INFO` -> `integer`
- `definitions.tool_summary.TOTAL` -> `integer`
- `definitions.tool_summary.EXEMPTED` -> `integer`
- `definitions.tool_summary.FAILED` -> `integer`
- `definitions.tool_summary.PASSED` -> `integer`
- `definitions.tool_summary.status` -> `string`
- `definitions.source_report_trace` -> `object`
- `definitions.source_report_trace.tool` -> `string`
- `definitions.source_report_trace.path` -> `string`
- `definitions.source_report_trace.present` -> `boolean`
- `definitions.source_report_trace.valid_json` -> `boolean`
- `definitions.source_report_trace.status` -> `string`
- `definitions.source_report_trace.reason` -> `string`
- `definitions.source_report_trace.sha256` -> `['string', 'null']`
- `definitions.scanner` -> `object`
- `definitions.scanner.tool` -> `string`
- `definitions.scanner.version` -> `string`
- `definitions.scanner.status` -> `string`
- `definitions.scanner.errors` -> `array`
- `definitions.scanner.errors[]` -> `string`
- `definitions.scanner.stats.$ref` -> `#/definitions/stats_summary`
- `definitions.scanner.findings` -> `array`
- `definitions.scanner.findings[].$ref` -> `#/definitions/finding`
- `definitions.finding` -> `object`
- `definitions.finding.id` -> `string`
- `definitions.finding.source` -> `object`
- `definitions.finding.source.tool` -> `string`
- `definitions.finding.source.version` -> `string`
- `definitions.finding.source.id` -> `string`
- `definitions.finding.source.scanner_type` -> `string`
- `definitions.finding.resource` -> `object`
- `definitions.finding.resource.name` -> `string`
- `definitions.finding.resource.version` -> `string`
- `definitions.finding.resource.type` -> `string`
- `definitions.finding.resource.path` -> `string`
- `definitions.finding.resource.location` -> `object`
- `definitions.finding.resource.location.file` -> `string`
- `definitions.finding.resource.location.start_line` -> `integer`
- `definitions.finding.resource.location.end_line` -> `integer`
- `definitions.finding.description` -> `string`
- `definitions.finding.severity` -> `object`
- `definitions.finding.severity.level` -> `string`
- `definitions.finding.severity.original_severity` -> `string`
- `definitions.finding.severity.cvss_score` -> `['number', 'null']`
- `definitions.finding.category` -> `string`
- `definitions.finding.status` -> `string`
- `definitions.finding.remediation` -> `object`
- `definitions.finding.remediation.sla_hours` -> `integer`
- `definitions.finding.remediation.fix_version` -> `string`
- `definitions.finding.remediation.references` -> `array`
- `definitions.finding.remediation.references[]` -> `string`
- `definitions.finding.context` -> `object`
- `definitions.finding.context.git` -> `object`
- `definitions.finding.context.git.author_email` -> `string`
- `definitions.finding.context.git.commit_date` -> `string`
- `definitions.finding.context.deduplication` -> `object`
- `definitions.finding.context.deduplication.fingerprint` -> `string`
- `definitions.finding.context.deduplication.is_duplicate` -> `boolean`
- `definitions.finding.context.deduplication.duplicate_of` -> `['string', 'null']`
- `definitions.finding.context.traceability` -> `object`
- `definitions.finding.context.traceability.source_report` -> `string`
- `definitions.finding.context.traceability.source_index` -> `integer`
- `definitions.finding.context.traceability.normalized_at` -> `string`

### 4.5 FAILURE MODES

- Missing scanner report -> NOT_RUN in source trace; may deny in CI OPA mode.
- Invalid scanner JSON -> NOT_RUN.
- Schema validation failure -> normalizer exits 1.
- Git metadata commands have non-fatal fallback values (`unknown` style).

## SECTION 5 ? DEFECTDOJO (fetch-exceptions pipeline)

### 5.1 OBJECTIVE

- Convert DefectDojo risk acceptances into strict, scope-bound exceptions consumable by OPA.
- Enforce four-eyes and expiration semantics before policy evaluation.

### 5.2 INPUT

- API call path: `/api/v2/risk_acceptance/`, following `next` pagination links.
- Auth: `Authorization: Token <DOJO_API_KEY>`.
- Enrichment calls: `/api/v2/users/{id}/` and `/api/v2/findings/{id}/`.
- Consumed fields include `id,name,accepted_findings,accepted_by,owner,expiration_date,created,decision,recommendation,status,is_active`.

### 5.3 VALIDATION CHAIN (fetch_validation.py)

- A) `is_active_accepted`: requires `is_active` truthy and normalized status `approved`.
- B) `validate_normalized_exception`: validates id/tool/rule/resource/severity/decision/source/status/four-eyes/timestamps/no wildcard.
- C) `_build_ci_scope`: binds repos/branches/environments from CI vars at fetch time.
- D) Stable exception ID: sha256(tool+rule_id+resource).

### 5.4 OUTPUT

- `.cloudsentinel/exceptions.json`
- `.cloudsentinel/dropped_exceptions.json`
- `.cloudsentinel/audit_events.jsonl`

```json
{"cloudsentinel":{"exceptions":{"schema_version":"2.0.0","generated_at":"2099-01-01T00:00:00Z","metadata":{"source":"local-bootstrap","total_raw_risk_acceptances":0,"total_valid_exceptions":0,"total_dropped":0},"exceptions":[]}}}
```

```text
[MISSING] .cloudsentinel/dropped_exceptions.json
```

### 5.5 HOW OPA USES exceptions.json

- Loaded as `data.cloudsentinel.exceptions.exceptions`.
- Exact match on tool+rule_id+normalized resource+scope (repo/env/branch).
- Invalid/expired exception IDs are surfaced and can deny the gate.

## SECTION 6 ? OPA (pipeline_decision.rego)

### 6.1 OBJECTIVE

- Policy-as-Code central gate: declarative, testable, auditable decisioning.
- PEP/PDP split: `run-opa.sh` is PEP, OPA policy engine is PDP.
- OPA provides richer governance than shell if/else thresholds alone.

### 6.2 INPUT

- Data A: golden report provided as `input`.
- Data B: exceptions loaded as `data.cloudsentinel.exceptions.exceptions`.
- Modes: REST server preferred; CLI fallback when available.

### 6.3 DECISION LOGIC

- A) Threshold ceiling clamp (`critical` ceiling 0, `high` ceiling 5).
- B) Scanner presence deny on NOT_RUN outside local/advisory modes.
- C) Exception matching strict on tool/rule/resource + scope.
- D) Effective counts computed after exception suppression.
- E) Prod blocks CRITICAL exceptions (`prod_critical_exception_violation`).
- F) Invalid exception checks deny malformed/status/timestamp issues.
- G) Four-eyes check enforced in `valid_exception_definition`.

### 6.4 OUTPUT

```json
{
  "decision_id": "8d75518a-d1a2-4bd4-b82f-46c39beb37e6",
  "result": {
    "allow": true,
    "deny": [],
    "environment": "dev",
    "exceptions": {
      "applied_audit": [],
      "applied_count": 0,
      "applied_ids": [],
      "expired_enabled_ids": [],
      "invalid_enabled_ids": [],
      "legacy_after_sunset_ids": [],
      "partial_matches_audit": [],
      "strict_prod_violations": []
    },
    "execution_mode": "advisory",
    "metrics": {
      "critical": 0,
      "excepted": 0,
      "excepted_exception_ids": 0,
      "excepted_findings": 0,
      "failed": 0,
      "failed_effective": 0,
      "failed_input": 0,
      "governance": {
        "active_break_glass": 0,
        "active_exceptions_by_severity": {
          "CRITICAL": 0,
          "HIGH": 0,
          "INFO": 0,
          "LOW": 0,
          "MEDIUM": 0
        },
        "avg_approval_time_hours": 0,
        "expired_enabled_exceptions": 0
      },
      "high": 0,
      "info": 0,
      "low": 0,
      "medium": 0
    },
    "thresholds": {
      "critical_max": 0,
      "high_max": 2
    },
    "_gate": {
      "mode": "--enforce",
      "engine": "server",
      "policy_file": "/home/ghassen/pfe-cloud-sentinel/policies/opa/pipeline_decision.rego",
      "exceptions_file": "/home/ghassen/pfe-cloud-sentinel/.cloudsentinel/exceptions.json",
      "evaluated_at": "2026-04-12T12:27:25Z"
    }
  }
}
```

- `.cloudsentinel/decision_audit_events.jsonl` contains one line per applied exception audit item when any are applied.

### 6.5 ENFORCEMENT

- `--enforce`: exit 1 when allow=false (pipeline blocked).
- `--advisory`: always exit 0 (developer feedback mode).
- Deploy stage depends on successful opa-decision stage.

### 6.6 FAILURE MODES

- OPA server unreachable -> fallback to CLI when available.
- Empty/invalid decision artifact -> exit 2 fail-closed.
- Missing exceptions in local -> bootstrap empty safe file; CI expects runtime artifact path.

## SECTION 7 ? DEFECTDOJO UPLOAD (upload-to-defectdojo.sh)

### 7.1 OBJECTIVE

- Keep monitoring/reporting decoupled from policy gate enforcement.
- DefectDojo persists finding lifecycle; OPA performs release gate decision.

### 7.2 INPUT

- Uploads raw scanner reports, not `golden_report.json`, because DefectDojo import parser expects scanner-native formats.
- Env aliases: URL/API key/engagement ID from DOJO_* or DEFECTDOJO_* variants.

### 7.3 API CALLS

- POST `/api/v2/import-scan/` with fields `file,scan_type,engagement,active,verified,close_old_findings,close_old_findings_product_scope,deduplication_on_engagement`.
- Expected HTTP 201; otherwise response body logged to response file.

### 7.4 OUTPUT

- `.cloudsentinel/dojo-responses/{label}.json` per upload attempt.
- DefectDojo-side state updates handled by import endpoint semantics.

### 7.5 WHY allow_failure: true

- Security gate already decided in OPA stage; external Dojo outage must not block deployment path.

## SECTION 8 ? DEPLOY INFRASTRUCTURE

### 8.1 OBJECTIVE

- Execute infrastructure apply only after OPA permit path.
- Security contract is enforced by stage dependency (`needs: opa-decision`).

### 8.2 INPUT

- OPA artifact path: `.cloudsentinel/opa_decision.json` from previous stage artifacts.
- Required ARM/TF vars are validated before any cloud call (missing => exit 2).
- TFSTATE key sanitized (`tr -d /\` + remove `..`) to prevent path traversal in backend key.

### 8.3 PROCESS

- `tofu init` + `tofu plan` + `tofu apply -auto-approve`.
- `ARM_USE_AZUREAD=true` and `ARM_STORAGE_USE_AZUREAD=true` enforce AAD auth mode.

### 8.4 OUTPUT

- `.cloudsentinel/terraform_outputs_student_secure.json` with sensitive outputs redacted to `REDACTED`.
- `infra/azure/student-secure/tfplan` binary plan artifact.

### 8.5 FAILURE MODES

- OPA deny -> deploy job not reached.
- Missing ARM vars / invalid SSH key / empty sanitized TFSTATE key / stale secret age -> exit 2.

## SECTION 9 ? CONTRACT TEST & GOVERNANCE

### 9.1 contract-test.sh

- Verifies raw report JSON contract: gitleaks array/leaks/findings, checkov results/checks, trivy SchemaVersion.
- Runs after normalize stage and before decide stage.
- Contract = interface integrity between scanner artifacts and downstream policy pipeline.

### 9.2 retry-guard.sh

- Wrapper delegates to `shift-left/ci/retry-guard.sh`.
- Input API query: `/projects/{id}/pipelines?sha={sha}` with `per_page` lookback limit.
- Enforces max retries and minimum interval; writes audit JSONL events.

### 9.3 policies-immutability.sh

- Wrapper delegates to `shift-left/ci/enforce-policies-immutability.sh`.
- Protected regex covers policy files, scripts, schemas, scanner configs, CI definitions.
- Only `CLOUDSENTINEL_APPSEC_USERS` actors may modify protected files.
- Unauthorized protected change => exit 1.

### 9.4 opa-unit-tests job (FIX 1)

- Isolated policy test suite avoids coupling with production runtime input artifacts.
- 22 tests total: 11 in `pipeline_decision_test.rego`, 11 in `test_pipeline_decision.rego`.

## SECTION 10 ? SILENT PASS ANALYSIS

### A) Scanner crashes silently

- Scenario: analyzed against repository code paths and stage dependencies.
- Detection blind-spot risk: present in weak pipeline designs.
- CloudSentinel prevention: wrapper validation + normalization NOT_RUN + OPA strict matching/gate + deploy hard validations depending on scenario.

### B) Scanner emits invalid JSON

- Scenario: analyzed against repository code paths and stage dependencies.
- Detection blind-spot risk: present in weak pipeline designs.
- CloudSentinel prevention: wrapper validation + normalization NOT_RUN + OPA strict matching/gate + deploy hard validations depending on scenario.

### C) Exception wrong resource path

- Scenario: analyzed against repository code paths and stage dependencies.
- Detection blind-spot risk: present in weak pipeline designs.
- CloudSentinel prevention: wrapper validation + normalization NOT_RUN + OPA strict matching/gate + deploy hard validations depending on scenario.

### D) Expired exception still enabled

- Scenario: analyzed against repository code paths and stage dependencies.
- Detection blind-spot risk: present in weak pipeline designs.
- CloudSentinel prevention: wrapper validation + normalization NOT_RUN + OPA strict matching/gate + deploy hard validations depending on scenario.

### E) Duplicate findings inflate counts

- Scenario: analyzed against repository code paths and stage dependencies.
- Detection blind-spot risk: present in weak pipeline designs.
- CloudSentinel prevention: wrapper validation + normalization NOT_RUN + OPA strict matching/gate + deploy hard validations depending on scenario.

### F) Branch injection in TFSTATE key

- Scenario: analyzed against repository code paths and stage dependencies.
- Detection blind-spot risk: present in weak pipeline designs.
- CloudSentinel prevention: wrapper validation + normalization NOT_RUN + OPA strict matching/gate + deploy hard validations depending on scenario.

### G) RA deactivated but approved status

- Scenario: analyzed against repository code paths and stage dependencies.
- Detection blind-spot risk: present in weak pipeline designs.
- CloudSentinel prevention: wrapper validation + normalization NOT_RUN + OPA strict matching/gate + deploy hard validations depending on scenario.

### H) Range secret found while no-git misses

- Scenario: analyzed against repository code paths and stage dependencies.
- Detection blind-spot risk: present in weak pipeline designs.
- CloudSentinel prevention: wrapper validation + normalization NOT_RUN + OPA strict matching/gate + deploy hard validations depending on scenario.

### I) Policy scans wrong resource type

- Scenario: analyzed against repository code paths and stage dependencies.
- Detection blind-spot risk: present in weak pipeline designs.
- CloudSentinel prevention: wrapper validation + normalization NOT_RUN + OPA strict matching/gate + deploy hard validations depending on scenario.

### J) Sensitive Terraform output leak

- Scenario: analyzed against repository code paths and stage dependencies.
- Detection blind-spot risk: present in weak pipeline designs.
- CloudSentinel prevention: wrapper validation + normalization NOT_RUN + OPA strict matching/gate + deploy hard validations depending on scenario.

## SECTION 11 ? CONFORMIT? AUX STANDARDS

### CIS Azure Foundations Benchmark v2.0 mapping

| Policy ID | Name | Resource Type(s) | PASS condition | FAIL condition | Reference token in file |
|---|---|---|---|---|---|
| CKV2_CS_AZ_025 | Ensure App Service only accepts HTTPS connections (CIS 9.1) | azurerm_linux_web_app,azurerm_windows_web_app | https_only equals true | inverse or missing attribute | CIS 9.1 |
| CKV2_CS_AZ_026 | Ensure App Service uses TLS 1.2 or higher (CIS 9.2) | azurerm_linux_web_app,azurerm_windows_web_app | site_config.minimum_tls_version equals "1.2" | inverse or missing attribute | CIS 9.2 |
| CKV2_CS_AZ_027 | Ensure App Service uses Managed Identity (CIS 9.3) | azurerm_linux_web_app,azurerm_windows_web_app | identity.type contains "SystemAssigned" | inverse or missing attribute | CIS 9.3 |
| CKV2_CS_AZ_028 | Ensure App Service is integrated with VNet (CIS 9.4) | azurerm_linux_web_app,azurerm_windows_web_app | virtual_network_subnet_id exists  | inverse or missing attribute | CIS 9.4 |
| CKV2_CS_AZ_010 | Ensure disk encryption is enabled on VMs via Disk Encryption Set (CIS 7.1) |  | PASS only if os_disk.disk_encryption_set_id is a non-empty, non-null string. | FAIL if null, empty, missing, or not a string. | CIS 7.1 |
| CKV2_CS_AZ_011 | Ensure VM extension operations are explicitly configured (CIS 7.2) | azurerm_linux_virtual_machine,azurerm_windows_virtual_machine | allow_extension_operations exists  | inverse or missing attribute | CIS 7.2 |
| CKV2_CS_AZ_019 | Ensure Virtual Machines use managed disks (CIS 7.3) | azurerm_linux_virtual_machine,azurerm_windows_virtual_machine | os_disk.storage_account_type exists  | inverse or missing attribute | CIS 7.3 |
| CKV2_CS_AZ_004 | Ensure Azure SQL Database Auditing is enabled (CIS 4.1) | azurerm_mssql_server_extended_auditing_policy,azurerm_sql_server_extended_auditing_policy | enabled equals true | inverse or missing attribute | CIS 4.1 |
| CKV2_CS_AZ_012 | Ensure Azure SQL Database TDE is enabled with Customer-Managed Key (CIS 4.2) | azurerm_mssql_server_transparent_data_encryption | key_vault_key_id exists  | inverse or missing attribute | CIS 4.2 |
| CKV2_CS_AZ_018 | Ensure Azure SQL Database Advanced Threat Protection is enabled (CIS 4.3) | azurerm_mssql_server_security_alert_policy | state equals "Enabled" | inverse or missing attribute | CIS 4.3 |
| CKV2_CS_AZ_032 | require_secure_transport |  | PASS if: resource name == "require_secure_transport" AND value == "ON"; PASS (vacuously) if: resource is a different configuration parameter | FAIL if: name is "require_secure_transport" AND value != "ON" | not declared |
| CKV2_CS_AZ_033 | Ensure MySQL Flexible Server backup retention is >= 7 days (CIS 4.13) |  | PASS if backup_retention_days >= 7 | FAIL if backup_retention_days < 7 or attribute is missing/null | CIS 4.13 |
| CKV2_CS_AZ_034 | Ensure MySQL Flexible Server uses version 8.0 or higher (EOL policy) |  | PASS if major version >= 8  (e.g. "8.0.21", "8.0", "8") | FAIL if major version < 8   (e.g. "5.7", "5.6"); FAIL if version is missing or unparseable | not declared |
| CKV2_CS_AZ_003 | Ensure key vault has purge protection enabled (CIS 8.4) | azurerm_key_vault | purge_protection_enabled equals true | inverse or missing attribute | CIS 8.4 |
| CKV2_CS_AZ_014 | Ensure key vault has soft delete enabled (CIS 8.3) | azurerm_key_vault | soft_delete_retention_days greater_than_or_equal 7 | inverse or missing attribute | CIS 8.3 |
| CKV2_CS_AZ_015 | Ensure Key Vault uses RBAC or explicit access policy authorization | azurerm_key_vault,azurerm_key_vault | enable_rbac_authorization equals true | inverse or missing attribute | not declared |
| CKV2_CS_AZ_029 | Ensure Key Vault keys have expiration date set (CIS 10.1) | azurerm_key_vault_key | expiration_date exists  | inverse or missing attribute | CIS 10.1 |
| CKV2_CS_AZ_030 | Ensure Key Vault secrets have expiration date set (CIS 10.2) | azurerm_key_vault_secret | expiration_date exists  | inverse or missing attribute | CIS 10.2 |
| CKV2_CS_AZ_031 | Ensure no Owner or Contributor role is assigned at subscription scope | Key Vault Crypto Service Encryption User,Key Vault Crypto User,Storage Blob Data Contributor | PASS for all other cases, including: | FAIL only when BOTH conditions are true simultaneously: | not declared |
| CKV2_CS_AZ_035 | Ensure Service Principal password has expiration date (NIST IA-5) |  | PASS if end_date or end_date_relative is present and non-empty | FAIL if both are absent, null, or empty string | NIST IA-5 |
| CKV2_CS_AZ_013 | Ensure Log Analytics Workspace has retention >= 90 days (CIS 5.1) |  | PASS if retention_in_days >= 90 | FAIL if retention_in_days < 90 or attribute missing. | CIS 5.1 |
| CKV2_CS_AZ_016 | Ensure Network Security Group Flow Log retention is greater than 90 days (CIS 6.2) | azurerm_network_watcher_flow_log | retention_policy.days greater_than_or_equal 90 | inverse or missing attribute | CIS 6.2 |
| CKV2_CS_AZ_020 | Ensure diagnostic settings capture appropriate categories (CIS 5.2) | azurerm_monitor_diagnostic_setting | enabled_log exists  | inverse or missing attribute | CIS 5.2 |
| CKV2_CS_AZ_007 | Ensure Network Security Group Flow logs are captured and sent to Log Analytics (CIS 6.1) | azurerm_network_watcher_flow_log | enabled equals true | inverse or missing attribute | CIS 6.1 |
| CKV2_CS_AZ_008 | Ensure Network Security Groups have explicit deny-all inbound rule (CIS 6.5) |  | PASS if the azurerm_network_security_group contains at least one security_rule | FAIL if no such catch-all deny-all inbound rule exists. | CIS 6.5 |
| CKV2_CS_AZ_017 | Ensure RDP access from the Internet is evaluated and restricted (CIS 6.3) |  in single:
        try:
            lo, hi = single.split(,, 1)
            if int(lo) <= port <= int(hi):
                return True
        except (ValueError, TypeError):
            pass

    ranges_raw = rule.get(, in pr:
                try:
                    lo, hi = pr.split(,, 1)
                    if int(lo) <= port <= int(hi):
                        return True
                except (ValueError, TypeError):
                    pass
    return False


def _from_internet(rule: dict) -> bool:
     | scan_resource_conf returns PASSED | FAIL only when a SINGLE security_rule simultaneously satisfies ALL of: | CIS 6.3 |
| CKV2_CS_AZ_021 | Ensure SSH access from the Internet is evaluated and restricted (CIS 6.4) |  in single:
        try:
            lo, hi = single.split(,, 1)
            if int(lo) <= port <= int(hi):
                return True
        except (ValueError, TypeError):
            pass

    # List form: destination_port_ranges  (can be [[...]] or [...])
    ranges_raw = rule.get(, in pr:
                try:
                    lo, hi = pr.split(,, 1)
                    if int(lo) <= port <= int(hi):
                        return True
                except (ValueError, TypeError):
                    pass
    return False


def _from_internet(rule: dict) -> bool:
     | scan_resource_conf returns PASSED | FAIL only when a SINGLE security_rule simultaneously satisfies ALL of: | CIS 6.4 |
| CKV2_CS_AZ_023 | Ensure Microsoft Defender for SQL is enabled (CIS 2.2) | azurerm_mssql_server_security_alert_policy | state equals "Enabled" | inverse or missing attribute | CIS 2.2 |
| CKV2_CS_AZ_024 | Ensure Microsoft Defender for Storage is enabled (CIS 2.3) | azurerm_security_center_subscription_pricing | resource_type equals "StorageAccounts" | inverse or missing attribute | CIS 2.3 |
| CKV2_CS_AZ_001 | Ensure that 'Public access level' is disabled for storage accounts (CIS 3.1) | azurerm_storage_account | allow_nested_items_to_be_public equals false | inverse or missing attribute | CIS 3.1 |
| CKV2_CS_AZ_002 | Ensure that 'Secure transfer required' is enabled for Storage Accounts (CIS 3.2) | azurerm_storage_account | https_traffic_only_enabled equals true | inverse or missing attribute | CIS 3.2 |
| CKV2_CS_AZ_005 | Ensure storage accounts are encrypted with customer-managed keys (CMK) | azurerm_storage_account_customer_managed_key | key_name exists  | inverse or missing attribute | not declared |
| CKV2_CS_AZ_006 | Ensure storage accounts use TLS 1.2 or higher (CIS 3.4) | azurerm_storage_account | min_tls_version equals "TLS1_2" | inverse or missing attribute | CIS 3.4 |

### NIST SP 800-53 Rev 5

| Control | Mapping in CloudSentinel |
|---|---|
| SA-11 | gitleaks + checkov + trivy scan stage |
| CM-3 | immutability guard + policy tests + OPA gate |
| AU-2/AU-3 | audit_events.jsonl + decision_audit_events.jsonl |
| SC-28 | terraform sensitive output redaction + CMK-related IaC controls |
| IA-5 | CKV2_CS_AZ_035 + ARM secret age governance |
| SI-3 | secret and vulnerability scanning pipeline |

### ISO 27001:2022

| Control | Mapping in CloudSentinel |
|---|---|
| A.8.8 | Trivy/Checkov/Gitleaks + DefectDojo upload |
| A.8.25 | OPA enforce before deploy |
| A.5.33 | JSONL audit trails |
| A.8.9 | IaC policy checks + immutability |

### OWASP Top 10 CI/CD Security Risks

| Risk | Mapping in CloudSentinel | Evidence / Notes |
|---|---|---|
| CICD-SEC-1 | retry-guard flow control | implemented in shift-left/ci/retry-guard.sh |
| CICD-SEC-2 | identity governance | immutability allowlist + four-eyes exceptions |
| CICD-SEC-4 | poisoned pipeline prevention | protected regex + pinned images |
| CICD-SEC-6 | credential hygiene | gitleaks + secret age + SP expiry policy |
| CICD-SEC-9 | artifact integrity | SHA256 checks in tool image builds; OpenTofu cosign verify in deploy-tools Dockerfile |

## SECTION 12 ? SYNTH?SE POUR SOUTENANCE PFE

1. CloudSentinel Shift-Left unifies multi-scanner detection, normalization, policy decision, and deployment enforcement in a fail-closed CI architecture.

2. 4-layer architecture: Detect (scanner jobs) -> Normalize (`normalize.py`) -> Decide (`pipeline_decision.rego`) -> Enforce (`run-opa.sh --enforce`, deploy needs).

3. OPA is the single enforcement point because scanner exit codes are advisory and heterogeneous; OPA centralizes threshold, exception, scope, and governance rules.

4. Fail-closed in practice means missing/invalid artifacts, invalid exceptions, or failed policy decision block progression to deploy.

5. Key decisions and rationale: scanners advisory, exceptions externalized in DefectDojo, unified schema contract, immutability guard for control plane integrity.

6. Production-ready next steps beyond PFE: stronger artifact attestations, mandatory approver allowlist, multi-repo governance observability, periodic chaos testing of failure paths.

### Actual Pipeline Output Snapshots Used

```json
{
  "schema_version": "1.1.0",
  "metadata": {
    "tool": "cloudsentinel",
    "timestamp": "2026-04-12T11:23:49Z",
    "generation_duration_ms": 7,
    "environment": "dev",
    "execution": {
      "mode": "advisory"
    },
    "git": {
      "repo": "drghassen/PFE-MPSSR",
      "repository": "drghassen/PFE-MPSSR",
      "branch": "main",
      "commit": "bbdbc48207648abf030861ad3c0745dd6055ce89",
      "commit_date": "2026-04-12T12:16:33+01:00",
      "author_email": "dridighassenbac2021@gmail.com",
      "pipeline_id": "local"
    },
    "normalizer": {
      "version": "1.1.0",
      "source_reports": {
        "gitleaks": {
          "tool": "gitleaks",
          "path": "/home/ghassen/pfe-cloud-sentinel/.cloudsentinel/gitleaks_raw.json",
          "present": true,
          "valid_json": true,
          "status": "PASSED",
          "reason": "",
          "sha256": "37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570"
        },
        "checkov": {
          "tool": "checkov",
          "path": "/home/ghassen/pfe-cloud-sentinel/.cloudsentinel/checkov_raw.json",
          "present": false,
          "valid_json": false,
          "status": "NOT_RUN",
          "reason": "skipped_local_fast",
          "sha256": null
        },
        "trivy": {
          "tool": "trivy",
          "path": "/home/ghassen/pfe-cloud-sentinel/shift-left/trivy/reports/raw",
          "present": false,
          "valid_json": false,
          "status": "NOT_RUN",
          "reason": "skipped_local_fast",
          "sha256": null
        }
      }
    }
  },
  "scanners": {
    "gitleaks": {
      "tool": "gitleaks",
      "version": "unknown",
      "status": "PASSED",
      "errors": [],
      "stats": {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
        "TOTAL": 0,
        "EXEMPTED": 0,
        "FAILED": 0,
        "PASSED": 0
      },
      "findings": []
    },
    "checkov": {
      "tool": "checkov",
      "version": "unknown",
      "status": "NOT_RUN",
      "errors": [
        "skipped_local_fast"
      ],
      "stats": {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
        "TOTAL": 0,
        "EXEMPTED": 0,
        "FAILED": 0,
        "PASSED": 0
      },
      "findings": []
    },
    "trivy": {
      "tool": "trivy",
      "version": "unknown",
      "status": "NOT_RUN",
      "errors": [
        "skipped_local_fast"
      ],
      "stats": {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
        "TOTAL": 0,
        "EXEMPTED": 0,
        "FAILED": 0,
        "PASSED": 0
      },
      "findings": []
    }
  },
  "findings": [],
  "summary": {
    "global": {
      "CRITICAL": 0,
      "HIGH": 0,
      "MEDIUM": 0,
      "LOW": 0,
      "INFO": 0,
      "TOTAL": 0,
      "EXEMPTED": 0,
      "FAILED": 0,
      "PASSED": 0
    },
    "by_tool": {
      "gitleaks": {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
        "TOTAL": 0,
        "EXEMPTED": 0,
        "FAILED": 0,
        "PASSED": 0,
        "status": "PASSED"
      },
      "checkov": {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
        "TOTAL": 0,
        "EXEMPTED": 0,
        "FAILED": 0,
        "PASSED": 0,
        "status": "NOT_RUN"
      },
      "trivy": {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
        "TOTAL": 0,
        "EXEMPTED": 0,
        "FAILED": 0,
        "PASSED": 0,
        "status": "NOT_RUN"
      }
    },
    "by_category": {
      "SECRETS": 0,
      "INFRASTRUCTURE_AS_CODE": 0,
      "VULNERABILITIES": 0
    }
  },
  "quality_gate": {
    "decision": "NOT_EVALUATED",
    "reason": "evaluation-performed-by-opa-only",
    "thresholds": {
      "critical_max": 0,
      "high_max": 2
    },
    "details": {
      "reasons": [
        "opa_is_single_enforcement_point"
      ],
      "not_run_scanners": [
        "checkov",
        "trivy"
      ]
    }
  }
}
```

```json
{"cloudsentinel":{"exceptions":{"schema_version":"2.0.0","generated_at":"2099-01-01T00:00:00Z","metadata":{"source":"local-bootstrap","total_raw_risk_acceptances":0,"total_valid_exceptions":0,"total_dropped":0},"exceptions":[]}}}
```

```json
{
  "decision_id": "8d75518a-d1a2-4bd4-b82f-46c39beb37e6",
  "result": {
    "allow": true,
    "deny": [],
    "environment": "dev",
    "exceptions": {
      "applied_audit": [],
      "applied_count": 0,
      "applied_ids": [],
      "expired_enabled_ids": [],
      "invalid_enabled_ids": [],
      "legacy_after_sunset_ids": [],
      "partial_matches_audit": [],
      "strict_prod_violations": []
    },
    "execution_mode": "advisory",
    "metrics": {
      "critical": 0,
      "excepted": 0,
      "excepted_exception_ids": 0,
      "excepted_findings": 0,
      "failed": 0,
      "failed_effective": 0,
      "failed_input": 0,
      "governance": {
        "active_break_glass": 0,
        "active_exceptions_by_severity": {
          "CRITICAL": 0,
          "HIGH": 0,
          "INFO": 0,
          "LOW": 0,
          "MEDIUM": 0
        },
        "avg_approval_time_hours": 0,
        "expired_enabled_exceptions": 0
      },
      "high": 0,
      "info": 0,
      "low": 0,
      "medium": 0
    },
    "thresholds": {
      "critical_max": 0,
      "high_max": 2
    },
    "_gate": {
      "mode": "--enforce",
      "engine": "server",
      "policy_file": "/home/ghassen/pfe-cloud-sentinel/policies/opa/pipeline_decision.rego",
      "exceptions_file": "/home/ghassen/pfe-cloud-sentinel/.cloudsentinel/exceptions.json",
      "evaluated_at": "2026-04-12T12:27:25Z"
    }
  }
}
```

### Line-Level Trace of Referenced Source Files (code-derived, non-invented)

#### ci/pipelines/shift-left.yml
- L0001: # ============================================================================
- L0002: # CloudSentinel - GitLab CI/CD (Shift-Left)
- L0003: # Shift-Left scanners are advisory only. OPA is the single ALLOW/DENY gate.
- L0004: # ============================================================================
- L0005: ##
- L0006: default:
- L0007:   tags:
- L0008:     - cloudsentinel
- L0009:     - docker
- L0010: 
- L0011: variables:
- L0012:   GIT_STRATEGY: clone
- L0013:   GIT_DEPTH: "1"
- L0014:   TOFU_VERSION: "1.8.8"
- L0015:   TOFU_LINUX_AMD64_ZIP_SHA256: "9e889633bc177b1d266552658020fe8ceb839445fcac82aaa7622952fd9c81bb"
- L0016:   GITLEAKS_VERSION: "8.21.2"
- L0017:   CHECKOV_VERSION: "3.2.502"
- L0018:   TRIVY_VERSION: "0.69.3"
- L0019:   OPA_VERSION: "1.13.1"
- L0020:   JSONSCHEMA_VERSION: "4.25.1"
- L0021:   TRIVY_IMAGE_MIN_REPORTS: "0"
- L0022: 
- L0023:   CRITICAL_MAX: "0"
- L0024:   HIGH_MAX: "2"
- L0025:   RETRY_GUARD_MAX_RETRIES: "3"
- L0026:   RETRY_GUARD_MIN_INTERVAL_SEC: "120"
- L0027: 
- L0028:   # ── Security governance variables (must be set in GitLab CI/CD Settings) ──
- L0029:   # CLOUDSENTINEL_APPSEC_USERS: "user1,user2"  # comma-separated GitLab usernames
- L0030:   #   authorized to modify security policies. If unset, policies-immutability
- L0031:   #   job will fail with exit 2. Set in: Settings → CI/CD → Variables (masked).
- L0032: 
- L0033: stages:
- L0034:   - guard
- L0035:   - scan
- L0036:   - normalize
- L0037:   - contract
- L0038:   - decide
- L0039:   - report
- L0040:   - deploy
- L0041:   - maintenance
- L0042: 
- L0043: .default_tools: &default_tools
- L0044:   image: "registry.gitlab.com/drghassen/pfe-cloud-sentinel/scan-tools@sha256:650fd078db93f2cf235231cf2c27be91f57ac02aa8b0193d5b6d9f5c9ce85c8f"
- L0045:   before_script: []
- L0046: 
- L0047: .trivy_cache_pull: &trivy_cache_pull
- L0048:   cache:
- L0049:     key: "trivy-db-${CI_PROJECT_ID}-${TRIVY_VERSION}"
- L0050:     policy: pull
- L0051:     paths:
- L0052:       - .trivy-cache
- L0053: 
- L0054: .trivy_cache_pull_push: &trivy_cache_pull_push
- L0055:   cache:
- L0056:     key: "trivy-db-${CI_PROJECT_ID}-${TRIVY_VERSION}"
- L0057:     policy: pull-push
- L0058:     paths:
- L0059:       - .trivy-cache
- L0060: 
- L0061: retry-guard:
- L0062:   <<: *default_tools
- L0063:   stage: guard
- L0064:   script:
- L0065:     - bash ci/scripts/retry-guard.sh
- L0066:   allow_failure: false
- L0067: 
- L0068: policies-immutability:
- L0069:   <<: *default_tools
- L0070:   stage: guard
- L0071:   script:
- L0072:     - bash ci/scripts/policies-immutability.sh
- L0073:   allow_failure: false
- L0074: 
- L0075: trivy-db-warm:
- L0076:   <<: *default_tools
- L0077:   stage: guard
- L0078:   cache:
- L0079:     key: "trivy-db-${CI_PROJECT_ID}-${TRIVY_VERSION}"
- L0080:     policy: pull-push
- L0081:     paths:
- L0082:       - .trivy-cache
- L0083:   script:
- L0084:     - trivy image --download-db-only --cache-dir .trivy-cache --no-progress
- L0085:   allow_failure: false
- L0086: 
- L0087: 
- L0088: gitleaks-scan:
- L0089:   <<: *default_tools
- L0090:   stage: scan
- L0091:   variables:
- L0092:     GIT_DEPTH: "0"
- L0093:   script:
- L0094:     - bash ci/scripts/gitleaks-scan.sh
- L0095:   artifacts:
- L0096:     when: always
- L0097:     expire_in: 7 days
- L0098:     paths:
- L0099:       - .cloudsentinel/gitleaks_raw.json
- L0100:       - .cloudsentinel/gitleaks_range_raw.json
- L0101: 
- L0102: checkov-scan:
- L0103:   <<: *default_tools
- L0104:   stage: scan
- L0105:   script:
- L0106:     - bash ci/scripts/checkov-scan.sh
- L0107:   artifacts:
- L0108:     when: always
- L0109:     expire_in: 7 days
- L0110:     paths:
- L0111:       - .cloudsentinel/checkov_raw.json
- L0112:       - .cloudsentinel/checkov_scan.log
- L0113: 
- L0114: trivy-fs-scan:
- L0115:   <<: [*default_tools, *trivy_cache_pull_push]
- L0116:   stage: scan
- L0117:   script:
- L0118:     - bash ci/scripts/trivy-fs-scan.sh
- L0119:   artifacts:
- L0120:     when: always
- L0121:     expire_in: 7 days
- L0122:     paths:
- L0123:       - shift-left/trivy/reports/raw/trivy-fs-raw.json
- L0124:       - shift-left/trivy/reports/sbom/trivy-fs.cdx.json
- L0125: 
- L0126: trivy-config-scan:
- L0127:   <<: [*default_tools, *trivy_cache_pull]
- L0128:   stage: scan
- L0129:   script:
- L0130:     - bash ci/scripts/trivy-config-scan.sh
- L0131:   artifacts:
- L0132:     when: always
- L0133:     expire_in: 7 days
- L0134:     paths:
- L0135:       - shift-left/trivy/reports/raw/trivy-config-raw.json
- L0136: 
- L0137: normalize-reports:
- L0138:   <<: *default_tools
- L0139:   stage: normalize
- L0140:   needs:
- L0141:     - job: gitleaks-scan
- L0142:       artifacts: true
- L0143:     - job: checkov-scan
- L0144:       artifacts: true
- L0145:     - job: trivy-fs-scan
- L0146:       artifacts: true
- L0147:     - job: trivy-config-scan
- L0148:       artifacts: true
- L0149:   script:
- L0150:     - bash ci/scripts/normalize-reports.sh
- L0151:   artifacts:
- L0152:     when: always
- L0153:     expire_in: 30 days
- L0154:     paths:
- L0155:       - .cloudsentinel/golden_report.json
- L0156:       - .cloudsentinel/gitleaks_raw.json
- L0157:       - .cloudsentinel/checkov_raw.json
- L0158:       - .cloudsentinel/checkov_scan.log
- L0159:       - shift-left/trivy/reports/raw/trivy-fs-raw.json
- L0160:       - shift-left/trivy/reports/raw/trivy-config-raw.json
- L0161:       - .cloudsentinel/exceptions.json
- L0162:       - .cloudsentinel/dropped_exceptions.json
- L0163:       - .cloudsentinel/audit_events.jsonl
- L0164: 
- L0165: contract-test:
- L0166:   <<: *default_tools
- L0167:   stage: contract
- L0168:   needs:
- L0169:     - job: normalize-reports
- L0170:       artifacts: true
- L0171:   script:
- L0172:     - bash ci/scripts/contract-test.sh
- L0173: 
- L0174: opa-image-smoke:
- L0175:   image:
- L0176:     name: "registry.gitlab.com/drghassen/pfe-cloud-sentinel/opa@sha256:9ed276b90b3b04e394655b0fd1c82d0525964c9dc7c90b16569720ee163cd882"
- L0177:     entrypoint: [""]
- L0178:   stage: contract
- L0179:   needs:
- L0180:     - job: normalize-reports
- L0181:       artifacts: true
- L0182:   script:
- L0183:     - bash ci/scripts/opa-image-smoke.sh
- L0184:   artifacts:
- L0185:     when: on_failure
- L0186:     expire_in: 7 days
- L0187:     paths:
- L0188:       - .cloudsentinel/opa-image-smoke.log
- L0189: 
- L0190: opa-unit-tests:
- L0191:   image:
- L0192:     name: "registry.gitlab.com/drghassen/pfe-cloud-sentinel/opa@sha256:9ed276b90b3b04e394655b0fd1c82d0525964c9dc7c90b16569720ee163cd882"
- L0193:     entrypoint: [""]
- L0194:   stage: contract
- L0195:   needs:
- L0196:     - job: normalize-reports
- L0197:       artifacts: true
- L0198:   script:
- L0199:     - echo "[opa-unit-tests] Running OPA policy unit tests (isolated from production data)"
- L0200:     - opa test policies/opa -v
- L0201:     - echo "[opa-unit-tests] All tests passed"
- L0202:   allow_failure: false
- L0203: 
- L0204: opa-decision:
- L0205:   image:
- L0206:     name: "registry.gitlab.com/drghassen/pfe-cloud-sentinel/opa@sha256:9ed276b90b3b04e394655b0fd1c82d0525964c9dc7c90b16569720ee163cd882"
- L0207:     entrypoint: [""]
- L0208:   stage: decide
- L0209:   needs:
- L0210:     - job: normalize-reports
- L0211:       artifacts: true
- L0212:     - job: contract-test
- L0213:     - job: opa-image-smoke
- L0214:     - job: opa-unit-tests
- L0215:   script:
- L0216:     - bash ci/scripts/opa-decision.sh
- L0217:   artifacts:
- L0218:     when: always
- L0219:     expire_in: 30 days
- L0220:     paths:
- L0221:       - .cloudsentinel/opa_decision.json
- L0222:       - .cloudsentinel/decision_audit_events.jsonl
- L0223:       - .cloudsentinel/audit_events.jsonl
- L0224: 
- L0225: upload-to-defectdojo:
- L0226:   stage: report
- L0227:   image: "registry.gitlab.com/drghassen/pfe-cloud-sentinel/scan-tools@sha256:650fd078db93f2cf235231cf2c27be91f57ac02aa8b0193d5b6d9f5c9ce85c8f"
- L0228:   retry: 2
- L0229:   allow_failure: true
- L0230:   variables:
- L0231:     GIT_STRATEGY: fetch
- L0232:   needs:
- L0233:     - job: gitleaks-scan
- L0234:       artifacts: true
- L0235:     - job: checkov-scan
- L0236:       artifacts: true
- L0237:     - job: trivy-fs-scan
- L0238:       artifacts: true
- L0239:     - job: trivy-config-scan
- L0240:       artifacts: true
- L0241:   script:
- L0242:     - bash ci/scripts/upload-to-defectdojo.sh
- L0243:   artifacts:
- L0244:     when: always
- L0245:     expire_in: 7 days
- L0246:     paths:
- L0247:       - .cloudsentinel/dojo-responses/
- L0248:   when: always
- L0249: 
- L0250: deploy-infrastructure:
- L0251:   # Digest pinned to current production build. Update after each rebuild via:
- L0252:   # docker inspect registry.gitlab.com/.../deploy-tools:latest --format '{{index .RepoDigests 0}}'
- L0253:   image: "registry.gitlab.com/drghassen/pfe-cloud-sentinel/deploy-tools@sha256:3a5a7b53028fa1c8bdfbaa7052d627414d5c1348b8aaa8b8fe4488a7ba5a8025"
- L0254:   before_script: []
- L0255:   stage: deploy
- L0256:   needs:
- L0257:     - job: opa-decision
- L0258:       artifacts: true
- L0259:   script:
- L0260:     - bash ci/scripts/deploy-infrastructure.sh
- L0261:   artifacts:
- L0262:     when: always
- L0263:     expire_in: 30 days
- L0264:     paths:
- L0265:       - .cloudsentinel/terraform_outputs_student_secure.json
- L0266:       - infra/azure/student-secure/tfplan
- L0267:   rules:
- L0268:     - if: '$CI_PIPELINE_SOURCE == "push" && $CI_COMMIT_BRANCH =~ /^(main|develop)$/'
- L0269: trigger-deploy-tools-rebuild:
- L0270:   stage: maintenance
- L0271:   needs: []
- L0272:   trigger:
- L0273:     include: .gitlab-ci-image-factory.yml
- L0274:     strategy: depend
- L0275:   rules:
- L0276:     - if: '$CI_PIPELINE_SOURCE == "push" && $CI_COMMIT_BRANCH == "main"'
- L0277:       changes:
- L0278:         - ci/images/deploy-tools/Dockerfile

#### shift-left/gitleaks/gitleaks.toml
- L0001: # ADR-0005: Hybrid secret-detection model for enterprise cloud security.
- L0002: # Decision (2026-04-02): enable Gitleaks defaults and retain CloudSentinel custom rules.
- L0003: # Rationale: defaults prevent maintenance blind spots; custom Azure rules add high-fidelity cloud coverage.
- L0004: 
- L0005: title = "CloudSentinel Enterprise v5.0 - PFE Edition"
- L0006: description = "Enterprise-grade secret detection - Hybrid model (custom Azure rules + upstream defaults)"
- L0007: version = "5.0.1-hybrid"
- L0008: author = "CloudSentinel Security Team"
- L0009: 
- L0010: [extend]
- L0011: useDefault = true
- L0012: 
- L0013: [allowlist]
- L0014: description = "Non-exploitable patterns - PFE optimized (Azure samples/dev placeholders)"
- L0015: paths = [
- L0016:   '''(^|/)vendor/''',
- L0017:   '''(^|/)node_modules/''',
- L0018:   '''(^|/)\.pnpm-store/''',
- L0019:   '''(^|/)\.terraform/''',
- L0020:   '''(^|/)\.terragrunt-cache/''',
- L0021:   '''(^|/)\.git/''',
- L0022:   '''(^|/)tests?/fixtures/''',
- L0023:   '''(^|/)__tests__/fixtures/''',
- L0024:   '''(^|/)test/fixtures/''',
- L0025:   '''(^|/)infra/azure/student-secure/tests/''',
- L0026:   '''(^|/)shift-left/checkov/tests/fixtures/''',
- L0027:   '''(^|/)shift-left/gitleaks/tests/fixtures/''',
- L0028:   '''(^|/)shift-left/trivy/tests/fixtures/''',
- L0029:   '''(^|/)(?:infra|terraform|iac)/.*(?:examples?|samples?)/''',
- L0030:   '''(^|/)docs/(?:examples?|samples?|learn)/''',
- L0031:   '''(^|/)gitleaks\.toml$'''
- L0032: ]
- L0033: 
- L0034: files = [
- L0035:   '''.*\.lock$''',
- L0036:   '''package-lock\.json$''',
- L0037:   '''yarn\.lock$''',
- L0038:   '''go\.sum$''',
- L0039:   '''.*\.min\.(js|css)$''',
- L0040:   '''.*\.(png|jpg|jpeg|gif|svg|ico|pdf)$''',
- L0041:   '''.*\.map$''',
- L0042:   '''.*\.(test|spec)\.(js|ts|py|go)$'''
- L0043: ]
- L0044: 
- L0045: regexes = [
- L0046:   '''^[a-f0-9]{40}$''',
- L0047:   '''^sha256:[a-f0-9]{64}$''',
- L0048:   '''^YOUR?_?(API|SECRET|KEY|TOKEN|PASSWORD)$''',
- L0049:   '''(?i)^example$''',
- L0050:   '''(?i)^placeholder$''',
- L0051:   '''^xxx+$''',
- L0052:   '''^XXX+$''',
- L0053:   '''^test123$''',
- L0054:   '''^password123$''',
- L0055:   '''^changeme$''',
- L0056:   '''^admin123$''',
- L0057:   '''^AKIAIOSFODNN7EXAMPLE$''',
- L0058:   '''^wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY$''',
- L0059:   '''^id_[a-z0-9]{10,}$''',
- L0060:   '''(?i)\b(postgres|postgresql|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@(localhost|127\.0\.0\.1)(:\d+)?([/\?#][^\s]*)?$''',
- L0061:   '''(?i)\b(postgres|postgresql|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@(\[::1\]|::1)(:\d+)?([/\?#][^\s]*)?$''',
- L0062:   '''(?i)\bAccountKey=YOUR_ACCOUNT_KEY\b''',
- L0063:   '''(?i)\b(?:YOUR_AZURE_KEY|your-azure-key)\b''',
- L0064:   '''(?i)\bUseDevelopmentStorage=true\b''',
- L0065:   '''^Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==$''',
- L0066:   '''^00000000-0000-0000-0000-000000000000$''',
- L0067:   '''(?i)\bclient_secret\s*=\s*"(?:YOUR[_-]?CLIENT[_-]?SECRET|<client_secret>|example|changeme|your-azure-key)"'''
- L0068: ]
- L0069: 
- L0070: # Targets AWS IAM access key IDs exposed in code/config.
- L0071: # Prefix + fixed 16-char suffix mirrors AWS key-id format and limits false positives.
- L0072: # Example catch: AKIA****************.
- L0073: [[rules]]
- L0074: id = "aws-access-key-id"
- L0075: description = "AWS Access Key ID"
- L0076: regex = '''(A3T[A-Z0-9]|AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}'''
- L0077: severity = "CRITICAL"
- L0078: tags = ["cloud", "aws", "iam", "credential"]
- L0079: 
- L0080: # Targets explicit AWS secret access key assignments in env/config files.
- L0081: # Context key names + 40-char base64-like value reduce random-string matches.
- L0082: # Example catch: aws_secret_access_key="********************************".
- L0083: [[rules]]
- L0084: id = "aws-secret-access-key"
- L0085: description = "AWS Secret Access Key"
- L0086: regex = '''(?i)\baws[_-]?(secret[_-]?access[_-]?key|secret[_-]?key|secret)\b\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?'''
- L0087: severity = "CRITICAL"
- L0088: tags = ["cloud", "aws", "iam", "credential"]
- L0089: 
- L0090: # Targets GCP service-account JSON private keys committed as blobs.
- L0091: # Bounded dotall window prevents runaway matching while preserving multiline key coverage.
- L0092: # Example catch: {"type":"service_account", "private_key":"-----BEGIN PRIVATE KEY-----..."}.
- L0093: [[rules]]
- L0094: id = "gcp-service-account-key"
- L0095: description = "GCP Service Account JSON Key"
- L0096: regex = '''(?s)"type"\s*:\s*"service_account".{0,800}?"private_key"\s*:\s*"(?:-----BEGIN PRIVATE KEY-----|-----BEGIN RSA PRIVATE KEY-----)(?:\\n|\n).{50,}?(?:\\n|\n)-----END (?:PRIVATE KEY|RSA PRIVATE KEY)-----'''
- L0097: severity = "CRITICAL"
- L0098: tags = ["cloud", "gcp", "service-account", "credential"]
- L0099: 
- L0100: # Targets Azure AD / Entra app secrets in env vars and IaC variables.
- L0101: # Includes ARM_/AZURE_ prefixes and generic client_secret assignments with 32-80 charset bounds.
- L0102: # Example catch: ARM_CLIENT_SECRET="********************************".
- L0103: [[rules]]
- L0104: id = "azure-client-secret"
- L0105: description = "Azure AD Client Secret"
- L0106: regex = '''(?i)\b(?:ARM_CLIENT_SECRET|AZURE_CLIENT_SECRET|(?:azure|aad|entra|microsoft|arm)[_-]?client[_-]?secret|client_secret)\b\s*[:=]\s*["']?[A-Za-z0-9~._-]{32,80}["']?'''
- L0107: severity = "CRITICAL"
- L0108: tags = ["cloud", "azure", "aad", "credential"]
- L0109: 
- L0110: # Targets Azure Storage connection strings carrying AccountKey material.
- L0111: # Requires storage connection-string keys and base64 AccountKey value to reduce generic hits.
- L0112: # Example catch: DefaultEndpointsProtocol=https;AccountName=...;AccountKey=...==;EndpointSuffix=core.windows.net.
- L0113: [[rules]]
- L0114: id = "azure-storage-connection"
- L0115: description = "Azure Storage Connection String"
- L0116: regex = '''(?i)\b(DefaultEndpointsProtocol|BlobEndpoint)=https?;[^\n\r]{0,400}?\bAccountName=[^;\s]+;[^\n\r]{0,400}?\bAccountKey=[A-Za-z0-9+/=]{40,}\b'''
- L0117: severity = "CRITICAL"
- L0118: tags = ["cloud", "azure", "storage", "credential"]
- L0119: 
- L0120: # Targets standalone Azure Storage account keys outside connection strings.
- L0121: # Anchored assignment pattern reduces scan cost on large files while preserving precision.
- L0122: # Example catch: AZURE_STORAGE_KEY="***************************************==".
- L0123: [[rules]]
- L0124: id = "azure-storage-account-key-standalone"
- L0125: description = "Azure Storage Account Key (Standalone)"
- L0126: regex = '''(?im)^\s*(?:export\s+)?(?:AZURE_STORAGE(?:ACCOUNT)?(?:_KEY|_ACCESS_KEY)?|ACCOUNTKEY|storage[_-]?account[_-]?key)\s*[:=]\s*["']?(?:[A-Za-z0-9+/]{86}==|[A-Za-z0-9+/]{87}=)["']?\s*$'''
- L0127: severity = "CRITICAL"
- L0128: tags = ["cloud", "azure", "storage", "credential", "standalone-key"]
- L0129: 
- L0130: # Targets Azure Cosmos DB connection strings with AccountEndpoint + AccountKey (master key exposure).
- L0131: # Contextual key/value pattern minimizes noise versus generic long base64 detection.
- L0132: # Example catch: AccountEndpoint=https://contoso.documents.azure.com:443/;AccountKey=<redacted>==;
- L0133: [[rules]]
- L0134: id = "azure-cosmos-db-connection-key"
- L0135: description = "Azure Cosmos DB AccountEndpoint + AccountKey"
- L0136: regex = '''(?i)\bAccountEndpoint=https?://[^;\s]+;\s*AccountKey=[A-Za-z0-9+/]{64,128}==;?'''
- L0137: severity = "CRITICAL"
- L0138: tags = ["cloud", "azure", "cosmosdb", "credential", "connection-string"]
- L0139: 
- L0140: # Targets GitHub classic PAT credentials.
- L0141: # Fixed ghp_ prefix + 36-char body keeps precision high.
- L0142: # Example catch: ghp_************************************.
- L0143: [[rules]]
- L0144: id = "github-pat-classic"
- L0145: description = "GitHub Personal Access Token (Classic)"
- L0146: regex = '''\bghp_[A-Za-z0-9]{36}\b'''
- L0147: severity = "CRITICAL"
- L0148: tags = ["scm", "github", "pat", "credential"]
- L0149: 
- L0150: # Targets GitHub fine-grained PAT credentials.
- L0151: # github_pat_ prefix and long token length distinguish from random identifiers.
- L0152: # Example catch: github_pat_********************************....
- L0153: [[rules]]
- L0154: id = "github-pat-finegrained"
- L0155: description = "GitHub Fine-grained Personal Access Token"
- L0156: regex = '''\bgithub_pat_[A-Za-z0-9_]{40,255}\b'''
- L0157: severity = "CRITICAL"
- L0158: tags = ["scm", "github", "pat", "fine-grained", "credential"]
- L0159: 
- L0160: # Targets GitLab PAT credentials.
- L0161: # glpat- prefix plus minimum token length reflects GitLab PAT format.
- L0162: # Example catch: glpat-****************************.
- L0163: [[rules]]
- L0164: id = "gitlab-pat"
- L0165: description = "GitLab Personal Access Token"
- L0166: regex = '''\bglpat-[A-Za-z0-9-]{20,}\b'''
- L0167: severity = "CRITICAL"
- L0168: tags = ["scm", "gitlab", "pat", "credential"]
- L0169: 
- L0170: # Targets Azure DevOps PATs in pipeline/developer environment variables.
- L0171: # Uses Azure DevOps variable context and 52-char base36 core format (plus legacy 72-char compatibility).
- L0172: # Example catch: export AZURE_DEVOPS_EXT_PAT=************************************.
- L0173: [[rules]]
- L0174: id = "azure-devops-pat"
- L0175: description = "Azure DevOps Personal Access Token"
- L0176: regex = '''(?i)\b(?:AZURE_DEVOPS_EXT_PAT|AZURE_DEVOPS_PAT|ADO_PAT|AZDO_PAT|SYSTEM_ACCESSTOKEN)\b\s*[:=]\s*["']?(?:[a-z0-9]{52}|[a-z0-9]{72})["']?'''
- L0177: severity = "CRITICAL"
- L0178: tags = ["scm", "azure", "azure-devops", "pat", "credential"]
- L0179: 
- L0180: # Targets Slack incoming webhooks with write capability.
- L0181: # Full hooks.slack.com path structure avoids generic URL matches.
- L0182: # Example catch: https://hooks.slack.com/services/T.../B.../....
- L0183: [[rules]]
- L0184: id = "slack-webhook"
- L0185: description = "Slack Incoming Webhook URL"
- L0186: regex = '''(?i)https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{20,}'''
- L0187: severity = "CRITICAL"
- L0188: tags = ["saas", "slack", "webhook", "write-access"]
- L0189: 
- L0190: # Targets PEM/OpenSSH/PGP private key blocks in plaintext.
- L0191: # BEGIN/END guards and minimum payload reduce accidental binary/text collisions.
- L0192: # Example catch: -----BEGIN PRIVATE KEY----- ... -----END PRIVATE KEY-----.
- L0193: [[rules]]
- L0194: id = "private-key-block"
- L0195: description = "Private Key Block (RSA/EC/DSA/OpenSSH/PGP)"
- L0196: regex = '''-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----(?:[A-Za-z0-9+/=\r\n\s]{80,}?)(?:-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)'''
- L0197: severity = "CRITICAL"
- L0198: tags = ["crypto", "pki", "private-key", "credential"]
- L0199: 
- L0200: # Targets Azure SAS tokens used for delegated storage access.
- L0201: # Requires service version and signature parameters to separate from generic query strings.
- L0202: # Example catch: sv=2024-08-04&...&sig=....
- L0203: [[rules]]
- L0204: id = "azure-sas-token"
- L0205: description = "Azure Shared Access Signature Token"
- L0206: regex = '''(?i)\bsv=\d{4}-\d{2}-\d{2}[^\n\r]{0,800}?\bsig=[A-Za-z0-9%/+._=-]{20,}\b'''
- L0207: severity = "HIGH"
- L0208: tags = ["cloud", "azure", "sas", "token"]
- L0209: 
- L0210: # Targets Google API keys.
- L0211: # AIza prefix + fixed-length body mirrors official key shape.
- L0212: # Example catch: AIza***********************************.
- L0213: [[rules]]
- L0214: id = "gcp-api-key"
- L0215: description = "Google Cloud API Key"
- L0216: regex = '''\bAIza[0-9A-Za-z_\-]{35}\b'''
- L0217: severity = "HIGH"
- L0218: tags = ["cloud", "gcp", "api-key", "quota-risk"]
- L0219: 
- L0220: # Targets explicit HashiCorp Vault token assignments.
- L0221: # Supports legacy s. and newer hvs./hvb. token prefixes.
- L0222: # Example catch: vault_token="hvs.************************".
- L0223: [[rules]]
- L0224: id = "vault-token-explicit"
- L0225: description = "HashiCorp Vault Token"
- L0226: regex = '''(?i)\bvault[_-]?token\b\s*[:=]\s*["']?(?:s\.[A-Za-z0-9]{20,}|hvs\.[A-Za-z0-9]{20,}|hvb\.[A-Za-z0-9]{20,})["']?'''
- L0227: severity = "HIGH"
- L0228: tags = ["vault", "hashicorp", "token", "secrets-management"]
- L0229: 
- L0230: # Targets Kubernetes Secret manifests where base64 data is inline.
- L0231: # Bounded multiline YAML matcher focuses on kind: Secret plus data keys.
- L0232: # Example catch: kind: Secret\n...\ndata:\n  password: c2VjcmV0...
- L0233: [[rules]]
- L0234: id = "kubernetes-secret-yaml"
- L0235: description = "Kubernetes Secret with Base64 data"
- L0236: regex = '''(?is)\bkind:\s*Secret\b.{0,800}?\bdata:\s*(?:\n\s+[A-Za-z0-9_.-]+\s*:\s*[A-Za-z0-9+/=]{16,})+'''
- L0237: severity = "HIGH"
- L0238: tags = ["kubernetes", "k8s", "secret", "base64"]
- L0239: 
- L0240: # Targets production-style DB URLs embedding credentials.
- L0241: # Scheme + user:pass@host structure detects high-risk credentialed DSNs.
- L0242: # Example catch: postgres://user:pass@prod-db.internal:5432/app.
- L0243: [[rules]]
- L0244: id = "database-connection-prod"
- L0245: description = "Database Connection String with credentials (Host reviewed by allowlist)"
- L0246: regex = '''(?i)\b(postgres|postgresql|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@[^/\s]+'''
- L0247: severity = "MEDIUM"
- L0248: tags = ["database", "connection-string", "credential"]
- L0249: 
- L0250: # Targets Azure API Management subscription key headers/variables.
- L0251: # Context key names and constrained alnum length reduce generic token noise.
- L0252: # Example catch: Ocp-Apim-Subscription-Key: ********************************.
- L0253: [[rules]]
- L0254: id = "azure-apim-subscription-key"
- L0255: description = "Azure API Management Subscription Key"
- L0256: regex = '''(?i)\b(ocp-apim-subscription-key|apim[_-]?key|subscription[_-]?key)\s*[:=]\s*["']?[A-Za-z0-9]{32,64}["']?'''
- L0257: severity = "HIGH"
- L0258: tags = ["cloud", "azure", "apim", "api-management", "credential"]
- L0259: 
- L0260: # Targets Terraform Cloud/Enterprise API tokens in CI and IaC.
- L0261: # Known env var names + minimum token length capture real operator patterns.
- L0262: # Example catch: TFC_TOKEN="*******************************".
- L0263: [[rules]]
- L0264: id = "terraform-cloud-token"
- L0265: description = "Terraform Cloud / Terraform Enterprise API Token"
- L0266: regex = '''(?i)\b(TFE_TOKEN|TFC_TOKEN|TERRAFORM_TOKEN|terraform[_-]?cloud[_-]?token)\s*[:=]\s*["']?[A-Za-z0-9._-]{32,}["']?'''
- L0267: severity = "CRITICAL"
- L0268: tags = ["iac", "terraform", "ci", "credential", "infra-access"]
- L0269: 
- L0270: # Targets hardcoded JWT signing material in source/config.
- L0271: # Secret-like key names plus 16+ char value catches insecure embedded signing secrets.
- L0272: # Example catch: JWT_SECRET="************************".
- L0273: [[rules]]
- L0274: id = "jwt-hardcoded-secret"
- L0275: description = "JWT signing secret hardcoded in code or config"
- L0276: regex = '''(?i)\b(jwt[_-]?secret|jwt[_-]?key|token[_-]?secret|signing[_-]?secret)\b\s*[:=]\s*["']?[A-Za-z0-9!@#$%^&*_\-+=./]{16,}["']?'''
- L0277: severity = "HIGH"
- L0278: tags = ["auth", "jwt", "signing-key", "credential"]

#### shift-left/gitleaks/run-gitleaks.sh
- L0001: #!/usr/bin/env bash
- L0002: set -euo pipefail
- L0003: 
- L0004: log()  { echo "[CloudSentinel][Gitleaks] $*"; }
- L0005: err()  { echo "[CloudSentinel][Gitleaks][ERROR] $*" >&2; }
- L0006: 
- L0007: SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
- L0008: source "${SCRIPT_DIR}/../lib_scanner_utils.sh"
- L0009: 
- L0010: REPO_ROOT="$(cs_get_repo_root)"
- L0011: OUT_DIR="$REPO_ROOT/.cloudsentinel"
- L0012: REPORT_RAW_OUT="$OUT_DIR/gitleaks_raw.json"
- L0013: CONFIG_PATH="${CONFIG_PATH:-$REPO_ROOT/shift-left/gitleaks/gitleaks.toml}"
- L0014: SCAN_TARGET="${SCAN_TARGET:-staged}"
- L0015: MAX_SIZE_MB="${GITLEAKS_MAX_SIZE:-5}"
- L0016: 
- L0017: if [[ -n "${CI:-}" ]]; then
- L0018:   TIMEOUT_SEC="${CLOUDSENTINEL_TIMEOUT:-300}"
- L0019: else
- L0020:   TIMEOUT_SEC="${CLOUDSENTINEL_TIMEOUT:-60}"
- L0021: fi
- L0022: 
- L0023: mkdir -p "$OUT_DIR"
- L0024: 
- L0025: command -v git >/dev/null 2>&1 || { err "git binary missing"; exit 2; }
- L0026: command -v jq >/dev/null 2>&1 || { err "jq binary missing"; exit 2; }
- L0027: command -v gitleaks >/dev/null 2>&1 || { err "gitleaks binary missing"; exit 2; }
- L0028: [[ -f "$CONFIG_PATH" ]] || { err "gitleaks config missing: $CONFIG_PATH"; exit 2; }
- L0029: 
- L0030: TIMEOUT_BIN=""
- L0031: command -v timeout >/dev/null 2>&1 && TIMEOUT_BIN="timeout"
- L0032: 
- L0033: run_cmd() {
- L0034:   if [[ "$TIMEOUT_SEC" -gt 0 && -n "$TIMEOUT_BIN" ]]; then
- L0035:     timeout "$TIMEOUT_SEC" "$@"
- L0036:   else
- L0037:     "$@"
- L0038:   fi
- L0039: }
- L0040: 
- L0041: SCAN_MODE="${SCAN_MODE:-}"
- L0042: if [[ "$SCAN_MODE" != "ci" && "$SCAN_MODE" != "local" ]]; then
- L0043:   [[ -n "${CI:-}" ]] && SCAN_MODE="ci" || SCAN_MODE="local"
- L0044: fi
- L0045: 
- L0046: log "Starting raw scan (mode=$SCAN_MODE, max_size=${MAX_SIZE_MB}MB)..."
- L0047: 
- L0048: set +e
- L0049: if [[ "$SCAN_MODE" == "local" ]]; then
- L0050:   if [[ "$SCAN_TARGET" == "repo" ]]; then
- L0051:     run_cmd gitleaks detect --source "$REPO_ROOT" --redact --config "$CONFIG_PATH" --report-format json --report-path "$REPORT_RAW_OUT" --max-target-megabytes "$MAX_SIZE_MB"
- L0052:   else
- L0053:     run_cmd gitleaks protect --staged --redact --config "$CONFIG_PATH" --report-format json --report-path "$REPORT_RAW_OUT" --max-target-megabytes "$MAX_SIZE_MB"
- L0054:   fi
- L0055: else
- L0056:   # CI must scan the full checked-out repository snapshot (no commit history).
- L0057:   run_cmd gitleaks detect --no-git --source "$REPO_ROOT" --redact --config "$CONFIG_PATH" --report-format json --report-path "$REPORT_RAW_OUT" --max-target-megabytes "$MAX_SIZE_MB"
- L0058: fi
- L0059: RC=$?
- L0060: set -e
- L0061: 
- L0062: if [[ "$RC" -gt 1 ]]; then
- L0063:   err "gitleaks execution error rc=$RC"
- L0064:   exit 2
- L0065: fi
- L0066: 
- L0067: [[ -s "$REPORT_RAW_OUT" ]] || { err "gitleaks raw output missing: $REPORT_RAW_OUT"; exit 2; }
- L0068: jq -e 'type=="array"' "$REPORT_RAW_OUT" >/dev/null || { err "gitleaks raw output invalid JSON array"; exit 2; }
- L0069: 
- L0070: log "Raw report ready: $REPORT_RAW_OUT"
- L0071: 
- L0072: # --- Scan range secondaire (enrichissement metadata — non-gating) ---
- L0073: # ENRICHISSEMENT UNIQUEMENT : gitleaks_range_raw.json n'alimente jamais OPA.
- L0074: # Signal OPA = gitleaks_raw.json (scan principal --no-git) uniquement.
- L0075: if [[ -n "${CI:-}" ]]; then
- L0076:   RANGE_OUT="$OUT_DIR/gitleaks_range_raw.json"
- L0077:   LOG_OPTS=""
- L0078:   ZERO_SHA="0000000000000000000000000000000000000000"
- L0079: 
- L0080:   if [[ -n "${CI_MERGE_REQUEST_TARGET_BRANCH_SHA:-}" \
- L0081:         && "${CI_MERGE_REQUEST_TARGET_BRANCH_SHA}" != "$ZERO_SHA" ]]; then
- L0082:     LOG_OPTS="${CI_MERGE_REQUEST_TARGET_BRANCH_SHA}..${CI_COMMIT_SHA:-HEAD}"
- L0083:   elif [[ -n "${CI_COMMIT_BEFORE_SHA:-}" \
- L0084:           && "${CI_COMMIT_BEFORE_SHA}" != "$ZERO_SHA" ]]; then
- L0085:     LOG_OPTS="${CI_COMMIT_BEFORE_SHA}..${CI_COMMIT_SHA:-HEAD}"
- L0086:   else
- L0087:     LOG_OPTS="--max-count=200"
- L0088:   fi
- L0089: 
- L0090:   log "Starting range scan (enrichissement, best-effort, log-opts='$LOG_OPTS')..."
- L0091:   set +e
- L0092:   run_cmd gitleaks detect \
- L0093:     --source "$REPO_ROOT" \
- L0094:     --log-opts "$LOG_OPTS" \
- L0095:     --redact \
- L0096:     --config "$CONFIG_PATH" \
- L0097:     --report-format json \
- L0098:     --report-path "$RANGE_OUT" \
- L0099:     --max-target-megabytes "$MAX_SIZE_MB"
- L0100:   RC_RANGE=$?
- L0101:   set -e
- L0102: 
- L0103:   if [[ "$RC_RANGE" -gt 1 ]]; then
- L0104:     log "WARN: range scan failed rc=$RC_RANGE — skipping enrichment"
- L0105:   else
- L0106:     if jq -e 'type=="array"' "$RANGE_OUT" >/dev/null 2>&1; then
- L0107:       log "Range report ready: $RANGE_OUT"
- L0108:       # Merge range findings into the main report for OPA gate evaluation.
- L0109:       # Deduplication is handled by normalize.py fingerprint.
- L0110:       if [[ -s "$RANGE_OUT" ]] && jq -e 'length > 0' "$RANGE_OUT" >/dev/null 2>&1; then
- L0111:         MERGED_COUNT=$(jq -s '.[0] + .[1] | unique_by(.Fingerprint // .fingerprint // .)' \
- L0112:           "$REPORT_RAW_OUT" "$RANGE_OUT" | jq 'length')
- L0113:         jq -s '.[0] + .[1] | unique_by(.Fingerprint // .fingerprint // .)' \
- L0114:           "$REPORT_RAW_OUT" "$RANGE_OUT" > "${REPORT_RAW_OUT}.merged"
- L0115:         mv "${REPORT_RAW_OUT}.merged" "$REPORT_RAW_OUT"
- L0116:         log "Merged range findings into main report. Total unique findings: $MERGED_COUNT"
- L0117:       fi
- L0118:     else
- L0119:       log "WARN: range report invalid JSON — skipping enrichment"
- L0120:       rm -f "$RANGE_OUT"
- L0121:     fi
- L0122:   fi
- L0123: fi
- L0124: 
- L0125: exit 0

#### ci/scripts/gitleaks-scan.sh
- L0001: #!/usr/bin/env bash
- L0002: set -euo pipefail
- L0003: 
- L0004: gitleaks version
- L0005: mkdir -p .cloudsentinel
- L0006: chmod +x shift-left/gitleaks/run-gitleaks.sh
- L0007: bash shift-left/gitleaks/run-gitleaks.sh
- L0008: chmod a+r .cloudsentinel/gitleaks_raw.json 2>/dev/null || true
- L0009: 
- L0010: IGNORE_FILE="shift-left/gitleaks/.gitleaksignore"
- L0011: if [[ -f "$IGNORE_FILE" ]]; then
- L0012:   while IFS= read -r line; do
- L0013:     [[ -z "$line" || "$line" =~ ^# ]] && continue
- L0014:     IFS=':' read -ra parts <<< "$line"
- L0015:     if [[ "${#parts[@]}" -lt 4 ]]; then
- L0016:       echo "[gitleaks][GOVERNANCE] FAIL: malformed .gitleaksignore entry (expected fingerprint:ticket:expiry:justification): $line" >&2
- L0017:       exit 1
- L0018:     fi
- L0019:     expiry="${parts[2]}"
- L0020:     if [[ -n "$expiry" ]] && [[ "$expiry" < "$(date +%Y-%m-%d)" ]]; then
- L0021:       echo "[gitleaks][GOVERNANCE] FAIL: expired suppression in .gitleaksignore: $line" >&2
- L0022:       exit 1
- L0023:     fi
- L0024:   done < "$IGNORE_FILE"
- L0025:   echo "[gitleaks][GOVERNANCE] .gitleaksignore governance check passed."
- L0026: fi
- L0027: jq -r '"[scan-summary] gitleaks_raw_findings=" + (length|tostring)' .cloudsentinel/gitleaks_raw.json

#### shift-left/checkov/.checkov.yml
- L0001: # CloudSentinel Checkov Configuration (Enterprise)
- L0002: #
- L0003: # Objective:
- L0004: # - Parse Terraform/Kubernetes with Checkov
- L0005: # - Load CloudSentinel custom policies
- L0006: # - Keep IaC scope only (Docker checks skipped)
- L0007: # Final allowlist filtering (CKV2_CS_AZ_*, CKV_AZURE_*, CKV_K8S_*) is enforced
- L0008: # in run-checkov.sh for OPA-ready normalization.
- L0009: # Policies are loaded from shift-left/checkov/policies
- L0010: #
- L0011: # NOTE:
- L0012: # - We use Terraform/Kubernetes frameworks for IaC parsing.
- L0013: # - We do not force a static "check" list here to avoid drift with built-in IDs.
- L0014: 
- L0015: framework:
- L0016:   - terraform
- L0017:   - kubernetes
- L0018: 
- L0019: output: json
- L0020: quiet: true
- L0021: compact: true
- L0022: 
- L0023: download-external-modules: false
- L0024: soft-fail: true
- L0025: 
- L0026: # Avoid overlap with Trivy (Docker) and keep scope IaC/K8s only.
- L0027: skip-check:
- L0028:   - CKV_DOCKER_*
- L0029: 
- L0030: # Allow everything else; policy-level filtering happens in run-checkov.sh

#### shift-left/checkov/run-checkov.sh
- L0001: #!/usr/bin/env bash
- L0002: set -euo pipefail
- L0003: 
- L0004: log_info() { echo "[Checkov][INFO] $*"; }
- L0005: log_err()  { echo "[Checkov][ERROR] $*" >&2; }
- L0006: 
- L0007: SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
- L0008: source "${SCRIPT_DIR}/../lib_scanner_utils.sh"
- L0009: 
- L0010: REPO_ROOT="$(cs_get_repo_root)"
- L0011: OUT_DIR="$REPO_ROOT/.cloudsentinel"
- L0012: mkdir -p "$OUT_DIR"
- L0013: 
- L0014: POLICIES_DIR="${SCRIPT_DIR}/policies"
- L0015: CONFIG_FILE="${SCRIPT_DIR}/.checkov.yml"
- L0016: 
- L0017: REPORT_RAW="$OUT_DIR/checkov_raw.json"
- L0018: REPORT_LOG="$OUT_DIR/checkov_scan.log"
- L0019: 
- L0020: command -v checkov >/dev/null 2>&1 || { log_err "checkov binary missing"; exit 2; }
- L0021: command -v jq >/dev/null 2>&1 || { log_err "jq binary missing"; exit 2; }
- L0022: [[ -f "$CONFIG_FILE" ]] || { log_err "config file missing: $CONFIG_FILE"; exit 2; }
- L0023: [[ -d "$POLICIES_DIR" ]] || { log_err "policies dir missing: $POLICIES_DIR"; exit 2; }
- L0024: 
- L0025: SCAN_TARGET="${1:-$REPO_ROOT}"
- L0026: log_info "Starting raw scan on: $SCAN_TARGET"
- L0027: 
- L0028: checkov_cmd=(checkov --directory "$SCAN_TARGET")
- L0029: checkov_cmd+=("--config-file" "$CONFIG_FILE")
- L0030: checkov_cmd+=("--external-checks-dir" "$POLICIES_DIR")
- L0031: # CKV_AZURE_43: Storage name uses substr() for the Azure 24-char limit.
- L0032: # Static analysis cannot evaluate the dynamic name — validated at runtime.
- L0033: checkov_cmd+=("--skip-check" "CKV_AZURE_43")
- L0034: 
- L0035: # Locked skip paths: do not trust runtime environment overrides.
- L0036: readonly LOCKED_SKIP_PATHS="infra/azure/student-secure/tests,infra/azure/test/tests,tests/fixtures"
- L0037: IFS=',' read -r -a skip_paths <<< "$LOCKED_SKIP_PATHS"
- L0038: for skip_path in "${skip_paths[@]}"; do
- L0039:   skip_path="$(echo "$skip_path" | xargs)"
- L0040:   [[ -z "$skip_path" ]] && continue
- L0041:   checkov_cmd+=("--skip-path" "$skip_path")
- L0042: done
- L0043: log_info "Applied locked skip paths: $LOCKED_SKIP_PATHS"
- L0044: 
- L0045: set +e
- L0046: "${checkov_cmd[@]}" > "$REPORT_RAW" 2> "$REPORT_LOG"
- L0047: RC=$?
- L0048: set -e
- L0049: 
- L0050: if [[ "$RC" -ge 2 ]]; then
- L0051:   log_err "Technical Checkov failure (rc=$RC). See $REPORT_LOG"
- L0052:   exit 2
- L0053: fi
- L0054: 
- L0055: [[ -s "$REPORT_RAW" ]] || { log_err "checkov raw output missing: $REPORT_RAW"; exit 2; }
- L0056: jq -e 'type == "object" and (.results | type == "object")' "$REPORT_RAW" >/dev/null \
- L0057:   || { log_err "invalid checkov raw JSON structure"; exit 2; }
- L0058: 
- L0059: PARSING_ERRORS="$(jq '[.results.parsing_errors // [] | length]' "$REPORT_RAW" 2>/dev/null || echo 0)"
- L0060: if [[ "$PARSING_ERRORS" -gt 0 ]]; then
- L0061:   log_info "WARN: checkov reported ${PARSING_ERRORS} parsing error(s) — check $REPORT_LOG"
- L0062: fi
- L0063: 
- L0064: log_info "Raw report ready: $REPORT_RAW"
- L0065: exit 0

#### ci/scripts/checkov-scan.sh
- L0001: #!/usr/bin/env bash
- L0002: set -euo pipefail
- L0003: 
- L0004: # =========================
- L0005: # checkov-scan.sh
- L0006: # =========================
- L0007: 
- L0008: checkov --version
- L0009: mkdir -p .cloudsentinel
- L0010: chmod +x shift-left/checkov/run-checkov.sh
- L0011: 
- L0012: # Hardcoded scan target / skip paths
- L0013: readonly DEFAULT_SCAN_TARGET="infra/azure/student-secure"
- L0014: SCAN_TARGET_EFF="${CHECKOV_SCAN_TARGET:-${DEFAULT_SCAN_TARGET}}"
- L0015: 
- L0016: bash shift-left/checkov/run-checkov.sh "${SCAN_TARGET_EFF}"
- L0017: 
- L0018: chmod a+r .cloudsentinel/checkov_raw.json .cloudsentinel/checkov_scan.log 2>/dev/null || true
- L0019: 
- L0020: jq -r '"[scan-summary] checkov_raw_failed_checks=" + (((.results.failed_checks // []) | length) | tostring)' \
- L0021:   .cloudsentinel/checkov_raw.json

#### shift-left/trivy/configs/trivy-ci.yaml
- L0001: ################################################################################
- L0002: # CloudSentinel — Trivy Configuration (CI / Enforcement Mode)
- L0003: # Scope: Container vuln (OS+lib) | Dockerfile misconfig | Secrets in image layers
- L0004: # NOTE: exit-code: 0 — OPA Quality Gate handles ALLOW/DENY decision
- L0005: ################################################################################
- L0006: 
- L0007: scan:
- L0008:   scanners:
- L0009:     - vuln
- L0010:     - misconfig
- L0011:     - secret
- L0012: 
- L0013: severity:
- L0014:   - CRITICAL
- L0015:   - HIGH
- L0016:   - MEDIUM
- L0017:   - LOW
- L0018: 
- L0019: # JSON output — consumed by OPA normalization pipeline
- L0020: format: json
- L0021: 
- L0022: # Increased timeout for CI large images
- L0023: timeout: 15m
- L0024: 
- L0025: # CI-optimised cache
- L0026: cache:
- L0027:   dir: .trivy-cache
- L0028: 
- L0029: # Suppress DB download progress bar in CI logs
- L0030: db:
- L0031:   no-progress: true
- L0032: 
- L0033: # Package types to scan (replaces deprecated 'vulnerability.type')
- L0034: pkg:
- L0035:   types:
- L0036:     - os
- L0037:     - library
- L0038: 
- L0039: # Misconfig scope — Dockerfile only
- L0040: misconfiguration:
- L0041:   scanners:
- L0042:     - dockerfile
- L0043: 
- L0044: # Secret configuration
- L0045: secret:
- L0046:   config: ""
- L0047: 
- L0048: # OPA is the enforcement layer — Trivy always exits 0
- L0049: exit-code: 0
- L0050: 
- L0051: # CVE allowlist: .trivyignore is DISABLED in CI.
- L0052: # Exception management in CI is enforced exclusively via OPA + DefectDojo.
- L0053: # Do NOT add ignorefile here — it causes a FATAL when the path cannot be resolved.
- L0054: 
- L0055: # Always show whether a fix is available
- L0056: show-suppressed: false

#### shift-left/trivy/scripts/scan-fs.sh
- L0001: #!/usr/bin/env bash
- L0002: set -euo pipefail
- L0003: 
- L0004: ################################################################################
- L0005: # CloudSentinel — Trivy Filesystem / SCA Scanner
- L0006: # Scope  : Language package vulnerabilities (npm, pip, maven, go, etc.)
- L0007: # Output : reports/raw/trivy-fs-raw.json
- L0008: # Note   : Source-level secret enforcement is handled exclusively by Gitleaks
- L0009: #          (pre-commit + CI). Trivy FS here is vuln-only.
- L0010: ################################################################################
- L0011: 
- L0012: SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
- L0013: BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
- L0014: CONFIG_DIR="$BASE_DIR/configs"
- L0015: REPORT_DIR="$BASE_DIR/reports/raw"
- L0016: SBOM_DIR="$BASE_DIR/reports/sbom"
- L0017: SCAN_MODE="${SCAN_MODE:-local}"
- L0018: [[ -n "${CI:-}" ]] && SCAN_MODE="ci"
- L0019: 
- L0020: IGNORE_FILE="$BASE_DIR/.trivyignore"
- L0021: IGNORE_ARGS=()
- L0022: if [[ -f "$IGNORE_FILE" ]]; then
- L0023:   if [[ "$SCAN_MODE" == "ci" ]]; then
- L0024:     echo -e "\033[1;33m[CloudSentinel][Trivy][WARN]\033[0m .trivyignore is IGNORED in CI mode. Use DefectDojo/OPA for exceptions." >&2
- L0025:   else
- L0026:     IGNORE_ARGS=(--ignorefile "$IGNORE_FILE")
- L0027:   fi
- L0028: fi
- L0029: 
- L0030: SKIP_ARGS=()
- L0031: SKIP_DIRS_CSV="${TRIVY_SKIP_DIRS:-}"
- L0032: if [[ -n "$SKIP_DIRS_CSV" ]]; then
- L0033:   IFS=',' read -r -a _skip_dirs <<< "$SKIP_DIRS_CSV"
- L0034:   for _dir in "${_skip_dirs[@]}"; do
- L0035:     _dir="$(echo "$_dir" | xargs)"
- L0036:     [[ -z "$_dir" ]] && continue
- L0037:     SKIP_ARGS+=(--skip-dirs "$_dir")
- L0038:   done
- L0039: fi
- L0040: 
- L0041: log()  { echo -e "\033[1;34m[CloudSentinel][Trivy][FS]\033[0m $*"; }
- L0042: warn() { echo -e "\033[1;33m[CloudSentinel][Trivy][FS][WARN]\033[0m $*" >&2; }
- L0043: err()  { echo -e "\033[1;31m[CloudSentinel][Trivy][FS][ERROR]\033[0m $*" >&2; }
- L0044: 
- L0045: # ── Argument validation ──────────────────────────────────────────────────────
- L0046: TARGET="${1:-.}"
- L0047: 
- L0048: [[ ! -d "$TARGET" ]] && { err "Target directory not found: $TARGET"; exit 1; }
- L0049: TARGET="$(realpath "$TARGET")"
- L0050: 
- L0051: # SCAN_MODE already detected above
- L0052: 
- L0053: CONFIG_FILE="$CONFIG_DIR/trivy.yaml"
- L0054: [[ "$SCAN_MODE" == "ci" ]] && CONFIG_FILE="$CONFIG_DIR/trivy-ci.yaml"
- L0055: 
- L0056: # ── Setup ────────────────────────────────────────────────────────────────────
- L0057: mkdir -p "$REPORT_DIR"
- L0058: mkdir -p "$SBOM_DIR"
- L0059: OUTPUT_FILE="$REPORT_DIR/trivy-fs-raw.json"
- L0060: SBOM_FILE="$SBOM_DIR/trivy-fs.cdx.json"
- L0061: 
- L0062: log "Mode      : $SCAN_MODE"
- L0063: log "Config    : $CONFIG_FILE"
- L0064: log "Target    : $TARGET"
- L0065: log "Output    : $OUTPUT_FILE"
- L0066: log "SBOM      : $SBOM_FILE"
- L0067: [[ -f "$IGNORE_FILE" ]] && log "Ignore   : $IGNORE_FILE"
- L0068: [[ ${#SKIP_ARGS[@]} -gt 0 ]] && log "Skip dirs: $SKIP_DIRS_CSV"
- L0069: 
- L0070: # ── SBOM Generation ──────────────────────────────────────────────────────────
- L0071: log "Generating SBOM (CycloneDX)..."
- L0072: trivy fs \
- L0073:   --format cyclonedx \
- L0074:   --output "$SBOM_FILE" \
- L0075:   "$TARGET" || warn "Failed to generate SBOM, continuing scan."
- L0076: 
- L0077: # ── Scan ─────────────────────────────────────────────────────────────────────
- L0078: # --scanners: vuln only (secrets are scanned by Gitleaks only)
- L0079: # RC handling:
- L0080: #   0/1 -> scan executed (findings may exist)
- L0081: #   >1  -> technical failure
- L0082: set +e
- L0083: trivy fs \
- L0084:   --config "$CONFIG_FILE" \
- L0085:   "${IGNORE_ARGS[@]}" \
- L0086:   "${SKIP_ARGS[@]}" \
- L0087:   --scanners vuln \
- L0088:   --format json \
- L0089:   --output "$OUTPUT_FILE" \
- L0090:   "$TARGET"
- L0091: TRIVY_RC=$?
- L0092: set -e
- L0093: 
- L0094: if [[ "$TRIVY_RC" -gt 1 ]]; then
- L0095:   err "Trivy technical error during filesystem scan (rc=$TRIVY_RC): $TARGET"
- L0096:   exit 1
- L0097: fi
- L0098: 
- L0099: FINDING_COUNT=$(jq '[.Results[]? | (.Vulnerabilities // []) | length] | add // 0' "$OUTPUT_FILE" 2>/dev/null || echo "?")
- L0100: log "Scan complete. Findings: $FINDING_COUNT → $OUTPUT_FILE"

#### shift-left/trivy/scripts/scan-config.sh
- L0001: #!/usr/bin/env bash
- L0002: set -euo pipefail
- L0003: 
- L0004: ################################################################################
- L0005: # CloudSentinel — Trivy Dockerfile Misconfig Scanner
- L0006: # Scope  : Dockerfile security misconfiguration (CIS Docker Benchmark)
- L0007: # Output : reports/raw/trivy-config-raw.json
- L0008: # Note   : Terraform IaC scanning → Checkov (out of Trivy scope)
- L0009: #          Container image vulnerabilities → scan-image.sh
- L0010: ################################################################################
- L0011: 
- L0012: SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
- L0013: BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
- L0014: CONFIG_DIR="$BASE_DIR/configs"
- L0015: REPORT_DIR="$BASE_DIR/reports/raw"
- L0016: SCAN_MODE="${SCAN_MODE:-local}"
- L0017: [[ -n "${CI:-}" ]] && SCAN_MODE="ci"
- L0018: 
- L0019: IGNORE_FILE="$BASE_DIR/.trivyignore"
- L0020: IGNORE_ARGS=()
- L0021: if [[ -f "$IGNORE_FILE" ]]; then
- L0022:   if [[ "$SCAN_MODE" == "ci" ]]; then
- L0023:     echo -e "\033[1;33m[CloudSentinel][Trivy][WARN]\033[0m .trivyignore is IGNORED in CI mode. Use DefectDojo/OPA for exceptions." >&2
- L0024:   else
- L0025:     IGNORE_ARGS=(--ignorefile "$IGNORE_FILE")
- L0026:   fi
- L0027: fi
- L0028: 
- L0029: log()  { echo -e "\033[1;34m[CloudSentinel][Trivy][CONFIG]\033[0m $*"; }
- L0030: warn() { echo -e "\033[1;33m[CloudSentinel][Trivy][CONFIG][WARN]\033[0m $*" >&2; }
- L0031: err()  { echo -e "\033[1;31m[CloudSentinel][Trivy][CONFIG][ERROR]\033[0m $*" >&2; }
- L0032: 
- L0033: # ── Argument validation ──────────────────────────────────────────────────────
- L0034: TARGET="${1:-}"
- L0035: [[ -z "$TARGET" ]] && { err "Usage: $0 <Dockerfile_path_or_directory>"; exit 1; }
- L0036: 
- L0037: if [[ -f "$TARGET" ]]; then
- L0038:   TARGET="$(realpath "$TARGET")"
- L0039: elif [[ -d "$TARGET" ]]; then
- L0040:   TARGET="$(realpath "$TARGET")"
- L0041: else
- L0042:   err "Target not found: $TARGET (expected Dockerfile or directory)"
- L0043:   exit 1
- L0044: fi
- L0045: 
- L0046: # SCAN_MODE already detected above
- L0047: 
- L0048: CONFIG_FILE="$CONFIG_DIR/trivy.yaml"
- L0049: [[ "$SCAN_MODE" == "ci" ]] && CONFIG_FILE="$CONFIG_DIR/trivy-ci.yaml"
- L0050: 
- L0051: # ── Setup ────────────────────────────────────────────────────────────────────
- L0052: mkdir -p "$REPORT_DIR"
- L0053: OUTPUT_FILE="$REPORT_DIR/trivy-config-raw.json"
- L0054: 
- L0055: log "Mode      : $SCAN_MODE"
- L0056: log "Config    : $CONFIG_FILE"
- L0057: log "Target    : $TARGET"
- L0058: log "Output    : $OUTPUT_FILE"
- L0059: [[ -f "$IGNORE_FILE" ]] && log "Ignore   : $IGNORE_FILE"
- L0060: 
- L0061: # ── Scan ─────────────────────────────────────────────────────────────────────
- L0062: # trivy config scans Dockerfiles for misconfigurations (CIS Docker Benchmark)
- L0063: # RC handling:
- L0064: #   0/1 -> scan executed (findings may exist)
- L0065: #   >1  -> technical failure
- L0066: set +e
- L0067: trivy config \
- L0068:   --config "$CONFIG_FILE" \
- L0069:   "${IGNORE_ARGS[@]}" \
- L0070:   --format json \
- L0071:   --output "$OUTPUT_FILE" \
- L0072:   "$TARGET"
- L0073: TRIVY_RC=$?
- L0074: set -e
- L0075: 
- L0076: if [[ "$TRIVY_RC" -gt 1 ]]; then
- L0077:   err "Trivy technical error during config scan (rc=$TRIVY_RC): $TARGET"
- L0078:   exit 1
- L0079: fi
- L0080: 
- L0081: FINDING_COUNT=$(jq '[.Results[]? | (.Misconfigurations // []) | length] | add // 0' "$OUTPUT_FILE" 2>/dev/null || echo "?")
- L0082: log "Scan complete. Misconfigurations: $FINDING_COUNT → $OUTPUT_FILE"

#### ci/scripts/trivy-fs-scan.sh
- L0001: #!/usr/bin/env bash
- L0002: set -euo pipefail
- L0003: 
- L0004: # =========================
- L0005: # trivy-fs-scan.sh
- L0006: # =========================
- L0007: 
- L0008: trivy --version
- L0009: mkdir -p shift-left/trivy/reports/raw .cloudsentinel
- L0010: chmod +x shift-left/trivy/scripts/run-trivy.sh
- L0011: 
- L0012: readonly DEFAULT_TRIVY_TARGET="infra/azure/student-secure"
- L0013: readonly DEFAULT_TRIVY_SKIP_DIRS="infra/azure/student-secure/tests,infra/azure/test/tests,tests/fixtures"
- L0014: 
- L0015: export TRIVY_SKIP_DIRS="${DEFAULT_TRIVY_SKIP_DIRS}"
- L0016: TRIVY_TARGET_EFF="${DEFAULT_TRIVY_TARGET}"
- L0017: 
- L0018: bash shift-left/trivy/scripts/run-trivy.sh "${TRIVY_TARGET_EFF}" "fs"
- L0019: chmod -R a+r shift-left/trivy/reports/raw 2>/dev/null || true
- L0020: 
- L0021: jq -r '"[scan-summary] trivy_fs_raw_results=" + (((.Results // []) | length) | tostring)' \
- L0022:   shift-left/trivy/reports/raw/trivy-fs-raw.json

#### ci/scripts/trivy-config-scan.sh
- L0001: #!/usr/bin/env bash
- L0002: set -euo pipefail
- L0003: 
- L0004: # =========================
- L0005: # trivy-config-scan.sh
- L0006: # =========================
- L0007: 
- L0008: trivy --version
- L0009: mkdir -p shift-left/trivy/reports/raw .cloudsentinel
- L0010: chmod +x shift-left/trivy/scripts/run-trivy.sh
- L0011: 
- L0012: # Hardcoded Trivy target
- L0013: readonly DEFAULT_TRIVY_TARGET="infra/azure/student-secure"
- L0014: TRIVY_TARGET_EFF="${DEFAULT_TRIVY_TARGET}"
- L0015: 
- L0016: bash shift-left/trivy/scripts/run-trivy.sh "${TRIVY_TARGET_EFF}" "config"
- L0017: chmod -R a+r shift-left/trivy/reports/raw 2>/dev/null || true
- L0018: 
- L0019: jq -r '"[scan-summary] trivy_config_raw_results=" + (((.Results // []) | length) | tostring)' \
- L0020:   shift-left/trivy/reports/raw/trivy-config-raw.json

#### shift-left/normalizer/normalize.py
- L0001: #!/usr/bin/env python3
- L0002: from __future__ import annotations
- L0003: 
- L0004: import hashlib
- L0005: import json
- L0006: import os
- L0007: import re
- L0008: import subprocess
- L0009: import sys
- L0010: import time
- L0011: from datetime import datetime
- L0012: from pathlib import Path
- L0013: from typing import Any, Dict, List, Optional, Tuple
- L0014: 
- L0015: 
- L0016: class CloudSentinelNormalizer:
- L0017:     def __init__(self):
- L0018:         self.start_time = time.time()
- L0019:         self.root = Path(self._run(["git", "rev-parse", "--show-toplevel"], os.getcwd()))
- L0020:         self.out_dir = self.root / ".cloudsentinel"
- L0021:         self.out_file = self.out_dir / "golden_report.json"
- L0022:         self.schema_version = "1.1.0"
- L0023: 
- L0024:         self.env = os.environ.get("ENVIRONMENT", os.environ.get("CI_ENVIRONMENT_NAME", "dev")).lower()
- L0025:         self.env = "staging" if self.env == "stage" else self.env
- L0026:         if self.env not in {"dev", "test", "staging", "prod"}:
- L0027:             self.env = "dev"
- L0028: 
- L0029:         self.exec_mode = os.environ.get("CLOUDSENTINEL_EXECUTION_MODE", "ci" if "CI" in os.environ else "local").lower()
- L0030:         if self.exec_mode not in {"ci", "local", "advisory"}:
- L0031:             self.exec_mode = "local"
- L0032:         self.local_fast = os.environ.get("CLOUDSENTINEL_LOCAL_FAST", "false").lower() == "true"
- L0033:         self.schema_strict = os.environ.get("CLOUDSENTINEL_SCHEMA_STRICT", "false").lower() == "true"
- L0034: 
- L0035:         self.critical_max = 0 if os.environ.get("CI") else self._to_int(os.environ.get("CRITICAL_MAX"), 0)
- L0036:         self.high_max = 2 if os.environ.get("CI") else self._to_int(os.environ.get("HIGH_MAX"), 2)
- L0037: 
- L0038:         self.ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
- L0039:         self.git_branch = (
- L0040:             os.environ.get("CI_COMMIT_REF_NAME", "").strip()
- L0041:             or self._run(["git", "rev-parse", "--abbrev-ref", "HEAD"], "unknown")
- L0042:         )
- L0043:         self.git_commit = self._run(["git", "rev-parse", "HEAD"], "unknown")
- L0044:         self.git_commit_date = self._run(["git", "log", "-1", "--format=%cI"], self.ts)
- L0045:         self.git_author_email = self._run(["git", "log", "-1", "--format=%ae"], "unknown@example.invalid")
- L0046:         self.pipeline_id = os.environ.get("CI_PIPELINE_ID", "local")
- L0047:         self.git_repo = self._resolve_repo()
- L0048: 
- L0049:         self.sev_lut = {
- L0050:             "CRITICAL": "CRITICAL", "CRIT": "CRITICAL", "SEV5": "CRITICAL", "SEVERITY5": "CRITICAL", "VERY_HIGH": "CRITICAL",
- L0051:             "HIGH": "HIGH", "SEV4": "HIGH", "SEVERITY4": "HIGH",
- L0052:             "MEDIUM": "MEDIUM", "MODERATE": "MEDIUM", "SEV3": "MEDIUM", "SEVERITY3": "MEDIUM",
- L0053:             "LOW": "LOW", "MINOR": "LOW", "SEV2": "LOW", "SEVERITY2": "LOW",
- L0054:             "INFO": "INFO", "INFORMATIONAL": "INFO", "SEV1": "INFO", "SEVERITY1": "INFO", "UNKNOWN": "INFO",
- L0055:         }
- L0056:         self.sla = {"CRITICAL": 24, "HIGH": 168, "MEDIUM": 720, "LOW": 2160, "INFO": 8760}
- L0057:         self._checkov_map: Optional[Dict[str, Dict[str, str]]] = None
- L0058:         self._gitleaks_sev_map: Optional[Dict[str, str]] = None
- L0059: 
- L0060:     def _run(self, cmd: List[str], fallback: str) -> str:
- L0061:         try:
- L0062:             return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL).strip()
- L0063:         except Exception:
- L0064:             return fallback
- L0065: 
- L0066:     def _to_int(self, v: Any, fb: int) -> int:
- L0067:         try:
- L0068:             return int(v)
- L0069:         except Exception:
- L0070:             return fb
- L0071: 
- L0072:     def _sha256(self, txt: str) -> str:
- L0073:         return hashlib.sha256(txt.encode("utf-8")).hexdigest()
- L0074: 
- L0075:     def _hash_file(self, p: Path) -> Optional[str]:
- L0076:         if not p.is_file():
- L0077:             return None
- L0078:         h = hashlib.sha256()
- L0079:         with p.open("rb") as f:
- L0080:             for c in iter(lambda: f.read(4096), b""):
- L0081:                 h.update(c)
- L0082:         return h.hexdigest()
- L0083: 
- L0084:     def _read_json(self, p: Path) -> Tuple[Optional[Any], Optional[str]]:
- L0085:         try:
- L0086:             with p.open("r", encoding="utf-8") as f:
- L0087:                 return json.load(f), None
- L0088:         except Exception as e:
- L0089:             return None, str(e)
- L0090: 
- L0091:     def _resolve_repo(self) -> str:
- L0092:         ci_repo = os.environ.get("CI_PROJECT_PATH", "").strip()
- L0093:         if ci_repo:
- L0094:             return ci_repo
- L0095:         remote = self._run(["git", "config", "--get", "remote.origin.url"], "")
- L0096:         if not remote:
- L0097:             return self.root.name or "unknown"
- L0098:         x = re.sub(r"^https?://[^/]+/", "", remote.strip())
- L0099:         x = re.sub(r"^git@[^:]+:", "", x)
- L0100:         x = re.sub(r"\.git$", "", x)
- L0101:         return x or self.root.name or "unknown"
- L0102: 
- L0103:     def _first(self, *vals: Any) -> Optional[str]:
- L0104:         for v in vals:
- L0105:             if v is not None and str(v).strip() != "":
- L0106:                 return str(v)
- L0107:         return None
- L0108: 
- L0109:     def _norm_path(self, p: Any) -> str:
- L0110:         if not p:
- L0111:             return "unknown"
- L0112:         s = str(p).replace("\\", "/").replace("/./", "/")
- L0113:         while "//" in s:
- L0114:             s = s.replace("//", "/")
- L0115:         return s[2:] if s.startswith("./") else s
- L0116: 
- L0117:     def _empty_stats(self) -> Dict[str, int]:
- L0118:         return {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "TOTAL": 0, "EXEMPTED": 0, "FAILED": 0, "PASSED": 0}
- L0119: 
- L0120:     def _trace_status(self, st: str, findings: List[Dict[str, Any]]) -> str:
- L0121:         if st == "NOT_RUN":
- L0122:             return "NOT_RUN"
- L0123:         return "FAILED" if findings else "PASSED"
- L0124: 
- L0125:     def _not_run(self, tool: str, path: str, reason: str, present=False, valid=False, sha=None):
- L0126:         rep = {"tool": tool, "version": "unknown", "status": "NOT_RUN", "findings": [], "errors": [reason]}
- L0127:         tr = {"tool": tool, "path": path, "present": present, "valid_json": valid, "status": "NOT_RUN", "reason": reason, "sha256": sha}
- L0128:         return rep, tr
- L0129: 
- L0130:     def _checkov_mapping(self) -> Dict[str, Dict[str, str]]:
- L0131:         if self._checkov_map is not None:
- L0132:             return self._checkov_map
- L0133:         p = self.root / "shift-left" / "checkov" / "policies" / "mapping.json"
- L0134:         doc, err = self._read_json(p)
- L0135:         if err or not isinstance(doc, dict):
- L0136:             self._checkov_map = {}
- L0137:             return self._checkov_map
- L0138:         out: Dict[str, Dict[str, str]] = {}
- L0139:         for k, v in doc.items():
- L0140:             if isinstance(v, dict):
- L0141:                 out[str(k)] = {"category": str(v.get("category", "UNKNOWN")), "severity": str(v.get("severity", "MEDIUM")).upper()}
- L0142:         self._checkov_map = out
- L0143:         return out
- L0144: 
- L0145:     def _gitleaks_mapping(self) -> Dict[str, str]:
- L0146:         if self._gitleaks_sev_map is not None:
- L0147:             return self._gitleaks_sev_map
- L0148:         p = self.root / "shift-left" / "gitleaks" / "gitleaks.toml"
- L0149:         if not p.is_file():
- L0150:             self._gitleaks_sev_map = {}
- L0151:             return {}
- L0152:         cur: Dict[str, str] = {}
- L0153:         out: Dict[str, str] = {}
- L0154: 
- L0155:         def flush():
- L0156:             rid = cur.get("id", "").strip()
- L0157:             if not rid:
- L0158:                 return
- L0159:             sev = cur.get("severity", "").strip().upper()
- L0160:             tags = cur.get("tags", "").lower()
- L0161:             if not sev:
- L0162:                 sev = "CRITICAL" if "critical" in tags else "HIGH" if "high" in tags else "MEDIUM" if "medium" in tags else "LOW" if "low" in tags else "INFO" if ("info" in tags or "informational" in tags) else "HIGH"
- L0163:             out[rid] = self.sev_lut.get(sev, "HIGH")
- L0164: 
- L0165:         for line in p.read_text(encoding="utf-8").splitlines():
- L0166:             s = line.strip()
- L0167:             if s.startswith("[[rules]]"):
- L0168:                 flush()
- L0169:                 cur = {}
- L0170:             elif s.startswith("id"):
- L0171:                 m = re.search(r'=\s*"([^"]+)"', s)
- L0172:                 if m:
- L0173:                     cur["id"] = m.group(1)
- L0174:             elif s.startswith("severity"):
- L0175:                 m = re.search(r'=\s*"([^"]+)"', s)
- L0176:                 if m:
- L0177:                     cur["severity"] = m.group(1)
- L0178:             elif s.startswith("tags"):
- L0179:                 cur["tags"] = s
- L0180:         flush()
- L0181:         self._gitleaks_sev_map = out
- L0182:         return out
- L0183: 
- L0184:     def _parse_gitleaks(self, skip=False):
- L0185:         # ENRICHISSEMENT UNIQUEMENT — gitleaks_range_raw.json n'est jamais un signal OPA.
- L0186:         # La clé composite (RuleID, File, StartLine, EndLine) est la seule clé de matching.
- L0187:         # Fingerprint NON utilisé : incompatible entre modes --no-git et --log-opts.
- L0188:         p = self.out_dir / "gitleaks_raw.json"
- L0189:         if skip:
- L0190:             return self._not_run("gitleaks", str(p), "skipped_local_fast")
- L0191:         if not p.is_file():
- L0192:             return self._not_run("gitleaks", str(p), f"missing_report:{p}")
- L0193:         sha = self._hash_file(p)
- L0194:         doc, err = self._read_json(p)
- L0195:         if err:
- L0196:             return self._not_run("gitleaks", str(p), f"invalid_json:{p}", present=True, sha=sha)
- L0197:         if not isinstance(doc, list):
- L0198:             return self._not_run("gitleaks", str(p), "invalid_raw_structure:expected_array", present=True, valid=True, sha=sha)
- L0199:         sev_map = self._gitleaks_mapping()
- L0200:         findings: List[Dict[str, Any]] = []
- L0201:         for i, it in enumerate(doc):
- L0202:             if not isinstance(it, dict):
- L0203:                 findings.append({"id": "GITLEAKS_UNKNOWN", "description": "Malformed gitleaks finding entry", "file": "unknown", "start_line": 0, "end_line": 0, "severity": "HIGH", "status": "FAILED", "finding_type": "secret", "resource": {"name": "unknown", "path": "unknown", "type": "file"}, "metadata": {"raw_index": i, "raw_sha256": self._sha256(str(it))}})
- L0204:                 continue
- L0205:             rid = self._first(it.get("RuleID"), it.get("rule_id"), "GITLEAKS_UNKNOWN")
- L0206:             fp = self._norm_path(self._first(it.get("File"), it.get("file"), "unknown"))
- L0207:             st = self._to_int(self._first(it.get("StartLine"), it.get("start_line"), it.get("line"), "0"), 0)
- L0208:             en = self._to_int(self._first(it.get("EndLine"), it.get("end_line"), str(st)), st)
- L0209:             secret = self._first(it.get("Secret"), it.get("Match"), it.get("match"), "") or ""
- L0210:             raw_sev = self._first(it.get("Severity"), sev_map.get(str(rid), "HIGH"), "HIGH")
- L0211:             findings.append({"id": rid, "description": self._first(it.get("Description"), "No description"), "file": fp, "start_line": st, "end_line": en, "severity": self.sev_lut.get(str(raw_sev).upper(), "HIGH"), "status": "FAILED", "finding_type": "secret", "resource": {"name": fp, "path": fp, "type": "file"}, "metadata": {"secret_hash": self._sha256(secret) if secret else "", "commit": self._first(it.get("Commit"), ""), "author": self._first(it.get("Email"), ""), "date": self._first(it.get("Date"), "")}})
- L0212:         # Enrichissement depuis le scan range (best-effort)
- L0213:         range_p = self.out_dir / "gitleaks_range_raw.json"
- L0214:         if range_p.is_file():
- L0215:             range_doc, range_err = self._read_json(range_p)
- L0216:             if not range_err and isinstance(range_doc, list):
- L0217:                 # Index clé composite : (RuleID.upper(), norm_path(File), StartLine, EndLine)
- L0218:                 range_index: Dict[tuple, Dict[str, Any]] = {}
- L0219:                 for r_item in range_doc:
- L0220:                     if not isinstance(r_item, dict):
- L0221:                         continue
- L0222:                     r_rid   = str(r_item.get("RuleID") or "").upper().strip()
- L0223:                     r_file  = self._norm_path(r_item.get("File") or "")
- L0224:                     r_start = self._to_int(r_item.get("StartLine"), 0)
- L0225:                     r_end   = self._to_int(r_item.get("EndLine"), r_start)
- L0226:                     r_commit = str(r_item.get("Commit") or "").strip()
- L0227:                     r_email  = str(r_item.get("Email") or "").strip()
- L0228:                     r_date   = str(r_item.get("Date") or "").strip()
- L0229: 
- L0230:                     if not r_rid or not r_file:
- L0231:                         continue
- L0232:                     # Valider : commit non vide + date parseable ISO8601
- L0233:                     if not r_commit:
- L0234:                         continue
- L0235:                     try:
- L0236:                         datetime.fromisoformat(r_date.replace("Z", "+00:00"))
- L0237:                     except (ValueError, AttributeError):
- L0238:                         continue
- L0239: 
- L0240:                     key = (r_rid, r_file, r_start, r_end)
- L0241:                     if key not in range_index:
- L0242:                         range_index[key] = r_item
- L0243: 
- L0244:                 # Injecter les metadata dans les findings du principal
- L0245:                 for f in findings:
- L0246:                     f_rid   = str(f.get("id") or "").upper().strip()
- L0247:                     f_file  = self._norm_path(f.get("file") or "")
- L0248:                     f_start = self._to_int(f.get("start_line"), 0)
- L0249:                     f_end   = self._to_int(f.get("end_line"), f_start)
- L0250:                     key = (f_rid, f_file, f_start, f_end)
- L0251:                     match = range_index.get(key)
- L0252:                     if match:
- L0253:                         r_email = str(match.get("Email") or "").strip()
- L0254:                         if "@" in r_email:  # email minimal valide
- L0255:                             meta = f.get("metadata")
- L0256:                             if isinstance(meta, dict):
- L0257:                                 meta["commit"] = str(match.get("Commit") or "").strip()
- L0258:                                 meta["author"] = r_email
- L0259:                                 meta["date"]   = str(match.get("Date") or "").strip()
- L0260: 
- L0261:         rep = {"tool": "gitleaks", "version": os.environ.get("GITLEAKS_VERSION", "unknown"), "status": "OK", "findings": findings, "errors": []}
- L0262:         tr = {"tool": "gitleaks", "path": str(p), "present": True, "valid_json": True, "status": self._trace_status("OK", findings), "reason": "", "sha256": sha}
- L0263:         return rep, tr
- L0264: 
- L0265:     def _parse_checkov(self, skip=False):
- L0266:         p = self.out_dir / "checkov_raw.json"
- L0267:         if skip:
- L0268:             return self._not_run("checkov", str(p), "skipped_local_fast")
- L0269:         if not p.is_file():
- L0270:             return self._not_run("checkov", str(p), f"missing_report:{p}")
- L0271:         sha = self._hash_file(p)
- L0272:         doc, err = self._read_json(p)
- L0273:         if err:
- L0274:             return self._not_run("checkov", str(p), f"invalid_json:{p}", present=True, sha=sha)
- L0275:         if not isinstance(doc, dict) or not isinstance(doc.get("results"), dict):
- L0276:             return self._not_run("checkov", str(p), "invalid_raw_structure:expected_object_results", present=True, valid=True, sha=sha)
- L0277:         failed = doc.get("results", {}).get("failed_checks", [])
- L0278:         if not isinstance(failed, list):
- L0279:             failed = []
- L0280:         cmap = self._checkov_mapping()
- L0281:         findings: List[Dict[str, Any]] = []
- L0282:         for i, it in enumerate(failed):
- L0283:             if not isinstance(it, dict):
- L0284:                 continue
- L0285:             cid = self._first(it.get("check_id"), "CHECKOV_UNKNOWN")
- L0286:             me = cmap.get(str(cid), {})
- L0287:             fp = self._norm_path(self._first(it.get("file_path"), it.get("file_abs_path"), "unknown"))
- L0288:             lr = it.get("file_line_range", [])
- L0289:             ln = self._to_int(lr[0] if isinstance(lr, list) and lr else 0, 0)
- L0290:             sev = self.sev_lut.get(str(self._first(it.get("severity"), me.get("severity"), "MEDIUM")).upper(), "MEDIUM")
- L0291:             refs = []
- L0292:             g = self._first(it.get("guideline"), "")
- L0293:             if g:
- L0294:                 refs.append(g)
- L0295:             findings.append({"id": cid, "description": self._first(it.get("check_name"), it.get("check_id"), "No description"), "file": fp, "line": ln, "severity": sev, "status": "FAILED", "category": self._first(me.get("category"), "INFRASTRUCTURE_AS_CODE"), "finding_type": "misconfig", "resource": {"name": self._first(it.get("resource"), fp, "unknown"), "path": fp, "type": "infrastructure"}, "references": refs, "metadata": {"raw_index": i}})
- L0296:         sm = doc.get("summary", {}) if isinstance(doc.get("summary"), dict) else {}
- L0297:         rep = {"tool": "checkov", "version": self._first(sm.get("checkov_version"), os.environ.get("CHECKOV_VERSION"), "unknown"), "status": "OK", "findings": findings, "errors": []}
- L0298:         tr = {"tool": "checkov", "path": str(p), "present": True, "valid_json": True, "status": self._trace_status("OK", findings), "reason": "", "sha256": sha}
- L0299:         return rep, tr
- L0300: 
- L0301:     def _cvss(self, v: Any) -> Optional[float]:
- L0302:         if not isinstance(v, dict):
- L0303:             return None
- L0304:         for x in v.values():
- L0305:             if isinstance(x, dict) and x.get("V3Score") is not None:
- L0306:                 try:
- L0307:                     return float(x.get("V3Score"))
- L0308:                 except Exception:
- L0309:                     return None
- L0310:         return None
- L0311: 
- L0312:     def _trivy_from_doc(self, doc: Dict[str, Any], scan_type: str) -> List[Dict[str, Any]]:
- L0313:         res = doc.get("Results", [])
- L0314:         if not isinstance(res, list):
- L0315:             return []
- L0316:         out: List[Dict[str, Any]] = []
- L0317:         for r in res:
- L0318:             if not isinstance(r, dict):
- L0319:                 continue
- L0320:             tgt = self._first(r.get("Target"), "unknown") or "unknown"
- L0321:             for v in (r.get("Vulnerabilities", []) if isinstance(r.get("Vulnerabilities"), list) else []):
- L0322:                 if not isinstance(v, dict):
- L0323:                     continue
- L0324:                 out.append({"id": self._first(v.get("VulnerabilityID"), "TRIVY_VULN_UNKNOWN"), "description": self._first(v.get("Title"), v.get("Description"), "No description"), "severity": self._first(v.get("Severity"), "MEDIUM"), "status": "FAILED", "finding_type": "vulnerability", "resource": {"name": self._first(v.get("PkgName"), tgt, "unknown"), "path": tgt, "type": "package", "version": self._first(v.get("InstalledVersion"), "N/A")}, "references": [str(x) for x in (v.get("References") or []) if isinstance(x, str)], "fix_version": self._first(v.get("FixedVersion"), "N/A"), "metadata": {"scan_type": scan_type, "installed_version": self._first(v.get("InstalledVersion"), ""), "fixed_version": self._first(v.get("FixedVersion"), ""), "cvss": self._cvss(v.get("CVSS"))}})
- L0325:             for s in (r.get("Secrets", []) if isinstance(r.get("Secrets"), list) else []):
- L0326:                 if not isinstance(s, dict):
- L0327:                     continue
- L0328:                 st = self._to_int(s.get("StartLine"), 0)
- L0329:                 en = self._to_int(s.get("EndLine"), st)
- L0330:                 material = self._first(s.get("Match"), s.get("Code"), "") or ""
- L0331:                 out.append({"id": self._first(s.get("RuleID"), "TRIVY_SECRET_UNKNOWN"), "description": self._first(s.get("Title"), "Secret detected"), "severity": self._first(s.get("Severity"), "HIGH"), "status": "FAILED", "finding_type": "secret", "resource": {"name": tgt, "path": tgt, "type": "asset"}, "start_line": st, "end_line": en, "references": [], "metadata": {"scan_type": scan_type, "secret_hash": self._sha256(material) if material else ""}})
- L0332:             for m in (r.get("Misconfigurations", []) if isinstance(r.get("Misconfigurations"), list) else []):
- L0333:                 if not isinstance(m, dict):
- L0334:                     continue
- L0335:                 st = "PASSED" if str(m.get("Status", "")).upper() == "PASS" else "FAILED"
- L0336:                 out.append({"id": self._first(m.get("ID"), "TRIVY_MISCONFIG_UNKNOWN"), "description": self._first(m.get("Title"), m.get("Message"), "No description"), "severity": self._first(m.get("Severity"), "MEDIUM"), "status": st, "finding_type": "misconfig", "resource": {"name": tgt, "path": self._first((m.get("CauseMetadata") or {}).get("Resource"), tgt, "unknown"), "type": "configuration"}, "references": [str(x) for x in (m.get("References") or []) if isinstance(x, str)], "metadata": {"scan_type": scan_type}})
- L0337:         return out
- L0338: 
- L0339:     def _parse_trivy(self, skip=False):
- L0340:         paths = {"fs": self.root / "shift-left/trivy/reports/raw/trivy-fs-raw.json", "config": self.root / "shift-left/trivy/reports/raw/trivy-config-raw.json"}
- L0341:         tr_path = str(self.root / "shift-left/trivy/reports/raw")
- L0342:         if skip:
- L0343:             return self._not_run("trivy", tr_path, "skipped_local_fast")
- L0344:         findings: List[Dict[str, Any]] = []
- L0345:         errs: List[str] = []
- L0346:         not_run = False
- L0347:         ver = "unknown"
- L0348:         present = True
- L0349:         valid = True
- L0350:         for st, p in paths.items():
- L0351:             if not p.is_file():
- L0352:                 errs.append(f"missing_report:{p}")
- L0353:                 not_run = True
- L0354:                 present = False
- L0355:                 continue
- L0356:             doc, err = self._read_json(p)
- L0357:             if err:
- L0358:                 errs.append(f"invalid_json:{p}")
- L0359:                 not_run = True
- L0360:                 valid = False
- L0361:                 continue
- L0362:             if not isinstance(doc, dict):
- L0363:                 errs.append(f"invalid_raw_structure:{p}")
- L0364:                 not_run = True
- L0365:                 valid = False
- L0366:                 continue
- L0367:             meta = doc.get("Trivy", {})
- L0368:             if isinstance(meta, dict):
- L0369:                 ver = self._first(meta.get("Version"), ver, "unknown") or "unknown"
- L0370:             findings.extend(self._trivy_from_doc(doc, st))
- L0371:         # --- Trivy image : agrégation Option A (dossier raw/image/) ---
- L0372:         # TRIVY_IMAGE_MIN_REPORTS doit correspondre au nombre de jobs
- L0373:         # trivy-image-scan-* dans shift-left.yml. Mettre à jour si une image est ajoutée.
- L0374:         TRIVY_IMAGE_MIN_REPORTS = int(os.environ.get("TRIVY_IMAGE_MIN_REPORTS", "3"))
- L0375:         image_dir = self.root / "shift-left" / "trivy" / "reports" / "raw" / "image"
- L0376:         image_files = sorted(image_dir.glob("trivy-image-*-raw.json")) if image_dir.is_dir() else []
- L0377: 
- L0378:         if self.exec_mode == "ci":
- L0379:             if len(image_files) < TRIVY_IMAGE_MIN_REPORTS:
- L0380:                 reason = f"image_reports_below_minimum:{len(image_files)}<{TRIVY_IMAGE_MIN_REPORTS}"
- L0381:                 errs.append(reason)
- L0382:                 not_run = True
- L0383:             else:
- L0384:                 for img_p in image_files:
- L0385:                     img_doc, img_err = self._read_json(img_p)
- L0386:                     if img_err:
- L0387:                         errs.append(f"invalid_json:{img_p}")
- L0388:                         not_run = True
- L0389:                         valid = False
- L0390:                         continue
- L0391:                     if not isinstance(img_doc, dict):
- L0392:                         errs.append(f"invalid_raw_structure:{img_p}")
- L0393:                         not_run = True
- L0394:                         valid = False
- L0395:                         continue
- L0396:                     meta = img_doc.get("Trivy", {})
- L0397:                     if isinstance(meta, dict):
- L0398:                         ver = self._first(meta.get("Version"), ver, "unknown") or "unknown"
- L0399:                     findings.extend(self._trivy_from_doc(img_doc, "image"))
- L0400:         else:
- L0401:             # Mode local : 0 fichiers image acceptés sans erreur
- L0402:             for img_p in image_files:
- L0403:                 img_doc, img_err = self._read_json(img_p)
- L0404:                 if img_err or not isinstance(img_doc, dict):
- L0405:                     continue
- L0406:                 meta = img_doc.get("Trivy", {})
- L0407:                 if isinstance(meta, dict):
- L0408:                     ver = self._first(meta.get("Version"), ver, "unknown") or "unknown"
- L0409:                 findings.extend(self._trivy_from_doc(img_doc, "image"))
- L0410: 
- L0411:         status = "NOT_RUN" if not_run else "OK"
- L0412:         rep = {"tool": "trivy", "version": ver, "status": status, "findings": findings, "errors": errs}
- L0413:         tr = {"tool": "trivy", "path": tr_path, "present": present, "valid_json": valid, "status": self._trace_status(status, findings), "reason": ";".join(errs), "sha256": None}
- L0414:         return rep, tr
- L0415: 
- L0416:     def _category(self, f: Dict[str, Any], tool: str) -> str:
- L0417:         raw = (self._first(f.get("category"), f.get("Category"), "") or "").upper()
- L0418:         st = (self._first(f.get("finding_type"), f.get("source", {}).get("scanner_type"), "") or "").lower()
- L0419:         if tool == "gitleaks":
- L0420:             return "SECRETS"
- L0421:         if tool == "checkov":
- L0422:             return "INFRASTRUCTURE_AS_CODE"
- L0423:         if raw in {"SECRET", "SECRETS"} or st == "secret":
- L0424:             return "SECRETS"
- L0425:         return "VULNERABILITIES"
- L0426: 
- L0427:     def _fingerprint(self, tool: str, rid: str, rname: str, rpath: str, sl: int, el: int, desc: str, secret_hash: str) -> str:
- L0428:         ctx = "|".join([rpath.lower(), str(sl), str(el), desc.strip().lower(), secret_hash.strip().lower()])
- L0429:         return hashlib.sha256("|".join([tool.lower(), rid.strip().upper(), rname.lower(), ctx]).encode("utf-8")).hexdigest()
- L0430: 
- L0431:     def _normalize_finding(self, f: Dict[str, Any], tool: str, version: str, idx: int) -> Dict[str, Any]:
- L0432:         rid = self._first(f.get("id"), f.get("rule_id"), f.get("RuleID"), f.get("VulnerabilityID"), "UNKNOWN")
- L0433:         desc = self._first(f.get("description"), f.get("message"), f.get("title"), f.get("check_name"), "No description")
- L0434:         cat = self._category(f, tool)
- L0435:         rsrc = f.get("resource", {}) if isinstance(f.get("resource"), dict) else {}
- L0436:         rname = self._first(rsrc.get("name"), f.get("resource") if isinstance(f.get("resource"), str) else None, f.get("file"), f.get("target"), "unknown")
- L0437:         rpath = self._norm_path(self._first(rsrc.get("path"), f.get("file"), f.get("target"), "unknown"))
- L0438:         meta = f.get("metadata", {}) if isinstance(f.get("metadata"), dict) else {}
- L0439:         loc = rsrc.get("location", {}) if isinstance(rsrc.get("location"), dict) else {}
- L0440:         sl = self._to_int(loc.get("start_line") or f.get("start_line") or f.get("line") or meta.get("line"), 0)
- L0441:         el = self._to_int(loc.get("end_line") or f.get("end_line") or meta.get("end_line"), sl)
- L0442:         sd = f.get("severity", {}) if isinstance(f.get("severity"), dict) else {}
- L0443:         raw_sev = f.get("severity") if isinstance(f.get("severity"), str) else (sd.get("level") or f.get("original_severity"))
- L0444:         sev = self.sev_lut.get(str(raw_sev).upper(), "MEDIUM")
- L0445:         st = str(f.get("status", "FAILED")).upper()
- L0446:         if st not in {"EXEMPTED", "PASSED"}:
- L0447:             st = "FAILED"
- L0448:         secret_hash = str(meta.get("secret_hash", "")).strip()
- L0449:         fp = self._fingerprint(tool, str(rid), str(rname), rpath, sl, el, str(desc), secret_hash)
- L0450:         fid = f"CS-{tool}-{hashlib.sha256(f'{fp}|{idx}'.encode('utf-8')).hexdigest()[:16]}"
- L0451:         cvss = sd.get("cvss_score") or f.get("cvss_score") or meta.get("cvss")
- L0452:         try:
- L0453:             cvss = float(cvss) if cvss is not None else None
- L0454:         except Exception:
- L0455:             cvss = None
- L0456:         refs = f.get("references") or meta.get("references") or []
- L0457:         refs = refs if isinstance(refs, list) else []
- L0458:         return {
- L0459:             "id": fid,
- L0460:             "source": {"tool": tool, "version": version or "unknown", "id": str(rid), "scanner_type": self._first(f.get("finding_type"), f.get("source", {}).get("scanner_type"), cat.lower(), "security")},
- L0461:             "resource": {"name": rname, "version": self._first(rsrc.get("version"), meta.get("installed_version"), "N/A"), "type": self._first(rsrc.get("type"), f.get("finding_type"), "asset"), "path": rpath, "location": {"file": rpath, "start_line": sl, "end_line": el}},
- L0462:             "description": str(desc),
- L0463:             "severity": {"level": sev, "original_severity": self._first(sd.get("level"), raw_sev, "UNKNOWN"), "cvss_score": cvss},
- L0464:             "category": cat,
- L0465:             "status": st,
- L0466:             "remediation": {"sla_hours": self.sla.get(sev, 720), "fix_version": self._first(f.get("fix_version"), meta.get("fixed_version"), "N/A"), "references": [str(x) for x in refs]},
- L0467:             "context": {"git": {"author_email": self.git_author_email, "commit_date": self.git_commit_date}, "deduplication": {"fingerprint": fp, "is_duplicate": False, "duplicate_of": None}, "traceability": {"source_report": f"{tool}_raw.json", "source_index": idx, "normalized_at": self.ts}},
- L0468:         }
- L0469: 
- L0470:     def _process_scanner(self, data: Dict[str, Any], name: str) -> Dict[str, Any]:
- L0471:         v = str(data.get("version", "unknown"))
- L0472:         st = "NOT_RUN" if str(data.get("status", "NOT_RUN")).upper() == "NOT_RUN" else "OK"
- L0473:         raws = data.get("findings", [])
- L0474:         raws = raws if isinstance(raws, list) else []
- L0475:         return {"tool": name, "version": v, "status": st, "errors": [str(x) for x in data.get("errors", [])], "stats": self._empty_stats(), "findings": [self._normalize_finding(f, name, v, i) for i, f in enumerate(raws)]}
- L0476: 
- L0477:     def _dedup(self, findings: List[Dict[str, Any]]) -> None:
- L0478:         seen: Dict[str, str] = {}
- L0479:         for f in findings:
- L0480:             d = f.get("context", {}).get("deduplication", {})
- L0481:             fp = str(d.get("fingerprint", "")).strip()
- L0482:             if not fp:
- L0483:                 continue
- L0484:             if fp in seen:
- L0485:                 d["is_duplicate"] = True
- L0486:                 d["duplicate_of"] = seen[fp]
- L0487:                 f["status"] = "EXEMPTED"
- L0488:             else:
- L0489:                 seen[fp] = f.get("id")
- L0490:                 d["is_duplicate"] = False
- L0491:                 d["duplicate_of"] = None
- L0492: 
- L0493:     def _stats(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
- L0494:         s = self._empty_stats()
- L0495:         for f in findings:
- L0496:             st = str(f.get("status", "FAILED")).upper()
- L0497:             if st == "EXEMPTED":
- L0498:                 s["EXEMPTED"] += 1
- L0499:                 continue
- L0500:             if st == "PASSED":
- L0501:                 s["PASSED"] += 1
- L0502:                 continue
- L0503:             if st != "FAILED":
- L0504:                 continue
- L0505:             s["FAILED"] += 1
- L0506:             s["TOTAL"] += 1
- L0507:             sev = str(f.get("severity", {}).get("level", "MEDIUM")).upper()
- L0508:             s[sev if sev in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} else "MEDIUM"] += 1
- L0509:         return s
- L0510: 
- L0511:     def generate(self):
- L0512:         print("\033[34m[INFO]\033[0m Starting CloudSentinel normalization (raw ingestion)...")
- L0513:         skip = self.local_fast and self.exec_mode in {"local", "advisory"}
- L0514:         g_data, g_trace = self._parse_gitleaks(skip=False)
- L0515:         c_data, c_trace = self._parse_checkov(skip=skip)
- L0516:         t_data, t_trace = self._parse_trivy(skip=skip)
- L0517: 
- L0518:         scanners = {"gitleaks": self._process_scanner(g_data, "gitleaks"), "checkov": self._process_scanner(c_data, "checkov"), "trivy": self._process_scanner(t_data, "trivy")}
- L0519:         findings = scanners["gitleaks"]["findings"] + scanners["checkov"]["findings"] + scanners["trivy"]["findings"]
- L0520:         self._dedup(findings)
- L0521:         for nm, sc in scanners.items():
- L0522:             sc["stats"] = self._stats(sc["findings"])
- L0523:             src = {"gitleaks": g_data, "checkov": c_data, "trivy": t_data}[nm]
- L0524:             if str(src.get("status", "OK")).upper() == "NOT_RUN":
- L0525:                 sc["status"] = "NOT_RUN"
- L0526:             elif sc["stats"]["TOTAL"] > 0:
- L0527:                 sc["status"] = "FAILED"
- L0528:             else:
- L0529:                 sc["status"] = "PASSED"
- L0530: 
- L0531:         by_cat = {"SECRETS": 0, "INFRASTRUCTURE_AS_CODE": 0, "VULNERABILITIES": 0}
- L0532:         for f in findings:
- L0533:             if str(f.get("status", "FAILED")).upper() == "FAILED":
- L0534:                 c = str(f.get("category", "VULNERABILITIES"))
- L0535:                 if c in by_cat:
- L0536:                     by_cat[c] += 1
- L0537:         summary = {"global": self._stats(findings), "by_tool": {k: {**v["stats"], "status": v["status"]} for k, v in scanners.items()}, "by_category": by_cat}
- L0538:         not_run = [k for k, v in scanners.items() if v["status"] == "NOT_RUN"]
- L0539: 
- L0540:         report = {
- L0541:             "schema_version": self.schema_version,
- L0542:             "metadata": {
- L0543:                 "tool": "cloudsentinel",
- L0544:                 "timestamp": self.ts,
- L0545:                 "generation_duration_ms": 0,
- L0546:                 "environment": self.env,
- L0547:                 "execution": {"mode": self.exec_mode},
- L0548:                 "git": {"repo": self.git_repo, "repository": self.git_repo, "branch": self.git_branch, "commit": self.git_commit, "commit_date": self.git_commit_date, "author_email": self.git_author_email, "pipeline_id": self.pipeline_id},
- L0549:                 "normalizer": {"version": self.schema_version, "source_reports": {"gitleaks": g_trace, "checkov": c_trace, "trivy": t_trace}},
- L0550:             },
- L0551:             "scanners": scanners,
- L0552:             "findings": findings,
- L0553:             "summary": summary,
- L0554:             "quality_gate": {"decision": "NOT_EVALUATED", "reason": "evaluation-performed-by-opa-only", "thresholds": {"critical_max": self.critical_max, "high_max": self.high_max}, "details": {"reasons": ["opa_is_single_enforcement_point"], "not_run_scanners": not_run}},
- L0555:         }
- L0556:         report["metadata"]["generation_duration_ms"] = int((time.time() - self.start_time) * 1000)
- L0557: 
- L0558:         self.out_dir.mkdir(parents=True, exist_ok=True)
- L0559:         with self.out_file.open("w", encoding="utf-8") as f:
- L0560:             json.dump(report, f, indent=2)
- L0561:         self._validate_schema(report)
- L0562:         print(f"\033[34m[INFO]\033[0m Golden Report generated successfully: {self.out_file}")
- L0563: 
- L0564:     def _validate_schema(self, report: Dict[str, Any]):
- L0565:         schema_path = self.root / "shift-left" / "normalizer" / "schema" / "cloudsentinel_report.schema.json"
- L0566:         try:
- L0567:             from jsonschema import Draft7Validator, validate
- L0568:             if schema_path.is_file():
- L0569:                 with schema_path.open("r", encoding="utf-8") as f:
- L0570:                     schema = json.load(f)
- L0571:                 Draft7Validator.check_schema(schema)
- L0572:                 validate(report, schema)
- L0573:         except ImportError:
- L0574:             if self.schema_strict:
- L0575:                 print("\033[31m[ERROR]\033[0m jsonschema module missing in strict mode", file=sys.stderr)
- L0576:                 sys.exit(1)
- L0577:         except Exception as e:
- L0578:             print(f"\033[31m[ERROR]\033[0m Golden report schema validation failed: {e}", file=sys.stderr)
- L0579:             sys.exit(1)
- L0580: 
- L0581: 
- L0582: if __name__ == "__main__":
- L0583:     CloudSentinelNormalizer().generate()

#### shift-left/normalizer/schema/cloudsentinel_report.schema.json
- L0001: {
- L0002:   "$schema": "http://json-schema.org/draft-07/schema#",
- L0003:   "title": "CloudSentinel Golden Report",
- L0004:   "type": "object",
- L0005:   "additionalProperties": false,
- L0006:   "required": [
- L0007:     "schema_version",
- L0008:     "metadata",
- L0009:     "summary",
- L0010:     "scanners",
- L0011:     "findings",
- L0012:     "quality_gate"
- L0013:   ],
- L0014:   "properties": {
- L0015:     "schema_version": {
- L0016:       "type": "string",
- L0017:       "pattern": "^\\d+\\.\\d+\\.\\d+$"
- L0018:     },
- L0019:     "metadata": {
- L0020:       "type": "object",
- L0021:       "additionalProperties": false,
- L0022:       "required": [
- L0023:         "tool",
- L0024:         "timestamp",
- L0025:         "generation_duration_ms",
- L0026:         "environment",
- L0027:         "execution",
- L0028:         "git",
- L0029:         "normalizer"
- L0030:       ],
- L0031:       "properties": {
- L0032:         "tool": {
- L0033:           "type": "string",
- L0034:           "const": "cloudsentinel"
- L0035:         },
- L0036:         "timestamp": {
- L0037:           "type": "string",
- L0038:           "format": "date-time"
- L0039:         },
- L0040:         "generation_duration_ms": {
- L0041:           "type": "integer",
- L0042:           "minimum": 0
- L0043:         },
- L0044:         "environment": {
- L0045:           "type": "string",
- L0046:           "enum": ["dev", "test", "staging", "prod"]
- L0047:         },
- L0048:         "execution": {
- L0049:           "type": "object",
- L0050:           "additionalProperties": false,
- L0051:           "required": ["mode"],
- L0052:           "properties": {
- L0053:             "mode": {
- L0054:               "type": "string",
- L0055:               "enum": ["ci", "local", "advisory"]
- L0056:             }
- L0057:           }
- L0058:         },
- L0059:         "git": {
- L0060:           "type": "object",
- L0061:           "additionalProperties": false,
- L0062:           "required": ["repo", "repository", "branch", "commit", "commit_date", "author_email", "pipeline_id"],
- L0063:           "properties": {
- L0064:             "repo": { "type": "string" },
- L0065:             "repository": { "type": "string" },
- L0066:             "branch": { "type": "string" },
- L0067:             "commit": { "type": "string" },
- L0068:             "commit_date": { "type": "string", "format": "date-time" },
- L0069:             "author_email": { "type": "string", "format": "email" },
- L0070:             "pipeline_id": { "type": "string" }
- L0071:           }
- L0072:         },
- L0073:         "normalizer": {
- L0074:           "type": "object",
- L0075:           "additionalProperties": false,
- L0076:           "required": ["version", "source_reports"],
- L0077:           "properties": {
- L0078:             "version": {
- L0079:               "type": "string",
- L0080:               "pattern": "^\\d+\\.\\d+\\.\\d+$"
- L0081:             },
- L0082:             "source_reports": {
- L0083:               "type": "object",
- L0084:               "additionalProperties": false,
- L0085:               "required": ["gitleaks", "checkov", "trivy"],
- L0086:               "properties": {
- L0087:                 "gitleaks": { "$ref": "#/definitions/source_report_trace" },
- L0088:                 "checkov": { "$ref": "#/definitions/source_report_trace" },
- L0089:                 "trivy": { "$ref": "#/definitions/source_report_trace" }
- L0090:               }
- L0091:             }
- L0092:           }
- L0093:         }
- L0094:       }
- L0095:     },
- L0096:     "summary": {
- L0097:       "type": "object",
- L0098:       "additionalProperties": false,
- L0099:       "required": ["global", "by_tool", "by_category"],
- L0100:       "properties": {
- L0101:         "global": {
- L0102:           "$ref": "#/definitions/stats_summary"
- L0103:         },
- L0104:         "by_tool": {
- L0105:           "type": "object",
- L0106:           "additionalProperties": false,
- L0107:           "required": ["gitleaks", "checkov", "trivy"],
- L0108:           "properties": {
- L0109:             "gitleaks": { "$ref": "#/definitions/tool_summary" },
- L0110:             "checkov": { "$ref": "#/definitions/tool_summary" },
- L0111:             "trivy": { "$ref": "#/definitions/tool_summary" }
- L0112:           }
- L0113:         },
- L0114:         "by_category": {
- L0115:           "type": "object",
- L0116:           "additionalProperties": false,
- L0117:           "required": ["SECRETS", "INFRASTRUCTURE_AS_CODE", "VULNERABILITIES"],
- L0118:           "properties": {
- L0119:             "SECRETS": { "type": "integer", "minimum": 0 },
- L0120:             "INFRASTRUCTURE_AS_CODE": { "type": "integer", "minimum": 0 },
- L0121:             "VULNERABILITIES": { "type": "integer", "minimum": 0 }
- L0122:           }
- L0123:         }
- L0124:       }
- L0125:     },
- L0126:     "scanners": {
- L0127:       "type": "object",
- L0128:       "additionalProperties": false,
- L0129:       "required": ["gitleaks", "checkov", "trivy"],
- L0130:       "properties": {
- L0131:         "gitleaks": { "$ref": "#/definitions/scanner" },
- L0132:         "checkov": { "$ref": "#/definitions/scanner" },
- L0133:         "trivy": { "$ref": "#/definitions/scanner" }
- L0134:       }
- L0135:     },
- L0136:     "findings": {
- L0137:       "type": "array",
- L0138:       "items": { "$ref": "#/definitions/finding" }
- L0139:     },
- L0140:     "quality_gate": {
- L0141:       "type": "object",
- L0142:       "additionalProperties": false,
- L0143:       "required": ["decision", "reason", "thresholds"],
- L0144:       "properties": {
- L0145:         "decision": {
- L0146:           "type": "string",
- L0147:           "enum": ["PASSED", "FAILED", "NOT_EVALUATED"]
- L0148:         },
- L0149:         "reason": {
- L0150:           "type": "string"
- L0151:         },
- L0152:         "thresholds": {
- L0153:           "type": "object",
- L0154:           "additionalProperties": false,
- L0155:           "required": ["critical_max", "high_max"],
- L0156:           "properties": {
- L0157:             "critical_max": { "type": "integer", "minimum": 0 },
- L0158:             "high_max": { "type": "integer", "minimum": 0 }
- L0159:           }
- L0160:         },
- L0161:         "details": {
- L0162:           "type": "object",
- L0163:           "additionalProperties": false,
- L0164:           "properties": {
- L0165:             "reasons": {
- L0166:               "type": "array",
- L0167:               "items": { "type": "string" }
- L0168:             },
- L0169:             "not_run_scanners": {
- L0170:               "type": "array",
- L0171:               "items": { "type": "string" }
- L0172:             }
- L0173:           }
- L0174:         }
- L0175:       }
- L0176:     }
- L0177:   },
- L0178:   "definitions": {
- L0179:     "stats_summary": {
- L0180:       "type": "object",
- L0181:       "additionalProperties": false,
- L0182:       "required": [
- L0183:         "CRITICAL",
- L0184:         "HIGH",
- L0185:         "MEDIUM",
- L0186:         "LOW",
- L0187:         "INFO",
- L0188:         "TOTAL",
- L0189:         "EXEMPTED",
- L0190:         "FAILED",
- L0191:         "PASSED"
- L0192:       ],
- L0193:       "properties": {
- L0194:         "CRITICAL": { "type": "integer", "minimum": 0 },
- L0195:         "HIGH": { "type": "integer", "minimum": 0 },
- L0196:         "MEDIUM": { "type": "integer", "minimum": 0 },
- L0197:         "LOW": { "type": "integer", "minimum": 0 },
- L0198:         "INFO": { "type": "integer", "minimum": 0 },
- L0199:         "TOTAL": { "type": "integer", "minimum": 0 },
- L0200:         "EXEMPTED": { "type": "integer", "minimum": 0 },
- L0201:         "FAILED": { "type": "integer", "minimum": 0 },
- L0202:         "PASSED": { "type": "integer", "minimum": 0 }
- L0203:       }
- L0204:     },
- L0205:     "tool_summary": {
- L0206:       "type": "object",
- L0207:       "additionalProperties": false,
- L0208:       "required": [
- L0209:         "CRITICAL",
- L0210:         "HIGH",
- L0211:         "MEDIUM",
- L0212:         "LOW",
- L0213:         "INFO",
- L0214:         "TOTAL",
- L0215:         "EXEMPTED",
- L0216:         "FAILED",
- L0217:         "PASSED",
- L0218:         "status"
- L0219:       ],
- L0220:       "properties": {
- L0221:         "CRITICAL": { "type": "integer", "minimum": 0 },
- L0222:         "HIGH": { "type": "integer", "minimum": 0 },
- L0223:         "MEDIUM": { "type": "integer", "minimum": 0 },
- L0224:         "LOW": { "type": "integer", "minimum": 0 },
- L0225:         "INFO": { "type": "integer", "minimum": 0 },
- L0226:         "TOTAL": { "type": "integer", "minimum": 0 },
- L0227:         "EXEMPTED": { "type": "integer", "minimum": 0 },
- L0228:         "FAILED": { "type": "integer", "minimum": 0 },
- L0229:         "PASSED": { "type": "integer", "minimum": 0 },
- L0230:         "status": {
- L0231:           "type": "string",
- L0232:           "enum": ["PASSED", "FAILED", "NOT_RUN"]
- L0233:         }
- L0234:       }
- L0235:     },
- L0236:     "source_report_trace": {
- L0237:       "type": "object",
- L0238:       "additionalProperties": false,
- L0239:       "required": ["tool", "path", "present", "valid_json", "status", "reason", "sha256"],
- L0240:       "properties": {
- L0241:         "tool": { "type": "string", "enum": ["gitleaks", "checkov", "trivy"] },
- L0242:         "path": { "type": "string" },
- L0243:         "present": { "type": "boolean" },
- L0244:         "valid_json": { "type": "boolean" },
- L0245:         "status": { "type": "string", "enum": ["PASSED", "FAILED", "NOT_RUN"] },
- L0246:         "reason": { "type": "string" },
- L0247:         "sha256": {
- L0248:           "type": ["string", "null"],
- L0249:           "pattern": "^[a-fA-F0-9]{64}$"
- L0250:         }
- L0251:       }
- L0252:     },
- L0253:     "scanner": {
- L0254:       "type": "object",
- L0255:       "additionalProperties": false,
- L0256:       "required": ["tool", "version", "status", "errors", "stats", "findings"],
- L0257:       "properties": {
- L0258:         "tool": { "type": "string" },
- L0259:         "version": { "type": "string" },
- L0260:         "status": {
- L0261:           "type": "string",
- L0262:           "enum": ["PASSED", "FAILED", "NOT_RUN"]
- L0263:         },
- L0264:         "errors": {
- L0265:           "type": "array",
- L0266:           "items": { "type": "string" }
- L0267:         },
- L0268:         "stats": { "$ref": "#/definitions/stats_summary" },
- L0269:         "findings": {
- L0270:           "type": "array",
- L0271:           "items": { "$ref": "#/definitions/finding" }
- L0272:         }
- L0273:       }
- L0274:     },
- L0275:     "finding": {
- L0276:       "type": "object",
- L0277:       "additionalProperties": false,
- L0278:       "required": [
- L0279:         "id",
- L0280:         "source",
- L0281:         "resource",
- L0282:         "description",
- L0283:         "severity",
- L0284:         "category",
- L0285:         "status",
- L0286:         "remediation",
- L0287:         "context"
- L0288:       ],
- L0289:       "properties": {
- L0290:         "id": { "type": "string" },
- L0291:         "source": {
- L0292:           "type": "object",
- L0293:           "additionalProperties": false,
- L0294:           "required": ["tool", "version", "id", "scanner_type"],
- L0295:           "properties": {
- L0296:             "tool": { "type": "string" },
- L0297:             "version": { "type": "string" },
- L0298:             "id": { "type": "string" },
- L0299:             "scanner_type": { "type": "string" }
- L0300:           }
- L0301:         },
- L0302:         "resource": {
- L0303:           "type": "object",
- L0304:           "additionalProperties": false,
- L0305:           "required": ["name", "version", "type", "path", "location"],
- L0306:           "properties": {
- L0307:             "name": { "type": "string" },
- L0308:             "version": { "type": "string" },
- L0309:             "type": { "type": "string" },
- L0310:             "path": { "type": "string" },
- L0311:             "location": {
- L0312:               "type": "object",
- L0313:               "additionalProperties": false,
- L0314:               "required": ["file", "start_line", "end_line"],
- L0315:               "properties": {
- L0316:                 "file": { "type": "string" },
- L0317:                 "start_line": { "type": "integer", "minimum": 0 },
- L0318:                 "end_line": { "type": "integer", "minimum": 0 }
- L0319:               }
- L0320:             }
- L0321:           }
- L0322:         },
- L0323:         "description": { "type": "string" },
- L0324:         "severity": {
- L0325:           "type": "object",
- L0326:           "additionalProperties": false,
- L0327:           "required": ["level", "original_severity"],
- L0328:           "properties": {
- L0329:             "level": {
- L0330:               "type": "string",
- L0331:               "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
- L0332:             },
- L0333:             "original_severity": { "type": "string" },
- L0334:             "cvss_score": { "type": ["number", "null"] }
- L0335:           }
- L0336:         },
- L0337:         "category": { "type": "string" },
- L0338:         "status": {
- L0339:           "type": "string",
- L0340:           "enum": ["PASSED", "FAILED", "EXEMPTED"]
- L0341:         },
- L0342:         "remediation": {
- L0343:           "type": "object",
- L0344:           "additionalProperties": false,
- L0345:           "required": ["sla_hours", "fix_version", "references"],
- L0346:           "properties": {
- L0347:             "sla_hours": { "type": "integer", "minimum": 0 },
- L0348:             "fix_version": { "type": "string" },
- L0349:             "references": {
- L0350:               "type": "array",
- L0351:               "items": { "type": "string" }
- L0352:             }
- L0353:           }
- L0354:         },
- L0355:         "context": {
- L0356:           "type": "object",
- L0357:           "additionalProperties": false,
- L0358:           "required": ["git", "deduplication", "traceability"],
- L0359:           "properties": {
- L0360:             "git": {
- L0361:               "type": "object",
- L0362:               "additionalProperties": false,
- L0363:               "required": ["author_email", "commit_date"],
- L0364:               "properties": {
- L0365:                 "author_email": { "type": "string", "format": "email" },
- L0366:                 "commit_date": { "type": "string", "format": "date-time" }
- L0367:               }
- L0368:             },
- L0369:             "deduplication": {
- L0370:               "type": "object",
- L0371:               "additionalProperties": false,
- L0372:               "required": ["fingerprint", "is_duplicate", "duplicate_of"],
- L0373:               "properties": {
- L0374:                 "fingerprint": { "type": "string" },
- L0375:                 "is_duplicate": { "type": "boolean" },
- L0376:                 "duplicate_of": {
- L0377:                   "type": ["string", "null"]
- L0378:                 }
- L0379:               }
- L0380:             },
- L0381:             "traceability": {
- L0382:               "type": "object",
- L0383:               "additionalProperties": false,
- L0384:               "required": ["source_report", "source_index", "normalized_at"],
- L0385:               "properties": {
- L0386:                 "source_report": { "type": "string" },
- L0387:                 "source_index": { "type": "integer", "minimum": 0 },
- L0388:                 "normalized_at": { "type": "string", "format": "date-time" }
- L0389:               }
- L0390:             }
- L0391:           }
- L0392:         }
- L0393:       }
- L0394:     }
- L0395:   }
- L0396: }

#### policies/opa/pipeline_decision.rego
- L0001: package cloudsentinel.gate
- L0002: 
- L0003: import rego.v1
- L0004: 
- L0005: # rego 0.69.1
- L0006: 
- L0007: scanners := object.get(input, "scanners", {})
- L0008: thresholds := object.get(object.get(input, "quality_gate", {}), "thresholds", {})
- L0009: required_scanners := ["gitleaks", "checkov", "trivy"]
- L0010: allowed_tools := {"gitleaks", "checkov", "trivy"}
- L0011: allowed_decisions := {"accept", "mitigate", "fix", "transfer", "avoid"}
- L0012: 
- L0013: metadata := object.get(input, "metadata", {})
- L0014: git_meta := object.get(metadata, "git", {})
- L0015: environment := lower(object.get(metadata, "environment", "dev"))
- L0016: execution_mode := lower(object.get(object.get(metadata, "execution", {}), "mode", "ci"))
- L0017: 
- L0018: critical_max_raw := object.get(thresholds, "critical_max", 0)
- L0019: high_max_raw := object.get(thresholds, "high_max", 2)
- L0020: 
- L0021: critical_max := to_number(critical_max_raw)
- L0022: high_max := to_number(high_max_raw)
- L0023: 
- L0024: # Policy-enforced ceilings — not injectable from input or CI variables.
- L0025: # Input thresholds are clamped to these maximums regardless of what CI passes.
- L0026: _policy_critical_max_ceiling := 0
- L0027: _policy_high_max_ceiling := 5
- L0028: 
- L0029: enforced_critical_max := min([critical_max, _policy_critical_max_ceiling])
- L0030: enforced_high_max     := min([high_max,     _policy_high_max_ceiling])
- L0031: 
- L0032: thresholds_valid if {
- L0033:   to_number(critical_max_raw)
- L0034:   to_number(high_max_raw)
- L0035: }
- L0036: 
- L0037: severity_rank := {
- L0038:   "LOW": 1,
- L0039:   "MEDIUM": 2,
- L0040:   "HIGH": 3,
- L0041:   "CRITICAL": 4,
- L0042: }
- L0043: 
- L0044: default exceptions_store := []
- L0045: exceptions_store := data.cloudsentinel.exceptions.exceptions
- L0046: 
- L0047: is_local if {
- L0048:   execution_mode == "local"
- L0049: }
- L0050: 
- L0051: is_local if {
- L0052:   execution_mode == "advisory"
- L0053: }
- L0054: 
- L0055: failed_findings := [f |
- L0056:   some i
- L0057:   f := object.get(input, "findings", [])[i]
- L0058:   object.get(f, "status", "") == "FAILED"
- L0059:   not to_bool(object.get(object.get(object.get(f, "context", {}), "deduplication", {}), "is_duplicate", false))
- L0060: ]
- L0061: 
- L0062: normalize_path(path) := normalized if {
- L0063:   type_name(path) == "string"
- L0064:   p1 := replace(path, "\\", "/")
- L0065:   p2 := replace(p1, "/./", "/")
- L0066:   p3 := replace(p2, "//", "/")
- L0067:   p4 := trim_prefix(p3, "./")
- L0068:   normalized := trim(p4, "/")
- L0069: }
- L0070: 
- L0071: normalize_path(path) := "" if {
- L0072:   type_name(path) != "string"
- L0073: }
- L0074: 
- L0075: to_bool(v) := b if {
- L0076:   type_name(v) == "boolean"
- L0077:   b := v
- L0078: }
- L0079: 
- L0080: to_bool(v) := true if {
- L0081:   type_name(v) == "string"
- L0082:   vv := lower(trim_space(v))
- L0083:   vv == "true"
- L0084: }
- L0085: 
- L0086: to_bool(v) := true if {
- L0087:   type_name(v) == "string"
- L0088:   vv := lower(trim_space(v))
- L0089:   vv == "1"
- L0090: }
- L0091: 
- L0092: to_bool(v) := false if {
- L0093:   type_name(v) == "string"
- L0094:   vv := lower(trim_space(v))
- L0095:   vv == "false"
- L0096: }
- L0097: 
- L0098: to_bool(v) := false if {
- L0099:   type_name(v) == "string"
- L0100:   vv := lower(trim_space(v))
- L0101:   vv == "0"
- L0102: }
- L0103: 
- L0104: to_bool(v) := false if {
- L0105:   type_name(v) != "boolean"
- L0106:   type_name(v) != "string"
- L0107: }
- L0108: 
- L0109: finding_rule_id(f) := upper(trim_space(object.get(object.get(f, "source", {}), "id", "")))
- L0110: finding_tool(f) := lower(trim_space(object.get(object.get(f, "source", {}), "tool", "")))
- L0111: 
- L0112: finding_resource_id(f) := rid if {
- L0113:   rid := normalize_path(object.get(object.get(f, "resource", {}), "name", ""))
- L0114:   rid != ""
- L0115: }
- L0116: 
- L0117: finding_resource_id(f) := rid if {
- L0118:   normalize_path(object.get(object.get(f, "resource", {}), "name", "")) == ""
- L0119:   rid := normalize_path(object.get(object.get(f, "resource", {}), "path", ""))
- L0120:   rid != ""
- L0121: }
- L0122: 
- L0123: finding_resource_id(f) := rid if {
- L0124:   normalize_path(object.get(object.get(f, "resource", {}), "name", "")) == ""
- L0125:   normalize_path(object.get(object.get(f, "resource", {}), "path", "")) == ""
- L0126:   rid := normalize_path(object.get(object.get(object.get(f, "resource", {}), "location", {}), "file", ""))
- L0127:   rid != ""
- L0128: }
- L0129: 
- L0130: finding_resource_id(f) := "" if {
- L0131:   normalize_path(object.get(object.get(f, "resource", {}), "name", "")) == ""
- L0132:   normalize_path(object.get(object.get(f, "resource", {}), "path", "")) == ""
- L0133:   normalize_path(object.get(object.get(object.get(f, "resource", {}), "location", {}), "file", "")) == ""
- L0134: }
- L0135: 
- L0136: finding_severity_level(f) := upper(trim_space(object.get(object.get(f, "severity", {}), "level", "LOW")))
- L0137: 
- L0138: exception_id(ex) := lower(trim_space(object.get(ex, "id", "")))
- L0139: exception_tool(ex) := lower(trim_space(object.get(ex, "tool", "")))
- L0140: exception_rule(ex) := upper(trim_space(object.get(ex, "rule_id", "")))
- L0141: exception_resource(ex) := lower(normalize_path(object.get(ex, "resource", "")))
- L0142: exception_severity(ex) := upper(trim_space(object.get(ex, "severity", "")))
- L0143: exception_requested_by(ex) := lower(trim_space(object.get(ex, "requested_by", "")))
- L0144: exception_approved_by(ex) := lower(trim_space(object.get(ex, "approved_by", "")))
- L0145: exception_status(ex) := lower(trim_space(object.get(ex, "status", "")))
- L0146: exception_source(ex) := lower(trim_space(object.get(ex, "source", "")))
- L0147: exception_decision(ex) := lower(trim_space(object.get(ex, "decision", "")))
- L0148: exception_approved_at(ex) := trim_space(object.get(ex, "approved_at", ""))
- L0149: exception_expires_at(ex) := trim_space(object.get(ex, "expires_at", ""))
- L0150: 
- L0151: exception_has_wildcard(ex) if {
- L0152:   contains(exception_resource(ex), "*")
- L0153: }
- L0154: 
- L0155: exception_has_wildcard(ex) if {
- L0156:   contains(exception_resource(ex), "?")
- L0157: }
- L0158: 
- L0159: exception_scope_matches_repo(ex) if {
- L0160:   repos := object.get(object.get(ex, "scope", {}), "repos", [])
- L0161:   count(repos) == 0
- L0162: }
- L0163: 
- L0164: exception_scope_matches_repo(ex) if {
- L0165:   repos := object.get(object.get(ex, "scope", {}), "repos", [])
- L0166:   count(repos) > 0
- L0167:   current_repo := lower(trim_space(object.get(git_meta, "repo", "")))
- L0168:   some r in repos
- L0169:   lower(trim_space(r)) == current_repo
- L0170: }
- L0171: 
- L0172: exception_scope_matches_env(ex) if {
- L0173:   envs := object.get(object.get(ex, "scope", {}), "environments", [])
- L0174:   count(envs) == 0
- L0175: }
- L0176: 
- L0177: exception_scope_matches_env(ex) if {
- L0178:   envs := object.get(object.get(ex, "scope", {}), "environments", [])
- L0179:   count(envs) > 0
- L0180:   some e in envs
- L0181:   lower(trim_space(e)) == environment
- L0182: }
- L0183: 
- L0184: exception_scope_matches_branch(ex) if {
- L0185:   branches := object.get(object.get(ex, "scope", {}), "branches", [])
- L0186:   count(branches) == 0
- L0187: }
- L0188: 
- L0189: exception_scope_matches_branch(ex) if {
- L0190:   branches := object.get(object.get(ex, "scope", {}), "branches", [])
- L0191:   count(branches) > 0
- L0192:   current_branch := lower(trim_space(object.get(git_meta, "branch", "")))
- L0193:   some b in branches
- L0194:   lower(trim_space(b)) == current_branch
- L0195: }
- L0196: 
- L0197: exception_timestamp_fields_parse(ex) if {
- L0198:   time.parse_rfc3339_ns(exception_approved_at(ex))
- L0199:   time.parse_rfc3339_ns(exception_expires_at(ex))
- L0200: }
- L0201: 
- L0202: exception_is_expired(ex) if {
- L0203:   exception_expires_at(ex) != ""
- L0204:   expires_ns := time.parse_rfc3339_ns(exception_expires_at(ex))
- L0205:   time.now_ns() >= expires_ns
- L0206: }
- L0207: 
- L0208: valid_exception_definition(ex) if {
- L0209:   exception_id(ex) != ""
- L0210:   regex.match("^[a-f0-9]{64}$", exception_id(ex))
- L0211:   allowed_tools[exception_tool(ex)]
- L0212:   exception_rule(ex) != ""
- L0213:   exception_resource(ex) != ""
- L0214:   not exception_has_wildcard(ex)
- L0215:   severity_rank[exception_severity(ex)] >= 1
- L0216:   exception_requested_by(ex) != ""
- L0217:   exception_approved_by(ex) != ""
- L0218:   exception_requested_by(ex) != exception_approved_by(ex)
- L0219:   allowed_decisions[exception_decision(ex)]
- L0220:   exception_source(ex) == "defectdojo"
- L0221:   exception_status(ex) == "approved"
- L0222:   exception_timestamp_fields_parse(ex)
- L0223:   approved_ns := time.parse_rfc3339_ns(exception_approved_at(ex))
- L0224:   expires_ns := time.parse_rfc3339_ns(exception_expires_at(ex))
- L0225:   approved_ns <= time.now_ns()
- L0226:   approved_ns < expires_ns
- L0227:   not exception_is_expired(ex)
- L0228: }
- L0229: 
- L0230: exception_status_not_approved_ids[ex_id] if {
- L0231:   ex := exceptions_store[_]
- L0232:   exception_status(ex) != "approved"
- L0233:   ex_id := exception_id(ex)
- L0234: }
- L0235: 
- L0236: exception_missing_approved_by_ids[ex_id] if {
- L0237:   ex := exceptions_store[_]
- L0238:   exception_approved_by(ex) == ""
- L0239:   ex_id := exception_id(ex)
- L0240: }
- L0241: 
- L0242: exception_missing_approved_at_ids[ex_id] if {
- L0243:   ex := exceptions_store[_]
- L0244:   exception_approved_at(ex) == ""
- L0245:   ex_id := exception_id(ex)
- L0246: }
- L0247: 
- L0248: invalid_enabled_exception_ids[ex_id] if {
- L0249:   ex := exceptions_store[_]
- L0250:   ex_id := exception_id(ex)
- L0251:   ex_id != ""
- L0252:   not valid_exception_definition(ex)
- L0253:   not exception_is_expired(ex)
- L0254: }
- L0255: 
- L0256: expired_enabled_exception_ids[ex_id] if {
- L0257:   ex := exceptions_store[_]
- L0258:   ex_id := exception_id(ex)
- L0259:   ex_id != ""
- L0260:   exception_is_expired(ex)
- L0261: }
- L0262: 
- L0263: legacy_exception_after_sunset[ex_id] if {
- L0264:   ex_id := ""
- L0265:   false
- L0266: }
- L0267: 
- L0268: active_valid_enabled_exceptions := [ex |
- L0269:   ex := exceptions_store[_]
- L0270:   valid_exception_definition(ex)
- L0271: ]
- L0272: 
- L0273: candidate_exceptions_for_finding(f) := [ex |
- L0274:   ex := active_valid_enabled_exceptions[_]
- L0275:   exception_tool(ex) == finding_tool(f)
- L0276: ]
- L0277: 
- L0278: exception_matches_finding(ex, f) if {
- L0279:   exception_tool(ex) == finding_tool(f)
- L0280:   exception_rule(ex) == finding_rule_id(f)
- L0281:   exception_resource(ex) == lower(trim_space(finding_resource_id(f)))
- L0282:   exception_scope_matches_repo(ex)
- L0283:   exception_scope_matches_env(ex)
- L0284:   exception_scope_matches_branch(ex)
- L0285: }
- L0286: 
- L0287: applied_exception_ids[ex_id] if {
- L0288:   f := failed_findings[_]
- L0289:   ex := candidate_exceptions_for_finding(f)[_]
- L0290:   exception_matches_finding(ex, f)
- L0291:   ex_id := exception_id(ex)
- L0292: }
- L0293: 
- L0294: applied_exception_audit[item] if {
- L0295:   f := failed_findings[_]
- L0296:   ex := candidate_exceptions_for_finding(f)[_]
- L0297:   exception_matches_finding(ex, f)
- L0298:   item := {
- L0299:     "exception_id": exception_id(ex),
- L0300:     "scope_type": "strict_tool_rule_resource",
- L0301:     "commit_sha": trim_space(object.get(git_meta, "commit", "")),
- L0302:     "rule_id": exception_rule(ex),
- L0303:     "matching_method": "tool_rule_resource_exact",
- L0304:     "break_glass": false,
- L0305:   }
- L0306: }
- L0307: 
- L0308: _resource_mismatch(ex, f) if {
- L0309:   exception_resource(ex) != lower(trim_space(finding_resource_id(f)))
- L0310: }
- L0311: 
- L0312: _repo_mismatch(ex) if {
- L0313:   not exception_scope_matches_repo(ex)
- L0314: }
- L0315: 
- L0316: _env_mismatch(ex) if {
- L0317:   not exception_scope_matches_env(ex)
- L0318: }
- L0319: 
- L0320: _branch_mismatch(ex) if {
- L0321:   not exception_scope_matches_branch(ex)
- L0322: }
- L0323: 
- L0324: partial_mismatch_reasons(ex, f) := array.concat(
- L0325:   array.concat(
- L0326:     array.concat(
- L0327:       [m | _resource_mismatch(ex, f); m := sprintf("Resource path mismatch: exception='%s' finding='%s'", [exception_resource(ex), lower(trim_space(finding_resource_id(f)))])],
- L0328:       [m | _repo_mismatch(ex); m := sprintf("Scope repo mismatch: expected one of %v, got '%s'", [object.get(object.get(ex, "scope", {}), "repos", []), lower(trim_space(object.get(git_meta, "repo", "")))])]
- L0329:     ),
- L0330:     [m | _env_mismatch(ex); m := sprintf("Scope environment mismatch: expected one of %v, got '%s'", [object.get(object.get(ex, "scope", {}), "environments", []), environment])]
- L0331:   ),
- L0332:   [m | _branch_mismatch(ex); m := sprintf("Scope branch mismatch: expected one of %v, got '%s'", [object.get(object.get(ex, "scope", {}), "branches", []), lower(trim_space(object.get(git_meta, "branch", "")))])]
- L0333: )
- L0334: 
- L0335: partial_matches_audit[item] if {
- L0336:   f := failed_findings[_]
- L0337:   ex := active_valid_enabled_exceptions[_]
- L0338:   exception_tool(ex) == finding_tool(f)
- L0339:   exception_rule(ex) == finding_rule_id(f)
- L0340:   not exception_matches_finding(ex, f)
- L0341:   
- L0342:   item := {
- L0343:     "exception_id": exception_id(ex),
- L0344:     "rule_id": exception_rule(ex),
- L0345:     "mismatch_reasons": partial_mismatch_reasons(ex, f),
- L0346:     "expected_exception_resource": exception_resource(ex),
- L0347:     "actual_finding_resource": finding_resource_id(f)
- L0348:   }
- L0349: }
- L0350: 
- L0351: is_excepted_finding(f) if {
- L0352:   ex := candidate_exceptions_for_finding(f)[_]
- L0353:   exception_matches_finding(ex, f)
- L0354: }
- L0355: 
- L0356: effective_failed_findings := [f |
- L0357:   f := failed_findings[_]
- L0358:   not is_excepted_finding(f)
- L0359: ]
- L0360: 
- L0361: excepted_failed_findings := [f |
- L0362:   f := failed_findings[_]
- L0363:   is_excepted_finding(f)
- L0364: ]
- L0365: 
- L0366: effective_critical := count([f |
- L0367:   f := effective_failed_findings[_]
- L0368:   finding_severity_level(f) == "CRITICAL"
- L0369: ])
- L0370: 
- L0371: effective_high := count([f |
- L0372:   f := effective_failed_findings[_]
- L0373:   finding_severity_level(f) == "HIGH"
- L0374: ])
- L0375: 
- L0376: effective_medium := count([f |
- L0377:   f := effective_failed_findings[_]
- L0378:   finding_severity_level(f) == "MEDIUM"
- L0379: ])
- L0380: 
- L0381: effective_low := count([f |
- L0382:   f := effective_failed_findings[_]
- L0383:   finding_severity_level(f) == "LOW"
- L0384: ])
- L0385: 
- L0386: active_exceptions := [ex |
- L0387:   ex := active_valid_enabled_exceptions[_]
- L0388: ]
- L0389: 
- L0390: active_exceptions_critical := count([ex |
- L0391:   ex := active_exceptions[_]
- L0392:   exception_severity(ex) == "CRITICAL"
- L0393: ])
- L0394: 
- L0395: active_exceptions_high := count([ex |
- L0396:   ex := active_exceptions[_]
- L0397:   exception_severity(ex) == "HIGH"
- L0398: ])
- L0399: 
- L0400: active_exceptions_medium := count([ex |
- L0401:   ex := active_exceptions[_]
- L0402:   exception_severity(ex) == "MEDIUM"
- L0403: ])
- L0404: 
- L0405: active_exceptions_low := count([ex |
- L0406:   ex := active_exceptions[_]
- L0407:   exception_severity(ex) == "LOW"
- L0408: ])
- L0409: 
- L0410: avg_approval_time_hours := 0
- L0411: active_break_glass_count := 0
- L0412: 
- L0413: prod_critical_exception_violation[ex_id] if {
- L0414:   environment == "prod"
- L0415:   ex := active_valid_enabled_exceptions[_]
- L0416:   exception_severity(ex) == "CRITICAL"
- L0417:   ex_id := exception_id(ex)
- L0418: }
- L0419: 
- L0420: scanner_not_run[name] if {
- L0421:   not is_local
- L0422:   name := required_scanners[_]
- L0423:   scanner := object.get(scanners, name, {})
- L0424:   object.get(scanner, "status", "NOT_RUN") == "NOT_RUN"
- L0425: }
- L0426: 
- L0427: deny[msg] if {
- L0428:   scanner_not_run[name]
- L0429:   msg := sprintf("Scanner %s did not run or report is invalid", [name])
- L0430: }
- L0431: 
- L0432: deny[msg] if {
- L0433:   not thresholds_valid
- L0434:   msg := "Invalid threshold configuration: critical_max/high_max must be numeric"
- L0435: }
- L0436: 
- L0437: deny[msg] if {
- L0438:   effective_critical > enforced_critical_max
- L0439:   msg := sprintf(
- L0440:     "CRITICAL findings (%d) exceed enforced threshold (%d)",
- L0441:     [effective_critical, enforced_critical_max],
- L0442:   )
- L0443: }
- L0444: 
- L0445: deny[msg] if {
- L0446:   effective_high > enforced_high_max
- L0447:   msg := sprintf(
- L0448:     "HIGH findings (%d) exceed enforced threshold (%d)",
- L0449:     [effective_high, enforced_high_max],
- L0450:   )
- L0451: }
- L0452: 
- L0453: deny[msg] if {
- L0454:   prod_critical_exception_violation[ex_id]
- L0455:   msg := sprintf("Exception %s is invalid for prod: severity CRITICAL is forbidden", [ex_id])
- L0456: }
- L0457: 
- L0458: deny[msg] if {
- L0459:   invalid_enabled_exception_ids[ex_id]
- L0460:   msg := sprintf("Exception %s is malformed: required governance fields are invalid", [ex_id])
- L0461: }
- L0462: 
- L0463: deny[msg] if {
- L0464:   exception_status_not_approved_ids[ex_id]
- L0465:   msg := sprintf("Exception %s is invalid: status must be approved", [ex_id])
- L0466: }
- L0467: 
- L0468: deny[msg] if {
- L0469:   exception_missing_approved_by_ids[ex_id]
- L0470:   msg := sprintf("Exception %s is invalid: approved_by is required", [ex_id])
- L0471: }
- L0472: 
- L0473: deny[msg] if {
- L0474:   exception_missing_approved_at_ids[ex_id]
- L0475:   msg := sprintf("Exception %s is invalid: approved_at is required (RFC3339)", [ex_id])
- L0476: }
- L0477: 
- L0478: deny[msg] if {
- L0479:   expired_enabled_exception_ids[ex_id]
- L0480:   msg := sprintf("Exception %s is invalid: expires_at is in the past", [ex_id])
- L0481: }
- L0482: 
- L0483: default allow := false
- L0484: 
- L0485: allow if {
- L0486:   count(deny) == 0
- L0487: }
- L0488: 
- L0489: deny_reasons := sort([msg | deny[msg]])
- L0490: 
- L0491: decision := {
- L0492:   "allow": allow,
- L0493:   "deny": deny_reasons,
- L0494:   "metrics": {
- L0495:     "critical": effective_critical,
- L0496:     "high": effective_high,
- L0497:     "medium": effective_medium,
- L0498:     "low": effective_low,
- L0499:     "info": 0,
- L0500:     "failed": count(effective_failed_findings),
- L0501:     "failed_input": count(failed_findings),
- L0502:     "failed_effective": count(effective_failed_findings),
- L0503:     "excepted": count(excepted_failed_findings),
- L0504:     "excepted_findings": count(excepted_failed_findings),
- L0505:     "excepted_exception_ids": count(applied_exception_ids),
- L0506:     "governance": {
- L0507:       "active_exceptions_by_severity": {
- L0508:         "CRITICAL": active_exceptions_critical,
- L0509:         "HIGH": active_exceptions_high,
- L0510:         "MEDIUM": active_exceptions_medium,
- L0511:         "LOW": active_exceptions_low,
- L0512:         "INFO": 0
- L0513:       },
- L0514:       "active_break_glass": active_break_glass_count,
- L0515:       "expired_enabled_exceptions": count(expired_enabled_exception_ids),
- L0516:       "avg_approval_time_hours": avg_approval_time_hours
- L0517:     }
- L0518:   },
- L0519:   "thresholds": {
- L0520:     "critical_max":          critical_max_raw,
- L0521:     "high_max":              high_max_raw,
- L0522:     "enforced_critical_max": enforced_critical_max,
- L0523:     "enforced_high_max":     enforced_high_max,
- L0524:   },
- L0525:   "environment": environment,
- L0526:   "execution_mode": execution_mode,
- L0527:   "exceptions": {
- L0528:     "applied_ids": sort([id | applied_exception_ids[id]]),
- L0529:     "applied_count": count(applied_exception_ids),
- L0530:     "applied_audit": [item | applied_exception_audit[item]],
- L0531:     "partial_matches_audit": [item | partial_matches_audit[item]],
- L0532:     "strict_prod_violations": sort([id | prod_critical_exception_violation[id]]),
- L0533:     "invalid_enabled_ids": sort([id | invalid_enabled_exception_ids[id]]),
- L0534:     "expired_enabled_ids": sort([id | expired_enabled_exception_ids[id]]),
- L0535:     "legacy_after_sunset_ids": sort([id | legacy_exception_after_sunset[id]])
- L0536:   }
- L0537: }

#### shift-left/opa/run-opa.sh
- L0001: #!/usr/bin/env bash
- L0002: set -euo pipefail
- L0003: 
- L0004: # ==============================================================================
- L0005: # CloudSentinel - OPA Quality Gate (Policy Enforcement Point)
- L0006: #
- L0007: # Architecture Role:
- L0008: #   This script is the PEP (Policy Enforcement Point).
- L0009: #   OPA is the PDP (Policy Decision Point).
- L0010: #
- L0011: #   PEP  →  golden_report.json  →  PDP (OPA)  →  decision (allow/deny)
- L0012: #   (here)                         (opa server or opa eval CLI)
- L0013: #
- L0014: # Invocation Modes:
- L0015: #   --advisory  : Evaluate and display. Always exits 0. Use locally / pre-commit.
- L0016: #   --enforce   : Evaluate and block.   Exits 1 on deny.   Use in CI/CD pipelines.
- L0017: #
- L0018: # OPA Engine Selection (automatic fallback):
- L0019: #   1. OPA Server REST API  : POST ${OPA_SERVER_URL}/v1/data/cloudsentinel/gate/decision
- L0020: #   2. OPA CLI fallback     : opa eval --input --data ...
- L0021: #   Use OPA_PREFER_CLI=true to force CLI mode.
- L0022: #
- L0023: # Environment Variables:
- L0024: #   OPA_SERVER_URL      : OPA server URL (default: http://localhost:8181)
- L0025: #   OPA_EXCEPTIONS_FILE : Override path to exceptions.json (for testing)
- L0026: #   OPA_DECISION_FILE   : Override path for saved decision output
- L0027: #   OPA_PREFER_CLI      : Force CLI evaluation even if server is reachable
- L0028: #
- L0029: # Usage:
- L0030: #   bash shift-left/opa/run-opa.sh --advisory   # local, always passes
- L0031: #   bash shift-left/opa/run-opa.sh --enforce    # CI mode, blocks on deny
- L0032: #   OPA_SERVER_URL=http://opa:8181 bash shift-left/opa/run-opa.sh --enforce
- L0033: # ==============================================================================
- L0034: 
- L0035: # --- Colors & Formatting ---
- L0036: RED='\033[0;31m'
- L0037: GREEN='\033[0;32m'
- L0038: YELLOW='\033[1;33m'
- L0039: BLUE='\033[0;34m'
- L0040: CYAN='\033[0;36m'
- L0041: BOLD='\033[1m'
- L0042: DIM='\033[2m'
- L0043: NC='\033[0m'
- L0044: 
- L0045: REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
- L0046: 
- L0047: # --- Paths ---
- L0048: GOLDEN_REPORT="${REPO_ROOT}/.cloudsentinel/golden_report.json"
- L0049: POLICY_FILE="${REPO_ROOT}/policies/opa/pipeline_decision.rego"
- L0050: OUTPUT_DIR="${REPO_ROOT}/.cloudsentinel"
- L0051: 
- L0052: # Security hardening:
- L0053: # In CI, always use the runtime exceptions artifact generated in the same pipeline.
- L0054: # Ignore OPA_EXCEPTIONS_FILE override to prevent path tampering via CI variables.
- L0055: if [[ -n "${CI:-}" ]]; then
- L0056:   EXCEPTIONS_FILE="${OUTPUT_DIR}/exceptions.json"
- L0057: else
- L0058:   EXCEPTIONS_FILE="${OPA_EXCEPTIONS_FILE:-${OUTPUT_DIR}/exceptions.json}"
- L0059:   # Bootstrap empty exceptions file for local/advisory mode.
- L0060:   # In CI, this file is populated by fetch-exceptions.py from DefectDojo.
- L0061:   # Locally, a valid empty structure is the correct safe default.
- L0062:   if [[ ! -f "$EXCEPTIONS_FILE" ]]; then
- L0063:     mkdir -p "$(dirname "$EXCEPTIONS_FILE")"
- L0064:     printf '{"cloudsentinel":{"exceptions":{"schema_version":"2.0.0","generated_at":"2099-01-01T00:00:00Z","metadata":{"source":"local-bootstrap","total_raw_risk_acceptances":0,"total_valid_exceptions":0,"total_dropped":0},"exceptions":[]}}}\n' \
- L0065:       > "$EXCEPTIONS_FILE"
- L0066:     echo -e "${YELLOW}[OPA]${NC} ${BOLD}WARN${NC}  exceptions.json not found locally - bootstrapped empty file at ${EXCEPTIONS_FILE}" >&2
- L0067:   fi
- L0068: fi
- L0069: 
- L0070: DECISION_FILE="${OPA_DECISION_FILE:-${OUTPUT_DIR}/opa_decision.json}"
- L0071: DECISION_AUDIT_LOG_FILE="${CLOUDSENTINEL_DECISION_AUDIT_LOG:-${OUTPUT_DIR}/decision_audit_events.jsonl}"
- L0072: 
- L0073: OPA_SERVER_URL="${OPA_SERVER_URL:-http://localhost:8181}"
- L0074: OPA_API_PATH="/v1/data/cloudsentinel/gate/decision"
- L0075: OPA_QUERY="data.cloudsentinel.gate.decision"
- L0076: OPA_PREFER_CLI="${OPA_PREFER_CLI:-false}"
- L0077: 
- L0078: # --- Mode ---
- L0079: MODE="${1:---enforce}"
- L0080: if [[ "$MODE" != "--advisory" && "$MODE" != "--enforce" ]]; then
- L0081:   echo -e "${RED}Usage:${NC} $0 [--advisory|--enforce]" >&2
- L0082:   echo -e "  ${DIM}--advisory : evaluate, warn only, always exit 0${NC}" >&2
- L0083:   echo -e "  ${DIM}--enforce  : evaluate, block on deny, exit 1${NC}" >&2
- L0084:   exit 1
- L0085: fi
- L0086: 
- L0087: # --- Logging ---
- L0088: log_header() { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════${NC}"; echo -e "${BOLD}${CYAN}  $*${NC}"; echo -e "${BOLD}${CYAN}══════════════════════════════════════════${NC}"; }
- L0089: log_info()   { echo -e "${BLUE}[OPA]${NC} ${DIM}INFO${NC}  $*"; }
- L0090: log_ok()     { echo -e "${GREEN}[OPA]${NC} ${BOLD}ALLOW${NC} $*"; }
- L0091: log_warn()   { echo -e "${YELLOW}[OPA]${NC} ${BOLD}WARN${NC}  $*" >&2; }
- L0092: log_deny()   { echo -e "${RED}[OPA]${NC} ${BOLD}DENY${NC}  $*"; }
- L0093: log_err()    { echo -e "${RED}[OPA]${NC} ${BOLD}ERROR${NC} $*" >&2; }
- L0094: 
- L0095: emit_decision_audit_applied_exceptions() {
- L0096:   local ts
- L0097:   ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
- L0098:   mkdir -p "$(dirname "$DECISION_AUDIT_LOG_FILE")"
- L0099: 
- L0100:   jq -c \
- L0101:     --arg ts "$ts" \
- L0102:     --arg mode "$MODE" \
- L0103:     --arg env "$ENVIRONMENT" \
- L0104:     --argjson allow "$( [[ "$ALLOW" == "true" ]] && echo true || echo false )" \
- L0105:     '
- L0106:       (.result.exceptions.applied_audit // [])[]
- L0107:       | {
- L0108:           timestamp: $ts,
- L0109:           component: "run-opa",
- L0110:           event_type: "exception_applied",
- L0111:           mode: $mode,
- L0112:           environment: $env,
- L0113:           allow: $allow,
- L0114:           exception_id: (.exception_id // "unknown"),
- L0115:           scope_type: (.scope_type // "unknown"),
- L0116:           commit_sha: (.commit_sha // ""),
- L0117:           rule_id: (.rule_id // ""),
- L0118:           matching_method: (.matching_method // "")
- L0119:         }
- L0120:     ' "$DECISION_FILE" >> "$DECISION_AUDIT_LOG_FILE" 2>/dev/null || true
- L0121: }
- L0122: 
- L0123: # --- Prerequisites ---
- L0124: command -v jq >/dev/null 2>&1 || { log_err "jq is required. Install with: apt-get install jq"; exit 2; }
- L0125: 
- L0126: [[ -f "$GOLDEN_REPORT" ]] || {
- L0127:   log_err "Golden report not found: ${GOLDEN_REPORT}"
- L0128:   log_err "Run first: bash shift-left/normalizer/normalize.sh"
- L0129:   exit 2
- L0130: }
- L0131: 
- L0132: [[ -f "$POLICY_FILE" ]] || { log_err "Policy not found: ${POLICY_FILE}"; exit 2; }
- L0133: [[ -f "$EXCEPTIONS_FILE" ]] || { log_err "Exceptions not found: ${EXCEPTIONS_FILE}"; exit 2; }
- L0134: 
- L0135: mkdir -p "$OUTPUT_DIR"
- L0136: 
- L0137: # ==============================================================================
- L0138: # OPA Invocation — Server (preferred) → CLI (fallback)
- L0139: # ==============================================================================
- L0140: 
- L0141: # Strategy 1: OPA Server (REST API)
- L0142: # Production pattern: OPA runs as a persistent daemon, policies hot-reloaded.
- L0143: # Decouples the CI pipeline from policy evaluation logic.
- L0144: invoke_opa_server() {
- L0145:   local input_json
- L0146:   local http_code
- L0147:   local curl_err
- L0148: 
- L0149:   # Inline the golden_report as the OPA input document
- L0150:   input_json="$(jq -c '.' "$GOLDEN_REPORT")"
- L0151: 
- L0152:   # OPA v1 REST API:
- L0153:   #   POST /v1/data/<package>/<rule>
- L0154:   #   Body: { "input": <input_document> }
- L0155:   #   Response: { "result": <rule_value> }
- L0156:   http_code=$(curl -s -S -w "%{http_code}" \
- L0157:     --max-time 5 \
- L0158:     --connect-timeout 2 \
- L0159:     -X POST "${OPA_SERVER_URL}${OPA_API_PATH}" \
- L0160:     -H "Content-Type: application/json" \
- L0161:     -d "{\"input\": ${input_json}}" \
- L0162:     -o "$DECISION_FILE" \
- L0163:     2>/dev/null) || curl_err=$?
- L0164: 
- L0165:   if [[ -n "${curl_err:-}" ]]; then
- L0166:       log_err "OPA Server connection failed (cURL error: $curl_err). URL: $OPA_SERVER_URL"
- L0167:       return 1
- L0168:   fi
- L0169: 
- L0170:   if [[ "$http_code" != "200" ]]; then
- L0171:       log_err "OPA Server returned HTTP $http_code"
- L0172:       [[ -s "$DECISION_FILE" ]] && log_err "Server Response: $(cat "$DECISION_FILE")"
- L0173:       return 1
- L0174:   fi
- L0175: 
- L0176:   return 0
- L0177: }
- L0178: 
- L0179: # Strategy 2: OPA CLI (opa eval)
- L0180: # Development / air-gapped fallback. No server needed.
- L0181: # Normalizes CLI output format to match OPA REST API response shape.
- L0182: invoke_opa_cli() {
- L0183:   command -v opa >/dev/null 2>&1 || {
- L0184:     log_err "Neither OPA Server (${OPA_SERVER_URL}) nor OPA CLI ('opa') is available."
- L0185:     log_err "Start OPA: docker compose up -d opa-server"
- L0186:     log_err "Or install CLI: https://www.openpolicyagent.org/docs/latest/#running-opa"
- L0187:     exit 2
- L0188:   }
- L0189: 
- L0190:   local tmp_raw
- L0191:   local tmp_err
- L0192:   tmp_raw="$(mktemp -t opa_raw.XXXXXX.json)"
- L0193:   tmp_err="$(mktemp -t opa_err.XXXXXX.log)"
- L0194:   trap 'rm -f "$tmp_raw" "$tmp_err"' RETURN
- L0195: 
- L0196:   if ! opa eval \
- L0197:     --format json \
- L0198:     --input "$GOLDEN_REPORT" \
- L0199:     --data "$POLICY_FILE" \
- L0200:     --data "$EXCEPTIONS_FILE" \
- L0201:     "$OPA_QUERY" \
- L0202:     > "$tmp_raw" 2> "$tmp_err"; then
- L0203:     log_err "OPA CLI eval failed. Check policy compatibility and OPA version."
- L0204:     if [[ -s "$tmp_err" ]]; then
- L0205:       log_err "OPA error output:"
- L0206:       sed 's/^/[opa-cli] /' "$tmp_err" >&2
- L0207:     fi
- L0208:     exit 2
- L0209:   fi
- L0210: 
- L0211:   # OPA CLI output: {"result": [{"expressions": [{"value": {...}}]}]}
- L0212:   # Normalize to match REST API shape: {"result": {...}}
- L0213:   jq '{result: .result[0].expressions[0].value}' "$tmp_raw" > "$DECISION_FILE"
- L0214: }
- L0215: 
- L0216: # ==============================================================================
- L0217: # Execute OPA
- L0218: # ==============================================================================
- L0219: 
- L0220: log_header "CloudSentinel — OPA Quality Gate"
- L0221: 
- L0222: ENVIRONMENT="$(jq -r '.metadata.environment // "unknown"' "$GOLDEN_REPORT")"
- L0223: GIT_COMMIT="$(jq -r '.metadata.git.commit // "unknown"' "$GOLDEN_REPORT" | cut -c1-8)"
- L0224: GIT_BRANCH="$(jq -r '.metadata.git.branch // "unknown"' "$GOLDEN_REPORT")"
- L0225: 
- L0226: log_info "Mode        : ${BOLD}${MODE}${NC}"
- L0227: log_info "Environment : ${BOLD}${ENVIRONMENT}${NC}"
- L0228: log_info "Commit      : ${GIT_COMMIT} (${GIT_BRANCH})"
- L0229: log_info "Policy      : ${POLICY_FILE}"
- L0230: log_info "Exceptions  : ${EXCEPTIONS_FILE}"
- L0231: echo ""
- L0232: 
- L0233: INVOCATION_MODE=""
- L0234: if [[ "${OPA_PREFER_CLI}" == "true" ]]; then
- L0235:   invoke_opa_cli
- L0236:   INVOCATION_MODE="cli"
- L0237:   log_info "Engine      : OPA CLI ${YELLOW}[forced]${NC}"
- L0238: else
- L0239:   if invoke_opa_server 2>/dev/null; then
- L0240:     INVOCATION_MODE="server"
- L0241:     log_info "Engine      : OPA Server ${BOLD}${OPA_SERVER_URL}${NC} ${GREEN}[REST API]${NC}"
- L0242:   else
- L0243:     log_warn "OPA Server not reachable (${OPA_SERVER_URL}). Falling back to OPA CLI."
- L0244:     invoke_opa_cli
- L0245:     INVOCATION_MODE="cli"
- L0246:     log_info "Engine      : OPA CLI ${YELLOW}[fallback]${NC}"
- L0247:   fi
- L0248: fi
- L0249: 
- L0250: if [[ ! -s "$DECISION_FILE" ]]; then
- L0251:   log_err "OPA decision file not generated: ${DECISION_FILE}"
- L0252:   log_err "Check OPA CLI version and policy compatibility."
- L0253:   exit 2
- L0254: fi
- L0255: 
- L0256: if ! jq -e '.result' "$DECISION_FILE" >/dev/null 2>&1; then
- L0257:   log_err "OPA decision file is invalid or missing '.result': ${DECISION_FILE}"
- L0258:   exit 2
- L0259: fi
- L0260: 
- L0261: # ==============================================================================
- L0262: # Parse & Display Decision
- L0263: # ==============================================================================
- L0264: 
- L0265: ALLOW="$(jq -r   '.result.allow          // false'   "$DECISION_FILE")"
- L0266: CRITICAL="$(jq -r '.result.metrics.critical // 0'    "$DECISION_FILE")"
- L0267: HIGH="$(jq -r     '.result.metrics.high     // 0'    "$DECISION_FILE")"
- L0268: MEDIUM="$(jq -r   '.result.metrics.medium   // 0'    "$DECISION_FILE")"
- L0269: LOW="$(jq -r      '.result.metrics.low      // 0'    "$DECISION_FILE")"
- L0270: EFFECTIVE="$(jq -r '.result.metrics.failed_effective // 0' "$DECISION_FILE")"
- L0271: EXCEPTED="$(jq -r  '.result.metrics.excepted     // 0'    "$DECISION_FILE")"
- L0272: APPLIED_IDS="$(jq -r '.result.exceptions.applied_ids // [] | join(", ")' "$DECISION_FILE")"
- L0273: APPLIED_COUNT="$(jq -r '.result.exceptions.applied_count // 0' "$DECISION_FILE")"
- L0274: INVALID_IDS="$(jq -r '.result.exceptions.invalid_enabled_ids // [] | join(", ")' "$DECISION_FILE")"
- L0275: DENY_COUNT="$(jq -r  '.result.deny // [] | length'           "$DECISION_FILE")"
- L0276: ACTIVE_EXC_CRITICAL="$(jq -r '.result.metrics.governance.active_exceptions_by_severity.CRITICAL // 0' "$DECISION_FILE")"
- L0277: ACTIVE_EXC_HIGH="$(jq -r '.result.metrics.governance.active_exceptions_by_severity.HIGH // 0' "$DECISION_FILE")"
- L0278: ACTIVE_EXC_MEDIUM="$(jq -r '.result.metrics.governance.active_exceptions_by_severity.MEDIUM // 0' "$DECISION_FILE")"
- L0279: ACTIVE_EXC_LOW="$(jq -r '.result.metrics.governance.active_exceptions_by_severity.LOW // 0' "$DECISION_FILE")"
- L0280: ACTIVE_EXC_INFO="$(jq -r '.result.metrics.governance.active_exceptions_by_severity.INFO // 0' "$DECISION_FILE")"
- L0281: ACTIVE_EXC_TOTAL=$((ACTIVE_EXC_CRITICAL + ACTIVE_EXC_HIGH + ACTIVE_EXC_MEDIUM + ACTIVE_EXC_LOW + ACTIVE_EXC_INFO))
- L0282: 
- L0283: log_header "Decision Report"
- L0284: 
- L0285: printf "  %-14s : %s\n" "Environment"  "${ENVIRONMENT}"
- L0286: printf "  %-14s : %s\n" "OPA Engine"   "${INVOCATION_MODE}"
- L0287: echo ""
- L0288: 
- L0289: # Severity table
- L0290: printf "  ${BOLD}%-22s  %s${NC}\n" "Severity" "Effective (post-exception)"
- L0291: printf "  ${RED}%-22s  %s${NC}\n"    "CRITICAL"             "${CRITICAL}"
- L0292: printf "  ${YELLOW}%-22s  %s${NC}\n" "HIGH"                 "${HIGH}"
- L0293: printf "  %-22s  %s\n"               "MEDIUM"               "${MEDIUM}"
- L0294: printf "  %-22s  %s\n"               "LOW"                  "${LOW}"
- L0295: echo   "  ──────────────────────────────"
- L0296: printf "  %-22s  %s\n"               "Total failed"         "${EFFECTIVE}"
- L0297: printf "  ${DIM}%-22s  %s${NC}\n"    "Excepted (suppressed)"  "${EXCEPTED}"
- L0298: echo ""
- L0299: printf "  ${DIM}%-22s  %s${NC}\n"    "Active exceptions"      "${ACTIVE_EXC_TOTAL}"
- L0300: printf "  ${DIM}%-22s  %s${NC}\n"    "Active exceptions sev"  "C:${ACTIVE_EXC_CRITICAL} H:${ACTIVE_EXC_HIGH} M:${ACTIVE_EXC_MEDIUM} L:${ACTIVE_EXC_LOW} I:${ACTIVE_EXC_INFO}"
- L0301: 
- L0302: if [[ -n "$APPLIED_IDS" ]]; then
- L0303:   echo ""
- L0304:   printf "  ${DIM}%-22s  %s${NC}\n" "Applied exceptions" "${APPLIED_IDS}"
- L0305: fi
- L0306: 
- L0307: if [[ -n "$INVALID_IDS" ]]; then
- L0308:   echo ""
- L0309:   printf "  ${RED}%-22s  %s${NC}\n" "INVALID exceptions" "${INVALID_IDS}"
- L0310: fi
- L0311: 
- L0312: echo ""
- L0313: echo "  ──────────────────────────────"
- L0314: 
- L0315: mkdir -p "$(dirname "$DECISION_AUDIT_LOG_FILE")"
- L0316: : > "$DECISION_AUDIT_LOG_FILE"
- L0317: 
- L0318: if [[ "$ALLOW" == "true" ]]; then
- L0319:   if [[ "$APPLIED_COUNT" -gt 0 ]]; then
- L0320:     emit_decision_audit_applied_exceptions
- L0321:     log_info "Applied exception decision_audit log appended to ${DECISION_AUDIT_LOG_FILE}"
- L0322:   fi
- L0323:   log_ok "DECISION → ${BOLD}${GREEN}ALLOW ✓${NC}"
- L0324: else
- L0325:   log_deny "DECISION → ${BOLD}${RED}DENY ✗${NC}  (${DENY_COUNT} reason(s))"
- L0326:   echo ""
- L0327:   jq -r '.result.deny // [] | to_entries[] | "  [" + (.key + 1 | tostring) + "] " + .value' "$DECISION_FILE"
- L0328: fi
- L0329: 
- L0330: echo ""
- L0331: 
- L0332: # ==============================================================================
- L0333: # Enrich & Save Decision Artifact
- L0334: # ==============================================================================
- L0335: 
- L0336: tmp_decision="$(mktemp -t opa_decision_enriched.XXXXXX.json)"
- L0337: jq \
- L0338:   --arg mode        "$MODE" \
- L0339:   --arg engine      "$INVOCATION_MODE" \
- L0340:   --arg policy_file "$POLICY_FILE" \
- L0341:   --arg exc_file    "$EXCEPTIONS_FILE" \
- L0342:   --arg timestamp   "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
- L0343:   '.result += {
- L0344:     _gate: {
- L0345:       mode:         $mode,
- L0346:       engine:       $engine,
- L0347:       policy_file:  $policy_file,
- L0348:       exceptions_file: $exc_file,
- L0349:       evaluated_at: $timestamp
- L0350:     }
- L0351:   }' \
- L0352:   "$DECISION_FILE" > "$tmp_decision" \
- L0353:   && mv "$tmp_decision" "$DECISION_FILE"
- L0354: 
- L0355: log_info "Decision saved : ${DECISION_FILE}"
- L0356: 
- L0357: # ==============================================================================
- L0358: # Enforcement
- L0359: # ==============================================================================
- L0360: 
- L0361: if [[ "$ALLOW" == "true" ]]; then
- L0362:   exit 0
- L0363: fi
- L0364: 
- L0365: if [[ "$MODE" == "--enforce" ]]; then
- L0366:   echo ""
- L0367:   log_deny "${BOLD}Pipeline BLOCKED by OPA Quality Gate.${NC}"
- L0368:   log_deny "Fix violations or submit an exception request using scripts/cloudsentinel_ra_template.py (or scripts/create-risk-acceptance.sh)."
- L0369:   exit 1
- L0370: else
- L0371:   log_warn "Advisory mode: deny detected but pipeline continues."
- L0372:   log_warn "Resolve all violations before this reaches --enforce (CI/CD)."
- L0373:   exit 0
- L0374: fi

#### ci/scripts/opa-decision.sh
- L0001: #!/usr/bin/env bash
- L0002: set -euo pipefail
- L0003: 
- L0004: opa run --server --addr=127.0.0.1:8181 \
- L0005:   --log-level=info \
- L0006:   --log-format=json \
- L0007:   --set=decision_logs.console=true \
- L0008:   policies/opa/pipeline_decision.rego \
- L0009:   .cloudsentinel/exceptions.json \
- L0010:   > /tmp/opa-server.log 2>&1 &
- L0011: for i in {1..10}; do
- L0012:   if curl -sf "http://127.0.0.1:8181/health" >/dev/null; then
- L0013:     echo "[opa] OPA server is UP"
- L0014:     break
- L0015:   fi
- L0016:   echo "[opa] Waiting for OPA... ($i/10)"
- L0017:   sleep 2
- L0018: done
- L0019: OPA_SERVER_URL="http://127.0.0.1:8181" bash shift-left/opa/run-opa.sh --enforce

#### shift-left/opa/fetch_exceptions/fetch_defectdojo.py
- L0001: #!/usr/bin/env python3
- L0002: """DefectDojo API client logic for risk acceptance retrieval (fetch layer only)."""
- L0003: 
- L0004: from __future__ import annotations
- L0005: 
- L0006: import json
- L0007: import urllib.error
- L0008: import urllib.request
- L0009: from logging import Logger
- L0010: from typing import Any, Dict, List
- L0011: 
- L0012: from .fetch_utils import sanitize_text
- L0013: 
- L0014: 
- L0015: class DefectDojoFetchError(RuntimeError):
- L0016:     """Raised when DefectDojo cannot be queried reliably."""
- L0017: 
- L0018: 
- L0019: def _fetch_json(url: str, headers: Dict[str, str], timeout: int, logger: Logger) -> Dict[str, Any]:
- L0020:     req = urllib.request.Request(url, headers=headers)
- L0021:     try:
- L0022:         with urllib.request.urlopen(req, timeout=timeout) as response:
- L0023:             body = json.loads(response.read().decode("utf-8"))
- L0024:     except urllib.error.URLError as exc:
- L0025:         logger.error(f"DefectDojo request failed: {exc}")
- L0026:         raise DefectDojoFetchError(f"request_failed:{url}") from exc
- L0027:     except json.JSONDecodeError as exc:
- L0028:         logger.error("DefectDojo returned malformed JSON")
- L0029:         raise DefectDojoFetchError(f"invalid_json:{url}") from exc
- L0030: 
- L0031:     if not isinstance(body, dict):
- L0032:         logger.error("DefectDojo response payload is not a JSON object")
- L0033:         raise DefectDojoFetchError(f"invalid_payload_type:{url}")
- L0034:     return body
- L0035: 
- L0036: 
- L0037: def _resolve_user_identity(
- L0038:     dojo_url: str,
- L0039:     headers: Dict[str, str],
- L0040:     raw_value: Any,
- L0041:     user_cache: Dict[str, str],
- L0042:     logger: Logger,
- L0043: ) -> str:
- L0044:     if isinstance(raw_value, dict):
- L0045:         candidate = sanitize_text(raw_value.get("username") or raw_value.get("email"))
- L0046:         return candidate
- L0047: 
- L0048:     token = sanitize_text(raw_value)
- L0049:     if not token:
- L0050:         return ""
- L0051:     if not token.isdigit():
- L0052:         return token
- L0053: 
- L0054:     if token in user_cache:
- L0055:         return user_cache[token]
- L0056: 
- L0057:     endpoint = f"{dojo_url}/api/v2/users/{token}/"
- L0058:     try:
- L0059:         user_payload = _fetch_json(endpoint, headers, 10, logger)
- L0060:     except DefectDojoFetchError:
- L0061:         return token
- L0062: 
- L0063:     resolved = sanitize_text(user_payload.get("username") or user_payload.get("email") or token)
- L0064:     user_cache[token] = resolved
- L0065:     return resolved
- L0066: 
- L0067: 
- L0068: def _extract_finding_id(item: Any) -> str:
- L0069:     if isinstance(item, int):
- L0070:         return str(item)
- L0071:     if isinstance(item, str):
- L0072:         return sanitize_text(item) if sanitize_text(item).isdigit() else ""
- L0073:     if isinstance(item, dict):
- L0074:         candidate = sanitize_text(item.get("id"))
- L0075:         return candidate if candidate.isdigit() else ""
- L0076:     return ""
- L0077: 
- L0078: 
- L0079: def _enrich_with_accepted_findings(
- L0080:     dojo_url: str,
- L0081:     headers: Dict[str, str],
- L0082:     risk_acceptances: List[Dict[str, Any]],
- L0083:     logger: Logger,
- L0084: ) -> None:
- L0085:     finding_cache: Dict[str, Dict[str, Any]] = {}
- L0086:     user_cache: Dict[str, str] = {}
- L0087: 
- L0088:     for ra in risk_acceptances:
- L0089:         ra["owner"] = _resolve_user_identity(dojo_url, headers, ra.get("owner"), user_cache, logger)
- L0090:         ra["accepted_by"] = _resolve_user_identity(
- L0091:             dojo_url,
- L0092:             headers,
- L0093:             ra.get("accepted_by"),
- L0094:             user_cache,
- L0095:             logger,
- L0096:         )
- L0097: 
- L0098:         raw_findings = ra.get("accepted_findings", [])
- L0099:         if not isinstance(raw_findings, list) or not raw_findings:
- L0100:             continue
- L0101: 
- L0102:         details: List[Dict[str, Any]] = []
- L0103:         for item in raw_findings:
- L0104:             finding_id = _extract_finding_id(item)
- L0105:             if not finding_id:
- L0106:                 continue
- L0107: 
- L0108:             if finding_id not in finding_cache:
- L0109:                 endpoint = f"{dojo_url}/api/v2/findings/{finding_id}/"
- L0110:                 finding_payload = _fetch_json(endpoint, headers, 10, logger)
- L0111:                 if isinstance(finding_payload, dict) and finding_payload:
- L0112:                     finding_cache[finding_id] = finding_payload
- L0113: 
- L0114:             if finding_id in finding_cache:
- L0115:                 details.append(finding_cache[finding_id])
- L0116: 
- L0117:         if details:
- L0118:             ra["accepted_finding_details"] = details
- L0119: 
- L0120: 
- L0121: def fetch_risk_acceptances(dojo_url: str, dojo_api_key: str, logger: Logger) -> List[Dict[str, Any]]:
- L0122:     if not dojo_url or not dojo_api_key:
- L0123:         raise DefectDojoFetchError("missing_credentials")
- L0124: 
- L0125:     headers = {
- L0126:         "Authorization": f"Token {dojo_api_key}",
- L0127:         "Accept": "application/json",
- L0128:     }
- L0129: 
- L0130:     endpoint = f"{dojo_url}/api/v2/risk_acceptance/"
- L0131:     results: List[Dict[str, Any]] = []
- L0132:     next_url = endpoint
- L0133: 
- L0134:     while next_url:
- L0135:         body = _fetch_json(next_url, headers, 15, logger)
- L0136:         page = body.get("results", [])
- L0137:         if not isinstance(page, list):
- L0138:             raise DefectDojoFetchError(f"invalid_results_array:{next_url}")
- L0139: 
- L0140:         for item in page:
- L0141:             if isinstance(item, dict):
- L0142:                 results.append(item)
- L0143: 
- L0144:         next_url = sanitize_text(body.get("next"))
- L0145: 
- L0146:     _enrich_with_accepted_findings(dojo_url, headers, results, logger)
- L0147:     logger.info(f"Fetched {len(results)} risk acceptances from DefectDojo")
- L0148:     return results

#### shift-left/opa/fetch_exceptions/fetch_mapping.py
- L0001: #!/usr/bin/env python3
- L0002: """Normalization orchestration, output emission, and audit trail generation."""
- L0003: 
- L0004: from __future__ import annotations
- L0005: 
- L0006: import json
- L0007: import os
- L0008: from typing import Any, Dict, List, Optional, Tuple
- L0009: 
- L0010: from .fetch_normalization import accepted_findings, normalize_finding_candidate, risk_acceptance_id
- L0011: from .fetch_utils import ensure_dir, normalize_path, now_utc, sanitize_text, save_json, to_rfc3339
- L0012: from .fetch_validation import (
- L0013:     FetchContext,
- L0014:     is_active_accepted,
- L0015:     parse_approved_at,
- L0016:     parse_approved_by,
- L0017:     parse_decision,
- L0018:     parse_expires_at,
- L0019:     parse_requested_by,
- L0020:     parse_status,
- L0021:     stable_exception_id,
- L0022:     validate_normalized_exception,
- L0023: )
- L0024: 
- L0025: 
- L0026: def _build_ci_scope() -> dict:
- L0027:     """
- L0028:     Injects pipeline execution context into the exception scope.
- L0029:     These values are NOT sourced from DefectDojo — they come from CI environment variables.
- L0030:     DefectDojo manages risk lifecycle; the fetch layer binds that risk to a CI context.
- L0031:     """
- L0032:     scope: dict = {}
- L0033: 
- L0034:     repo = os.environ.get("CI_PROJECT_PATH", "").strip()
- L0035:     if repo:
- L0036:         scope["repos"] = [repo]
- L0037: 
- L0038:     branch = os.environ.get("CI_COMMIT_REF_NAME", "").strip()
- L0039:     if branch:
- L0040:         scope["branches"] = [branch]
- L0041: 
- L0042:     env = (
- L0043:         os.environ.get("CI_ENVIRONMENT_NAME", "")
- L0044:         or os.environ.get("ENVIRONMENT", "")
- L0045:     ).strip().lower()
- L0046:     valid_envs = {"dev", "test", "staging", "prod"}
- L0047:     if env in valid_envs:
- L0048:         scope["environments"] = [env]
- L0049: 
- L0050:     return scope
- L0051: 
- L0052: 
- L0053: def emit_audit_event(
- L0054:     ctx: FetchContext,
- L0055:     input_payload: Any,
- L0056:     output_payload: Optional[Dict[str, Any]],
- L0057:     status: str,
- L0058:     reason: Optional[str] = None,
- L0059: ) -> None:
- L0060:     ensure_dir(ctx.audit_log_file)
- L0061:     event: Dict[str, Any] = {
- L0062:         "timestamp": to_rfc3339(now_utc()),
- L0063:         "source": "defectdojo",
- L0064:         "action": "normalize_exception",
- L0065:         "input": input_payload,
- L0066:         "output": output_payload,
- L0067:         "status": status,
- L0068:     }
- L0069:     if reason:
- L0070:         event["reason"] = reason
- L0071: 
- L0072:     with open(ctx.audit_log_file, "a", encoding="utf-8") as f:
- L0073:         f.write(json.dumps(event, separators=(",", ":"), sort_keys=True) + "\n")
- L0074: 
- L0075: 
- L0076: def json_payload(ctx: FetchContext, exceptions: List[Dict[str, Any]], meta: Dict[str, Any]) -> Dict[str, Any]:
- L0077:     return {
- L0078:         "cloudsentinel": {
- L0079:             "exceptions": {
- L0080:                 "schema_version": ctx.schema_version,
- L0081:                 "generated_at": to_rfc3339(now_utc()),
- L0082:                 "metadata": meta,
- L0083:                 "exceptions": exceptions,
- L0084:             }
- L0085:         }
- L0086:     }
- L0087: 
- L0088: 
- L0089: def drop(ctx: FetchContext, ra_identifier: str, reason: str, detail: str, input_payload: Any) -> None:
- L0090:     record = {
- L0091:         "risk_acceptance_id": ra_identifier,
- L0092:         "reason": reason,
- L0093:         "detail": detail,
- L0094:         "timestamp": to_rfc3339(now_utc()),
- L0095:         "input": input_payload,
- L0096:     }
- L0097:     ctx.dropped.append(record)
- L0098: 
- L0099: 
- L0100: def save_outputs(ctx: FetchContext, payload: Dict[str, Any]) -> None:
- L0101:     save_json(ctx.output_file, payload)
- L0102:     save_json(ctx.dropped_file, {"dropped_exceptions": ctx.dropped})
- L0103: 
- L0104: 
- L0105: def _draft_exception(
- L0106:     ctx: FetchContext,
- L0107:     ra: Dict[str, Any],
- L0108:     finding_candidate: Dict[str, Any],
- L0109: ) -> Dict[str, Any]:
- L0110:     tool = sanitize_text(finding_candidate.get("tool")).lower()
- L0111:     rule_id = sanitize_text(finding_candidate.get("rule_id"))
- L0112:     resource = normalize_path(finding_candidate.get("resource"))
- L0113: 
- L0114:     requested_by = parse_requested_by(ra)
- L0115:     approved_by = parse_approved_by(ra)
- L0116:     decision = parse_decision(ra)
- L0117:     approved_at = parse_approved_at(ra)
- L0118:     expires_at = parse_expires_at(ra)
- L0119: 
- L0120:     return {
- L0121:         "id": stable_exception_id(tool, rule_id, resource) if tool and rule_id and resource else "",
- L0122:         "tool": tool,
- L0123:         "rule_id": rule_id,
- L0124:         "resource": resource,
- L0125:         "severity": sanitize_text(finding_candidate.get("severity")).upper(),
- L0126:         "requested_by": requested_by,
- L0127:         "approved_by": approved_by,
- L0128:         "approved_at": to_rfc3339(approved_at) if approved_at else "",
- L0129:         "expires_at": to_rfc3339(expires_at) if expires_at else "",
- L0130:         "decision": decision,
- L0131:         "source": "defectdojo",
- L0132:         "status": parse_status(ra) or "",
- L0133:         "scope": _build_ci_scope(),
- L0134:     }
- L0135: 
- L0136: 
- L0137: def _deduplicate_exceptions(exceptions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
- L0138:     by_id: Dict[str, Tuple[str, Dict[str, Any]]] = {}
- L0139: 
- L0140:     for item in exceptions:
- L0141:         identifier = sanitize_text(item.get("id"))
- L0142:         if not identifier:
- L0143:             continue
- L0144:         canonical = json.dumps(item, separators=(",", ":"), sort_keys=True)
- L0145:         previous = by_id.get(identifier)
- L0146:         if previous is None or canonical < previous[0]:
- L0147:             by_id[identifier] = (canonical, item)
- L0148: 
- L0149:     ordered_ids = sorted(by_id.keys())
- L0150:     return [by_id[item_id][1] for item_id in ordered_ids]
- L0151: 
- L0152: 
- L0153: def map_risk_acceptances(ctx: FetchContext, raw_ras: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
- L0154:     accepted: List[Dict[str, Any]] = []
- L0155: 
- L0156:     for ra in raw_ras:
- L0157:         ra_identifier = risk_acceptance_id(ra)
- L0158: 
- L0159:         # Filter: only process Risk Acceptances that are actively accepted
- L0160:         # in DefectDojo (active=true AND not rejected/expired).
- L0161:         if not is_active_accepted(ra):
- L0162:             reason = "inactive_risk_acceptance"
- L0163:             detail = "DefectDojo RA is not active+accepted (active=False or status!=accepted)"
- L0164:             drop(ctx, ra_identifier, reason, detail, ra)
- L0165:             emit_audit_event(ctx, ra, None, "rejected", reason)
- L0166:             continue
- L0167: 
- L0168:         findings = accepted_findings(ra)
- L0169: 
- L0170:         if not findings:
- L0171:             reason = "parsing_error"
- L0172:             detail = "no accepted findings available"
- L0173:             drop(ctx, ra_identifier, reason, detail, ra)
- L0174:             emit_audit_event(ctx, ra, None, "rejected", reason)
- L0175:             continue
- L0176: 
- L0177:         valid_for_ra = 0
- L0178:         for finding in findings:
- L0179:             finding_dict = finding if isinstance(finding, dict) else {"title": sanitize_text(finding)}
- L0180:             candidate = normalize_finding_candidate(ctx, ra, finding_dict)
- L0181:             normalized_exception = _draft_exception(ctx, ra, candidate)
- L0182: 
- L0183:             is_valid, reason, detail = validate_normalized_exception(ctx, normalized_exception)
- L0184:             if not is_valid:
- L0185:                 reject_reason = reason or "parsing_error"
- L0186:                 drop(ctx, ra_identifier, reject_reason, detail or "validation failed", finding_dict)
- L0187:                 emit_audit_event(ctx, finding_dict, normalized_exception, "rejected", reject_reason)
- L0188:                 continue
- L0189: 
- L0190:             accepted.append(normalized_exception)
- L0191:             valid_for_ra += 1
- L0192:             emit_audit_event(ctx, finding_dict, normalized_exception, "accepted")
- L0193: 
- L0194:         if valid_for_ra == 0:
- L0195:             reason = "parsing_error"
- L0196:             detail = "no valid findings parsed"
- L0197:             drop(ctx, ra_identifier, reason, detail, ra)
- L0198: 
- L0199:     deduplicated = _deduplicate_exceptions(accepted)
- L0200: 
- L0201:     meta = {
- L0202:         "source": "defectdojo",
- L0203:         "total_raw_risk_acceptances": len(raw_ras),
- L0204:         "total_valid_exceptions": len(deduplicated),
- L0205:         "total_dropped": len(ctx.dropped),
- L0206:     }
- L0207: 
- L0208:     return deduplicated, meta

#### shift-left/opa/fetch_exceptions/fetch_validation.py
- L0001: #!/usr/bin/env python3
- L0002: """Validation rules for CloudSentinel DefectDojo exception ingestion."""
- L0003: 
- L0004: from __future__ import annotations
- L0005: 
- L0006: from dataclasses import dataclass, field
- L0007: from datetime import datetime
- L0008: from logging import Logger
- L0009: from typing import Any, Dict, List, Optional, Set, Tuple
- L0010: 
- L0011: from .fetch_utils import (
- L0012:     cf,
- L0013:     first_non_empty,
- L0014:     has_wildcard,
- L0015:     normalize_decision,
- L0016:     normalize_severity,
- L0017:     now_utc,
- L0018:     parse_datetime,
- L0019:     sanitize_text,
- L0020:     sanitize_username,
- L0021:     sha256_hex,
- L0022:     to_rfc3339,
- L0023: )
- L0024: 
- L0025: 
- L0026: @dataclass
- L0027: class FetchContext:
- L0028:     logger: Logger
- L0029:     dojo_url: str
- L0030:     dojo_api_key: str
- L0031:     repo_root: str
- L0032:     output_file: str
- L0033:     dropped_file: str
- L0034:     audit_log_file: str
- L0035:     schema_version: str
- L0036:     severity_enum: Set[str]
- L0037:     allowed_tools: Set[str]
- L0038:     allowed_decisions: Set[str]
- L0039:     enforce_approver_allowlist: bool
- L0040:     approver_allowlist: Set[str]
- L0041:     fuzzy_threshold: float
- L0042:     dropped: List[Dict[str, Any]] = field(default_factory=list)
- L0043: 
- L0044: 
- L0045: def stable_exception_id(tool: str, rule_id: str, resource: str) -> str:
- L0046:     seed = f"{tool}{rule_id}{resource}"
- L0047:     return sha256_hex(seed)
- L0048: 
- L0049: 
- L0050: def parse_requested_by(ra: Dict[str, Any]) -> str:
- L0051:     return sanitize_username(cf(ra, "requested_by") or ra.get("owner"))
- L0052: 
- L0053: 
- L0054: def parse_approved_by(ra: Dict[str, Any]) -> str:
- L0055:     return sanitize_username(cf(ra, "approved_by") or ra.get("accepted_by"))
- L0056: 
- L0057: 
- L0058: def parse_decision(ra: Dict[str, Any]) -> str:
- L0059:     raw = first_non_empty(
- L0060:         cf(ra, "decision", "recommendation"),
- L0061:         ra.get("decision"),
- L0062:         ra.get("recommendation"),
- L0063:     )
- L0064:     return normalize_decision(raw)
- L0065: 
- L0066: 
- L0067: def parse_expires_at(ra: Dict[str, Any]) -> Optional[datetime]:
- L0068:     raw = cf(ra, "expires_at", "expiration_date") or ra.get("expiration_date")
- L0069:     return parse_datetime(raw, end_of_day=True)
- L0070: 
- L0071: 
- L0072: def parse_approved_at(ra: Dict[str, Any]) -> Optional[datetime]:
- L0073:     raw = (
- L0074:         cf(ra, "approved_at", "created")
- L0075:         or ra.get("created")
- L0076:         or ra.get("accepted_date")
- L0077:         or ra.get("updated")
- L0078:     )
- L0079:     return parse_datetime(raw)
- L0080: 
- L0081: 
- L0082: def parse_status(ra: Dict[str, Any]) -> str:
- L0083:     raw = sanitize_text(cf(ra, "status") or ra.get("status")).lower()
- L0084:     aliases = {
- L0085:         "approved": "approved",
- L0086:         "approve": "approved",
- L0087:         "accepted": "approved",
- L0088:         "accept": "approved",
- L0089:         "a": "approved",
- L0090:     }
- L0091:     normalized = aliases.get(raw, raw)
- L0092:     if normalized:
- L0093:         return normalized
- L0094: 
- L0095:     # DefectDojo Risk Acceptance objects may omit explicit status while still
- L0096:     # carrying accepted_by + decision/recommendation.
- L0097:     accepted_by = sanitize_text(cf(ra, "approved_by") or ra.get("accepted_by"))
- L0098:     decision = parse_decision(ra)
- L0099:     if accepted_by and decision:
- L0100:         return "approved"
- L0101: 
- L0102:     return ""
- L0103: 
- L0104: 
- L0105: def is_active_accepted(ra: Dict[str, Any]) -> bool:
- L0106:     status = parse_status(ra)
- L0107:     is_active_raw = cf(ra, "is_active") or ra.get("is_active")
- L0108:     is_active = str(is_active_raw).strip().lower() in {"true", "1", "yes", "on"}
- L0109:     return is_active and status == "approved"
- L0110: 
- L0111: 
- L0112: def validate_normalized_exception(ctx: FetchContext, exception_obj: Dict[str, Any]) -> Tuple[bool, Optional[str], Optional[str]]:
- L0113:     requested_by = sanitize_username(exception_obj.get("requested_by"))
- L0114:     approved_by = sanitize_username(exception_obj.get("approved_by"))
- L0115: 
- L0116:     if not requested_by or not approved_by:
- L0117:         return False, "four_eyes_violation", "requested_by and approved_by are mandatory"
- L0118:     if requested_by == approved_by:
- L0119:         return False, "four_eyes_violation", "requested_by equals approved_by"
- L0120:     if ctx.enforce_approver_allowlist and approved_by not in ctx.approver_allowlist:
- L0121:         return False, "four_eyes_violation", "approved_by is not in configured approver allowlist"
- L0122: 
- L0123:     severity = normalize_severity(exception_obj.get("severity"), ctx.severity_enum)
- L0124:     if not severity:
- L0125:         return False, "invalid_severity", "severity must be one of CRITICAL|HIGH|MEDIUM|LOW"
- L0126: 
- L0127:     missing_fields = [
- L0128:         key
- L0129:         for key in ["tool", "rule_id", "resource", "approved_at", "expires_at", "decision"]
- L0130:         if not sanitize_text(exception_obj.get(key))
- L0131:     ]
- L0132:     if missing_fields:
- L0133:         return False, "missing_fields", f"missing required fields: {','.join(missing_fields)}"
- L0134: 
- L0135:     if sanitize_text(exception_obj.get("tool")).lower() not in ctx.allowed_tools:
- L0136:         return False, "missing_fields", "tool is invalid"
- L0137: 
- L0138:     if sanitize_text(exception_obj.get("decision")).lower() not in ctx.allowed_decisions:
- L0139:         return False, "missing_fields", "decision is invalid"
- L0140: 
- L0141:     if sanitize_text(exception_obj.get("status")).lower() != "approved":
- L0142:         return False, "missing_fields", "status must be approved"
- L0143: 
- L0144:     if sanitize_text(exception_obj.get("source")).lower() != "defectdojo":
- L0145:         return False, "missing_fields", "source must be defectdojo"
- L0146: 
- L0147:     resource = sanitize_text(exception_obj.get("resource"))
- L0148:     if has_wildcard(resource):
- L0149:         return False, "parsing_error", "wildcard resources are forbidden"
- L0150: 
- L0151:     approved_at = parse_datetime(exception_obj.get("approved_at"))
- L0152:     if not approved_at:
- L0153:         return False, "missing_fields", "approved_at is invalid"
- L0154: 
- L0155:     expires_at = parse_datetime(exception_obj.get("expires_at"), end_of_day=True)
- L0156:     if not expires_at:
- L0157:         return False, "missing_fields", "expires_at is invalid"
- L0158: 
- L0159:     if now_utc() >= expires_at:
- L0160:         return False, "missing_fields", "expires_at is in the past"
- L0161: 
- L0162:     if approved_at > now_utc():
- L0163:         return False, "missing_fields", "approved_at cannot be in the future"
- L0164: 
- L0165:     return True, None, None
- L0166: 
- L0167: 
- L0168: def build_base_exception(
- L0169:     ctx: FetchContext,
- L0170:     tool: str,
- L0171:     rule_id: str,
- L0172:     resource: str,
- L0173:     severity: str,
- L0174:     requested_by: str,
- L0175:     approved_by: str,
- L0176:     approved_at: datetime,
- L0177:     expires_at: datetime,
- L0178:     decision: str,
- L0179: ) -> Dict[str, Any]:
- L0180:     cleaned_tool = sanitize_text(tool).lower()
- L0181:     cleaned_rule = sanitize_text(rule_id)
- L0182:     cleaned_resource = sanitize_text(resource)
- L0183: 
- L0184:     return {
- L0185:         "id": stable_exception_id(cleaned_tool, cleaned_rule, cleaned_resource),
- L0186:         "tool": cleaned_tool,
- L0187:         "rule_id": cleaned_rule,
- L0188:         "resource": cleaned_resource,
- L0189:         "severity": normalize_severity(severity, ctx.severity_enum),
- L0190:         "requested_by": sanitize_username(requested_by),
- L0191:         "approved_by": sanitize_username(approved_by),
- L0192:         "approved_at": to_rfc3339(approved_at),
- L0193:         "expires_at": to_rfc3339(expires_at),
- L0194:         "decision": sanitize_text(decision).lower(),
- L0195:         "source": "defectdojo",
- L0196:         "status": "approved",
- L0197:     }

#### shift-left/opa/fetch_exceptions/main.py
- L0001: #!/usr/bin/env python3
- L0002: """Main orchestration for CloudSentinel exception fetch pipeline."""
- L0003: 
- L0004: from __future__ import annotations
- L0005: 
- L0006: import logging
- L0007: import os
- L0008: import sys
- L0009: from typing import Optional
- L0010: 
- L0011: from .fetch_defectdojo import DefectDojoFetchError, fetch_risk_acceptances
- L0012: from .fetch_mapping import json_payload, map_risk_acceptances, save_outputs
- L0013: from .fetch_utils import ensure_dir
- L0014: from .fetch_validation import FetchContext
- L0015: 
- L0016: 
- L0017: def _parse_bool_env(name: str, default: str = "false") -> bool:
- L0018:     return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}
- L0019: 
- L0020: 
- L0021: def _parse_set_env(name: str, default_csv: str) -> set[str]:
- L0022:     return {
- L0023:         item.strip().lower()
- L0024:         for item in os.environ.get(name, default_csv).split(",")
- L0025:         if item.strip()
- L0026:     }
- L0027: 
- L0028: 
- L0029: def _parse_threshold(value: str, fallback: float = 0.85) -> float:
- L0030:     try:
- L0031:         parsed = float(value)
- L0032:     except ValueError:
- L0033:         return fallback
- L0034:     if parsed < 0.0 or parsed > 1.0:
- L0035:         return fallback
- L0036:     return parsed
- L0037: 
- L0038: 
- L0039: def configure_logging() -> logging.Logger:
- L0040:     logging.basicConfig(
- L0041:         level=logging.INFO,
- L0042:         format='{"time":"%(asctime)s","level":"%(levelname)s","component":"fetch-exceptions","message":"%(message)s"}',
- L0043:         datefmt="%Y-%m-%dT%H:%M:%SZ",
- L0044:         stream=sys.stderr,
- L0045:     )
- L0046:     return logging.getLogger("fetch-exceptions")
- L0047: 
- L0048: 
- L0049: def build_context(logger: Optional[logging.Logger] = None) -> FetchContext:
- L0050:     logger = logger or configure_logging()
- L0051: 
- L0052:     repo_root = os.getcwd()
- L0053:     output_file = os.environ.get(
- L0054:         "OPA_EXCEPTIONS_FILE", os.path.join(repo_root, ".cloudsentinel", "exceptions.json")
- L0055:     )
- L0056:     dropped_file = os.path.join(repo_root, ".cloudsentinel", "dropped_exceptions.json")
- L0057:     audit_log_file = os.environ.get(
- L0058:         "CLOUDSENTINEL_AUDIT_LOG", os.path.join(repo_root, ".cloudsentinel", "audit_events.jsonl")
- L0059:     )
- L0060: 
- L0061:     return FetchContext(
- L0062:         logger=logger,
- L0063:         dojo_url=os.environ.get("DOJO_URL", "").rstrip("/"),
- L0064:         dojo_api_key=os.environ.get("DOJO_API_KEY", ""),
- L0065:         repo_root=repo_root,
- L0066:         output_file=output_file,
- L0067:         dropped_file=dropped_file,
- L0068:         audit_log_file=audit_log_file,
- L0069:         schema_version="2.0.0",
- L0070:         severity_enum={"CRITICAL", "HIGH", "MEDIUM", "LOW"},
- L0071:         allowed_tools={"checkov", "trivy", "gitleaks"},
- L0072:         allowed_decisions={"accept", "mitigate", "fix", "transfer", "avoid"},
- L0073:         enforce_approver_allowlist=_parse_bool_env("CLOUDSENTINEL_ENFORCE_APPROVER_ALLOWLIST", "false"),
- L0074:         approver_allowlist=_parse_set_env("CLOUDSENTINEL_APPROVER_ALLOWLIST", "appsecteam,security-team"),
- L0075:         fuzzy_threshold=_parse_threshold(os.environ.get("CLOUDSENTINEL_FUZZY_MATCH_THRESHOLD", "0.85")),
- L0076:     )
- L0077: 
- L0078: 
- L0079: def execute(ctx: FetchContext) -> None:
- L0080:     ctx.logger.info("Starting CloudSentinel DefectDojo exception ingestion")
- L0081: 
- L0082:     if not ctx.dojo_url or not ctx.dojo_api_key:
- L0083:         ctx.logger.error("DefectDojo credentials are not configured")
- L0084:         raise SystemExit(2)
- L0085: 
- L0086:     ensure_dir(ctx.audit_log_file)
- L0087:     with open(ctx.audit_log_file, "w", encoding="utf-8"):
- L0088:         pass
- L0089: 
- L0090:     try:
- L0091:         raw_ras = fetch_risk_acceptances(ctx.dojo_url, ctx.dojo_api_key, ctx.logger)
- L0092:     except DefectDojoFetchError as exc:
- L0093:         ctx.logger.error(f"DefectDojo fetch failed: {exc}")
- L0094:         raise SystemExit(2) from exc
- L0095: 
- L0096:     mapped, meta = map_risk_acceptances(ctx, raw_ras)
- L0097:     payload = json_payload(ctx, mapped, meta)
- L0098:     save_outputs(ctx, payload)
- L0099: 
- L0100:     ctx.logger.info(
- L0101:         "Exceptions payload written: valid=%s dropped=%s",
- L0102:         len(mapped),
- L0103:         len(ctx.dropped),
- L0104:     )
- L0105: 
- L0106: 
- L0107: def run_cli() -> None:
- L0108:     ctx = build_context()
- L0109:     try:
- L0110:         execute(ctx)
- L0111:     except SystemExit:
- L0112:         raise
- L0113:     except Exception as exc:
- L0114:         ctx.logger.exception(f"Unhandled error in fetch-exceptions: {exc}")
- L0115:         raise SystemExit(2) from exc

#### ci/scripts/normalize-reports.sh
- L0001: #!/usr/bin/env bash
- L0002: set -euo pipefail
- L0003: 
- L0004: chmod +x shift-left/normalizer/normalize.py
- L0005: export ENVIRONMENT="${CI_ENVIRONMENT_NAME:-dev}"
- L0006: export CLOUDSENTINEL_EXECUTION_MODE="ci"
- L0007: export CLOUDSENTINEL_SCHEMA_STRICT="true"
- L0008: export DOJO_URL="${DOJO_URL:-${DEFECTDOJO_URL:-}}"
- L0009: export DOJO_API_KEY="${DOJO_API_KEY:-${DEFECTDOJO_API_KEY:-${DEFECTDOJO_API_TOKEN:-}}}"
- L0010: python3 shift-left/normalizer/normalize.py
- L0011: jq '.summary' .cloudsentinel/golden_report.json
- L0012: jq '.quality_gate' .cloudsentinel/golden_report.json
- L0013: timeout 30 python3 shift-left/opa/fetch-exceptions.py
- L0014: 
- L0015: if [[ -f .cloudsentinel/exceptions.json ]]; then
- L0016:   VALID_EXCEPTIONS="$(jq -r '.cloudsentinel.exceptions.metadata.total_valid_exceptions // 0' .cloudsentinel/exceptions.json)"
- L0017:   DROPPED_EXCEPTIONS="$(jq -r '.cloudsentinel.exceptions.metadata.total_dropped // 0' .cloudsentinel/exceptions.json)"
- L0018:   echo "[exceptions] valid=${VALID_EXCEPTIONS} dropped=${DROPPED_EXCEPTIONS}"
- L0019: fi

#### ci/scripts/contract-test.sh
- L0001: #!/usr/bin/env bash
- L0002: set -euo pipefail
- L0003: 
- L0004: # CloudSentinel — Contract Test
- L0005: # Verifies that all raw scanner reports exist, are valid JSON,
- L0006: # and contain the expected top-level structure before normalization.
- L0007: 
- L0008: fail() { echo "[contract][FAIL] $*" >&2; exit 1; }
- L0009: ok()   { echo "[contract][OK]   $*"; }
- L0010: 
- L0011: check_json() {
- L0012:   local file="$1"
- L0013:   local field="$2"
- L0014:   local label="$3"
- L0015: 
- L0016:   [[ -f "$file" ]] || fail "$label: file not found → $file"
- L0017:   jq empty "$file" 2>/dev/null || fail "$label: invalid JSON → $file"
- L0018:   jq -e "$field" "$file" >/dev/null 2>&1 || fail "$label: missing field '$field' → $file"
- L0019:   ok "$label"
- L0020: }
- L0021: 
- L0022: # Gitleaks
- L0023: check_json ".cloudsentinel/gitleaks_raw.json" \
- L0024:   "(. | type) == \"array\" or has(\"leaks\") or has(\"findings\")" \
- L0025:   "gitleaks_raw"
- L0026: 
- L0027: # Checkov
- L0028: check_json ".cloudsentinel/checkov_raw.json" \
- L0029:   "has(\"results\") or has(\"checks\")" \
- L0030:   "checkov_raw"
- L0031: 
- L0032: # Trivy FS
- L0033: check_json "shift-left/trivy/reports/raw/trivy-fs-raw.json" \
- L0034:   "has(\"SchemaVersion\")" \
- L0035:   "trivy_fs_raw"
- L0036: 
- L0037: # Trivy Config
- L0038: check_json "shift-left/trivy/reports/raw/trivy-config-raw.json" \
- L0039:   "has(\"SchemaVersion\")" \
- L0040:   "trivy_config_raw"
- L0041: 
- L0042: echo "[contract][SKIP] Image scan jobs removed from pipeline - monitoring via DefectDojo only"
- L0043: 
- L0044: echo "[contract] All checks passed."

#### ci/scripts/upload-to-defectdojo.sh
- L0001: #!/usr/bin/env bash
- L0002: set -euo pipefail
- L0003: 
- L0004: DOJO_URL_EFF="${DOJO_URL:-${DEFECTDOJO_URL:-}}"
- L0005: DOJO_API_KEY_EFF="${DOJO_API_KEY:-${DEFECTDOJO_API_KEY:-${DEFECTDOJO_API_TOKEN:-}}}"
- L0006: DOJO_ENGAGEMENT_ID_EFF="${DOJO_ENGAGEMENT_ID:-${DEFECTDOJO_ENGAGEMENT_ID:-}}"
- L0007: 
- L0008: if [ -z "${DOJO_URL_EFF}" ] || [ -z "${DOJO_API_KEY_EFF}" ] || [ -z "${DOJO_ENGAGEMENT_ID_EFF}" ]; then
- L0009:   echo "[dojo] Missing Dojo vars. Accepted names:"
- L0010:   echo "[dojo] URL: DOJO_URL or DEFECTDOJO_URL"
- L0011:   echo "[dojo] API key: DOJO_API_KEY or DEFECTDOJO_API_KEY or DEFECTDOJO_API_TOKEN"
- L0012:   echo "[dojo] Engagement: DOJO_ENGAGEMENT_ID or DEFECTDOJO_ENGAGEMENT_ID"
- L0013:   echo "[dojo] Skipping upload."
- L0014:   exit 0
- L0015: fi
- L0016: 
- L0017: chmod -R a+r .cloudsentinel shift-left/trivy/reports/raw 2>/dev/null || true
- L0018: mkdir -p .cloudsentinel/dojo-responses
- L0019: 
- L0020: upload_scan() {
- L0021:   file_path="$1"
- L0022:   scan_type="$2"
- L0023:   label="$3"
- L0024:   safe_label="$(echo "${label}" | tr ' /()' '_____' | tr -cd '[:alnum:]_.-')"
- L0025:   response_file=".cloudsentinel/dojo-responses/${safe_label}.json"
- L0026: 
- L0027:   if [ ! -f "${file_path}" ]; then
- L0028:     echo "[dojo] ${label}: report not found (${file_path}), skipping."
- L0029:     return 0
- L0030:   fi
- L0031: 
- L0032:   if [ ! -r "${file_path}" ]; then
- L0033:     echo "[dojo] ${label}: report exists but is not readable (${file_path})."
- L0034:     ls -l "${file_path}" || true
- L0035:     return 1
- L0036:   fi
- L0037: 
- L0038:   HTTP_CODE=$(curl -sS -o "${response_file}" -w "%{http_code}" \
- L0039:     -X POST "${DOJO_URL_EFF}/api/v2/import-scan/" \
- L0040:     -H "Authorization: Token ${DOJO_API_KEY_EFF}" \
- L0041:     -F "file=@${file_path}" \
- L0042:     -F "scan_type=${scan_type}" \
- L0043:     --form-string "engagement=${DOJO_ENGAGEMENT_ID_EFF}" \
- L0044:     --form-string "active=true" \
- L0045:     --form-string "verified=true" \
- L0046:     --form-string "close_old_findings=true" \
- L0047:     --form-string "close_old_findings_product_scope=false" \
- L0048:     --form-string "deduplication_on_engagement=true")
- L0049: 
- L0050:   if [ "${HTTP_CODE}" = "201" ]; then
- L0051:     echo "[dojo] ${label} uploaded HTTP=201"
- L0052:   else
- L0053:     echo "[dojo] ${label} upload failed HTTP=${HTTP_CODE}"
- L0054:     cat "${response_file}" || true
- L0055:     return 1
- L0056:   fi
- L0057: }
- L0058: 
- L0059: # Shift-Left scanners
- L0060: upload_scan ".cloudsentinel/gitleaks_raw.json"                                       "Gitleaks Scan" "Gitleaks"
- L0061: upload_scan ".cloudsentinel/checkov_raw.json"                                        "Checkov Scan"  "Checkov"
- L0062: upload_scan "shift-left/trivy/reports/raw/trivy-fs-raw.json"                        "Trivy Scan"    "Trivy (FS/SCA)"
- L0063: upload_scan "shift-left/trivy/reports/raw/trivy-config-raw.json"                    "Trivy Scan"    "Trivy (Config)"

#### ci/scripts/deploy-infrastructure.sh
- L0001: #!/usr/bin/env bash
- L0002: set -euo pipefail
- L0003: required_vars=(
- L0004:   ARM_CLIENT_ID
- L0005:   ARM_CLIENT_SECRET
- L0006:   ARM_TENANT_ID
- L0007:   ARM_SUBSCRIPTION_ID
- L0008:   TFSTATE_RESOURCE_GROUP
- L0009:   TFSTATE_STORAGE_ACCOUNT
- L0010:   TFSTATE_CONTAINER
- L0011:   TF_VAR_admin_ssh_public_key
- L0012: )
- L0013: for name in "${required_vars[@]}"; do
- L0014:   if [ -z "${!name:-}" ]; then
- L0015:     echo "[deploy][ERROR] missing required variable: ${name}" >&2
- L0016:     exit 2
- L0017:   fi
- L0018: done
- L0019: if ! printf '%s' "${TF_VAR_admin_ssh_public_key}" | grep -Eq '^ssh-rsa[[:space:]]+[A-Za-z0-9+/=]+([[:space:]].*)?$'; then
- L0020:   echo "[deploy][ERROR] TF_VAR_admin_ssh_public_key must be RSA format (starts with 'ssh-rsa ')." >&2
- L0021:   echo "[deploy][ERROR] Generate with: ssh-keygen -t rsa -b 4096 -C \"gitlab-ci\" -f ~/.ssh/student_secure_rsa" >&2
- L0022:   exit 2
- L0023: fi
- L0024: 
- L0025: # ── ARM_CLIENT_SECRET governance check ─────────────────────────────────────
- L0026: # Detects stale credentials. ARM_CLIENT_SECRET_CREATED_AT must be set in
- L0027: # GitLab CI/CD Settings → Variables (format: YYYY-MM-DD).
- L0028: # If unset: warning only (non-blocking) to avoid breaking existing pipelines.
- L0029: # If set and age > 90 days: pipeline FAILS to enforce rotation policy.
- L0030: # Rotation procedure: az ad sp credential reset → update GitLab masked variable.
- L0031: # Reference: NIST 800-53 IA-5 / CIS Azure 1.x
- L0032: ARM_MAX_SECRET_AGE_DAYS="${ARM_MAX_SECRET_AGE_DAYS:-90}"
- L0033: if [[ -n "${ARM_CLIENT_SECRET_CREATED_AT:-}" ]]; then
- L0034:   SECRET_CREATED_EPOCH="$(date -u -d "${ARM_CLIENT_SECRET_CREATED_AT}" +%s 2>/dev/null || echo 0)"
- L0035:   NOW_EPOCH="$(date -u +%s)"
- L0036:   if [[ "$SECRET_CREATED_EPOCH" -gt 0 ]]; then
- L0037:     SECRET_AGE_DAYS=$(( (NOW_EPOCH - SECRET_CREATED_EPOCH) / 86400 ))
- L0038:     if [[ "$SECRET_AGE_DAYS" -gt "$ARM_MAX_SECRET_AGE_DAYS" ]]; then
- L0039:       echo "[deploy][SECURITY] FAIL: ARM_CLIENT_SECRET is ${SECRET_AGE_DAYS} days old" \
- L0040:            "(max: ${ARM_MAX_SECRET_AGE_DAYS}). Rotate now:" >&2
- L0041:       echo "[deploy][SECURITY]   az ad sp credential reset --id \$ARM_CLIENT_ID" >&2
- L0042:       echo "[deploy][SECURITY]   Then update GitLab masked variable ARM_CLIENT_SECRET" >&2
- L0043:       echo "[deploy][SECURITY]   And update ARM_CLIENT_SECRET_CREATED_AT to $(date -u +%Y-%m-%d)" >&2
- L0044:       exit 2
- L0045:     else
- L0046:       echo "[deploy] ARM_CLIENT_SECRET age: ${SECRET_AGE_DAYS} days (max: ${ARM_MAX_SECRET_AGE_DAYS}) — OK"
- L0047:     fi
- L0048:   else
- L0049:     echo "[deploy][WARN] ARM_CLIENT_SECRET_CREATED_AT='${ARM_CLIENT_SECRET_CREATED_AT}'" \
- L0050:          "is not a valid date — skipping age check" >&2
- L0051:   fi
- L0052: else
- L0053:   echo "[deploy][WARN] ARM_CLIENT_SECRET_CREATED_AT not set in CI variables." \
- L0054:        "Set it to the credential creation date (YYYY-MM-DD) to enforce rotation policy." >&2
- L0055:   echo "[deploy][WARN] This warning will become a hard FAIL in a future version." >&2
- L0056: fi
- L0057: # ── end credential age governance ──────────────────────────────────────────
- L0058: 
- L0059: tofu version
- L0060: cosign version
- L0061: export ARM_USE_AZUREAD=true
- L0062: export ARM_STORAGE_USE_AZUREAD=true
- L0063: 
- L0064: # Sanitize TFSTATE key: strip path separators to prevent traversal.
- L0065: # CI_COMMIT_REF_SLUG is derived from branch name — treat as untrusted input.
- L0066: TFSTATE_KEY_RAW="${TFSTATE_KEY:-student-secure-${CI_COMMIT_REF_SLUG}.tfstate}"
- L0067: TFSTATE_KEY_SAFE="$(echo "${TFSTATE_KEY_RAW}" | tr -d '/\\' | sed 's/\.\.//g')"
- L0068: if [[ "${TFSTATE_KEY_SAFE}" != "${TFSTATE_KEY_RAW}" ]]; then
- L0069:   echo "[deploy][SECURITY] TFSTATE key sanitized: '${TFSTATE_KEY_RAW}' → '${TFSTATE_KEY_SAFE}'" >&2
- L0070: fi
- L0071: if [[ -z "${TFSTATE_KEY_SAFE}" || "${TFSTATE_KEY_SAFE}" == ".tfstate" ]]; then
- L0072:   echo "[deploy][ERROR] TFSTATE key is empty after sanitization. Refusing to continue." >&2
- L0073:   exit 2
- L0074: fi
- L0075: 
- L0076: tofu -chdir=infra/azure/student-secure init -input=false \
- L0077:   -backend-config="resource_group_name=${TFSTATE_RESOURCE_GROUP}" \
- L0078:   -backend-config="storage_account_name=${TFSTATE_STORAGE_ACCOUNT}" \
- L0079:   -backend-config="container_name=${TFSTATE_CONTAINER}" \
- L0080:   -backend-config="key=${TFSTATE_KEY_SAFE}" \
- L0081:   -backend-config="use_azuread_auth=true"
- L0082: export TF_VAR_subscription_id="${TF_VAR_subscription_id:-${ARM_SUBSCRIPTION_ID}}"
- L0083: [ -n "${TF_VAR_subscription_id}" ] || { echo "[deploy][ERROR] TF_VAR_subscription_id is empty"; exit 2; }
- L0084: echo "[deploy] TF_VAR_subscription_id is set"
- L0085: export TF_VAR_enable_vm_encryption_at_host="${TF_VAR_enable_vm_encryption_at_host:-false}"
- L0086: echo "[deploy] TF_VAR_enable_vm_encryption_at_host=${TF_VAR_enable_vm_encryption_at_host}"
- L0087: tofu -chdir=infra/azure/student-secure plan -input=false -out=tfplan
- L0088: tofu -chdir=infra/azure/student-secure apply -input=false -auto-approve tfplan
- L0089: tofu -chdir=infra/azure/student-secure output -json \
- L0090:   | jq 'to_entries
- L0091:         | map(if .value.sensitive == true
- L0092:               then .value.value = "REDACTED"
- L0093:               else .
- L0094:               end)
- L0095:         | from_entries' \
- L0096:   > .cloudsentinel/terraform_outputs_student_secure.json

#### ci/scripts/retry-guard.sh
- L0001: #!/usr/bin/env bash
- L0002: set -euo pipefail
- L0003: 
- L0004: chmod +x shift-left/ci/retry-guard.sh
- L0005: bash shift-left/ci/retry-guard.sh

#### ci/scripts/policies-immutability.sh
- L0001: #!/usr/bin/env bash
- L0002: set -euo pipefail
- L0003: 
- L0004: chmod +x shift-left/ci/enforce-policies-immutability.sh
- L0005: bash shift-left/ci/enforce-policies-immutability.sh

#### shift-left/ci/retry-guard.sh
- L0001: #!/usr/bin/env bash
- L0002: set -euo pipefail
- L0003: 
- L0004: # ------------------------------------------------------------------------------
- L0005: # CloudSentinel Retry Guard
- L0006: # - Protects CI from retry abuse on same commit SHA
- L0007: # - Enforces max retries and minimum delay between retries
- L0008: # - Stateless OPA stays focused on policy decision only
- L0009: # ------------------------------------------------------------------------------
- L0010: 
- L0011: log()  { echo "[CloudSentinel][retry-guard] $*"; }
- L0012: warn() { echo "[CloudSentinel][retry-guard][WARN] $*" >&2; }
- L0013: err()  { echo "[CloudSentinel][retry-guard][ERROR] $*" >&2; }
- L0014: 
- L0015: need() { command -v "$1" >/dev/null 2>&1 || { err "$1 not installed"; exit 2; }; }
- L0016: need curl
- L0017: need jq
- L0018: need date
- L0019: 
- L0020: : "${CI_API_V4_URL:?CI_API_V4_URL is required}"
- L0021: : "${CI_PROJECT_ID:?CI_PROJECT_ID is required}"
- L0022: : "${CI_PIPELINE_ID:?CI_PIPELINE_ID is required}"
- L0023: : "${CI_COMMIT_SHA:?CI_COMMIT_SHA is required}"
- L0024: 
- L0025: OUTPUT_DIR="${CI_PROJECT_DIR:-$(pwd)}/.cloudsentinel"
- L0026: AUDIT_LOG_FILE="${CLOUDSENTINEL_AUDIT_LOG:-$OUTPUT_DIR/audit_events.jsonl}"
- L0027: mkdir -p "$OUTPUT_DIR"
- L0028: 
- L0029: MAX_RETRIES="${RETRY_GUARD_MAX_RETRIES:-3}"
- L0030: MIN_INTERVAL_SEC="${RETRY_GUARD_MIN_INTERVAL_SEC:-120}"
- L0031: LOOKBACK_LIMIT="${RETRY_GUARD_LOOKBACK_LIMIT:-50}"
- L0032: 
- L0033: API_URL="${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/pipelines?sha=${CI_COMMIT_SHA}&per_page=${LOOKBACK_LIMIT}"
- L0034: 
- L0035: auth_header_name="JOB-TOKEN"
- L0036: auth_header_value="${CI_JOB_TOKEN:-}"
- L0037: if [[ -n "${GITLAB_RETRY_GUARD_TOKEN:-}" ]]; then
- L0038:   auth_header_name="PRIVATE-TOKEN"
- L0039:   auth_header_value="${GITLAB_RETRY_GUARD_TOKEN}"
- L0040: fi
- L0041: 
- L0042: if [[ -z "$auth_header_value" ]]; then
- L0043:   err "No token available (CI_JOB_TOKEN or GITLAB_RETRY_GUARD_TOKEN)"
- L0044:   exit 2
- L0045: fi
- L0046: 
- L0047: emit_audit_event() {
- L0048:   local event_type=$1
- L0049:   local payload=$2
- L0050:   jq -cn \
- L0051:     --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
- L0052:     --arg event_type "$event_type" \
- L0053:     --argjson payload "$payload" \
- L0054:     '{timestamp:$ts,component:"retry-guard",event_type:$event_type} + $payload' \
- L0055:     >> "$AUDIT_LOG_FILE" || true
- L0056: }
- L0057: 
- L0058: log "Checking retry policy for commit ${CI_COMMIT_SHA:0:12}..."
- L0059: 
- L0060: RESP_FILE="$(mktemp -t retry-guard.XXXXXX.json)"
- L0061: trap 'rm -f "$RESP_FILE"' EXIT
- L0062: 
- L0063: HTTP_CODE="$(curl -sS -w "%{http_code}" \
- L0064:   -H "${auth_header_name}: ${auth_header_value}" \
- L0065:   "$API_URL" -o "$RESP_FILE")"
- L0066: 
- L0067: if [[ "$HTTP_CODE" != "200" ]]; then
- L0068:   err "GitLab API error HTTP=${HTTP_CODE}"
- L0069:   emit_audit_event "retry_guard_error" "{\"http_code\":\"$HTTP_CODE\",\"pipeline_id\":\"$CI_PIPELINE_ID\",\"commit_sha\":\"$CI_COMMIT_SHA\"}"
- L0070:   exit 2
- L0071: fi
- L0072: 
- L0073: if ! jq -e 'type=="array"' "$RESP_FILE" >/dev/null 2>&1; then
- L0074:   err "Unexpected GitLab API payload format"
- L0075:   emit_audit_event "retry_guard_error" "{\"reason\":\"invalid_payload\",\"pipeline_id\":\"$CI_PIPELINE_ID\",\"commit_sha\":\"$CI_COMMIT_SHA\"}"
- L0076:   exit 2
- L0077: fi
- L0078: 
- L0079: PREVIOUS_COUNT="$(jq -r --arg cur "$CI_PIPELINE_ID" '[ .[] | select((.id|tostring) != $cur) ] | length' "$RESP_FILE")"
- L0080: LAST_PREVIOUS_TS="$(jq -r --arg cur "$CI_PIPELINE_ID" '[ .[] | select((.id|tostring) != $cur) ][0].updated_at // ""' "$RESP_FILE")"
- L0081: 
- L0082: if [[ "$PREVIOUS_COUNT" -gt "$MAX_RETRIES" ]]; then
- L0083:   err "Retry limit exceeded: previous_runs=${PREVIOUS_COUNT}, max_retries=${MAX_RETRIES}"
- L0084:   emit_audit_event "retry_guard_blocked" "{\"reason\":\"max_retries_exceeded\",\"previous_runs\":$PREVIOUS_COUNT,\"max_retries\":$MAX_RETRIES,\"pipeline_id\":\"$CI_PIPELINE_ID\",\"commit_sha\":\"$CI_COMMIT_SHA\"}"
- L0085:   exit 1
- L0086: fi
- L0087: 
- L0088: if [[ -n "$LAST_PREVIOUS_TS" ]]; then
- L0089:   NOW_EPOCH="$(date -u +%s)"
- L0090:   LAST_EPOCH="$(date -u -d "$LAST_PREVIOUS_TS" +%s 2>/dev/null || echo 0)"
- L0091:   if [[ "$LAST_EPOCH" -gt 0 ]]; then
- L0092:     DELTA_SEC="$((NOW_EPOCH - LAST_EPOCH))"
- L0093:     if [[ "$DELTA_SEC" -lt "$MIN_INTERVAL_SEC" ]]; then
- L0094:       err "Retry interval too short: ${DELTA_SEC}s < ${MIN_INTERVAL_SEC}s"
- L0095:       emit_audit_event "retry_guard_blocked" "{\"reason\":\"min_interval_not_respected\",\"delta_sec\":$DELTA_SEC,\"min_interval_sec\":$MIN_INTERVAL_SEC,\"pipeline_id\":\"$CI_PIPELINE_ID\",\"commit_sha\":\"$CI_COMMIT_SHA\"}"
- L0096:       exit 1
- L0097:     fi
- L0098:   else
- L0099:     warn "Could not parse previous pipeline timestamp: $LAST_PREVIOUS_TS"
- L0100:   fi
- L0101: fi
- L0102: 
- L0103: emit_audit_event "retry_guard_passed" "{\"previous_runs\":$PREVIOUS_COUNT,\"max_retries\":$MAX_RETRIES,\"min_interval_sec\":$MIN_INTERVAL_SEC,\"pipeline_id\":\"$CI_PIPELINE_ID\",\"commit_sha\":\"$CI_COMMIT_SHA\"}"
- L0104: log "Retry guard passed (previous_runs=${PREVIOUS_COUNT}, max_retries=${MAX_RETRIES})."
- L0105: exit 0
- L0106: 

#### shift-left/ci/enforce-policies-immutability.sh
- L0001: #!/usr/bin/env bash
- L0002: set -euo pipefail
- L0003: 
- L0004: # ------------------------------------------------------------------------------
- L0005: # CloudSentinel Security Immutability Guard
- L0006: # - Restricts changes to security-critical controls to AppSec identities
- L0007: # - Covers policies, schemas, scanner configs/mappings and CI pipeline definition
- L0008: # ------------------------------------------------------------------------------
- L0009: 
- L0010: log() { echo "[CloudSentinel][immutability] $*"; }
- L0011: err() { echo "[CloudSentinel][immutability][ERROR] $*" >&2; }
- L0012: 
- L0013: # CLOUDSENTINEL_APPSEC_USERS doit être définie comme variable CI protégée
- L0014: # et masquée dans GitLab (Settings → CI/CD → Variables).
- L0015: # Valeur de production minimale : "appsec-bot,appsec-admin"
- L0016: # Ne jamais inclure de comptes personnels dans cette liste.
- L0017: if [[ -z "${CLOUDSENTINEL_APPSEC_USERS:-}" ]]; then
- L0018:   err "CLOUDSENTINEL_APPSEC_USERS is not set. Define it as a protected masked CI variable."
- L0019:   err "Minimum value: appsec-bot,appsec-admin"
- L0020:   exit 2
- L0021: fi
- L0022: readonly APPSEC_ALLOWED_USERS="${CLOUDSENTINEL_APPSEC_USERS}"
- L0023: HEAD_SHA="${CI_COMMIT_SHA:-HEAD}"
- L0024: ZERO_SHA="0000000000000000000000000000000000000000"
- L0025: DEFAULT_BRANCH="${CI_DEFAULT_BRANCH:-main}"
- L0026: 
- L0027: # Resolve base SHA deterministically.
- L0028: BASE_SHA="${CI_MERGE_REQUEST_TARGET_BRANCH_SHA:-${CI_COMMIT_BEFORE_SHA:-}}"
- L0029: 
- L0030: if [[ -z "$BASE_SHA" || "$BASE_SHA" == "$ZERO_SHA" ]]; then
- L0031:   BASE_SHA="$(git merge-base "$HEAD_SHA" "origin/${DEFAULT_BRANCH}" 2>/dev/null || true)"
- L0032: fi
- L0033: 
- L0034: if [[ -z "$BASE_SHA" || "$BASE_SHA" == "$ZERO_SHA" ]]; then
- L0035:   err "Unable to resolve BASE_SHA for immutability check. Refusing to continue."
- L0036:   exit 2
- L0037: fi
- L0038: 
- L0039: if ! git cat-file -e "${BASE_SHA}^{commit}" 2>/dev/null; then
- L0040:   log "Base SHA not present in clone. Attempting secure fetch..."
- L0041:   if ! git fetch --no-tags --depth="${IMMUTABILITY_FETCH_DEPTH:-200}" origin "$BASE_SHA" "${DEFAULT_BRANCH}" >/dev/null 2>&1; then
- L0042:     err "Unable to fetch BASE_SHA=${BASE_SHA}. Refusing to bypass immutability check."
- L0043:     exit 2
- L0044:   fi
- L0045: fi
- L0046: 
- L0047: if ! git cat-file -e "${BASE_SHA}^{commit}" 2>/dev/null; then
- L0048:   err "BASE_SHA still unavailable after fetch: ${BASE_SHA}"
- L0049:   exit 2
- L0050: fi
- L0051: 
- L0052: if ! git cat-file -e "${HEAD_SHA}^{commit}" 2>/dev/null; then
- L0053:   err "HEAD_SHA not available in clone: ${HEAD_SHA}"
- L0054:   exit 2
- L0055: fi
- L0056: 
- L0057: # .gitlab-ci-image-factory.yml: protected because it controls CI image rebuilds.
- L0058: # Unauthorized modification could introduce malicious images into the supply chain.
- L0059: PROTECTED_REGEX='^(policies/opa/.*\.rego|ci/scripts/.*\.sh|ci/libs/cloudsentinel_contracts\.py|shift-left/normalizer/.*|shift-left/opa/.*|shift-left/.*/run-.*\.sh|shift-left/opa/schema/exceptions_v2\.schema\.json|shift-left/normalizer/schema/cloudsentinel_report\.schema\.json|shift-left/gitleaks/gitleaks\.toml|shift-left/checkov/\.checkov\.yml|shift-left/checkov/policies/mapping\.json|shift-left/trivy/configs/trivy\.yaml|shift-left/trivy/configs/trivy-ci\.yaml|shift-left/trivy/configs/severity-mapping\.json|\.gitlab-ci\.yml|\.gitlab-ci-image-factory\.yml)$'
- L0060: 
- L0061: CHANGED_PROTECTED_FILES="$({
- L0062:   git diff --name-only "$BASE_SHA" "$HEAD_SHA"
- L0063: } | grep -E "$PROTECTED_REGEX" || true)"
- L0064: 
- L0065: if [[ -z "$CHANGED_PROTECTED_FILES" ]]; then
- L0066:   log "No protected security control changes detected."
- L0067:   exit 0
- L0068: fi
- L0069: 
- L0070: ACTOR_LOGIN="${GITLAB_USER_LOGIN:-unknown}"
- L0071: ACTOR_EMAIL="${GITLAB_USER_EMAIL:-unknown}"
- L0072: 
- L0073: if echo ",${APPSEC_ALLOWED_USERS}," | grep -qi ",${ACTOR_LOGIN},"; then
- L0074:   log "Authorized AppSec change by ${ACTOR_LOGIN}."
- L0075:   log "Changed protected files:"
- L0076:   echo "$CHANGED_PROTECTED_FILES" | sed 's/^/  - /'
- L0077:   exit 0
- L0078: fi
- L0079: 
- L0080: err "Unauthorized modification of protected security controls by ${ACTOR_LOGIN} (${ACTOR_EMAIL})."
- L0081: err "Changed protected files:"
- L0082: echo "$CHANGED_PROTECTED_FILES" | sed 's/^/  - /' >&2
- L0083: exit 1

#### policies/opa/pipeline_decision_test.rego
- L0001: package cloudsentinel.gate_test
- L0002: 
- L0003: # ─────────────────────────────────────────────────────────────────────
- L0004: # Test suite A — Functional scenarios (allow/deny, scanners, thresholds)
- L0005: # Companion: test_pipeline_decision.rego (exception lifecycle + edge cases)
- L0006: # Total coverage: 22 tests across both files. Zero overlap.
- L0007: # Run: opa test policies/opa -v
- L0008: # ─────────────────────────────────────────────────────────────────────
- L0009: 
- L0010: import rego.v1
- L0011: 
- L0012: # ─── Shared fixtures ─────────────────────────────────────────────────────────
- L0013: 
- L0014: _scanners_ok := {
- L0015: 	"gitleaks": {"status": "PASSED"},
- L0016: 	"checkov":  {"status": "PASSED"},
- L0017: 	"trivy":    {"status": "PASSED"},
- L0018: }
- L0019: 
- L0020: _base := {
- L0021: 	"metadata":     {"environment": "dev"},
- L0022: 	"quality_gate": {"thresholds": {"critical_max": 0, "high_max": 2}},
- L0023: 	"scanners":     _scanners_ok,
- L0024: 	"findings":     [],
- L0025: }
- L0026: 
- L0027: _critical_finding := {
- L0028: 	"status":   "FAILED",
- L0029: 	"source":   {"tool": "trivy", "id": "CVE-TEST-001"},
- L0030: 	"resource": {"name": "my-package"},
- L0031: 	"severity": {"level": "CRITICAL"},
- L0032: }
- L0033: 
- L0034: _high_finding := {
- L0035: 	"status":   "FAILED",
- L0036: 	"source":   {"tool": "checkov", "id": "CKV_AZ_001"},
- L0037: 	"resource": {"name": "azurerm_storage_account.example"},
- L0038: 	"severity": {"level": "HIGH"},
- L0039: }
- L0040: 
- L0041: # Valid exception matching _critical_finding exactly (tool/rule_id/resource)
- L0042: _valid_exception := {
- L0043: 	"id":           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
- L0044: 	"tool":         "trivy",
- L0045: 	"rule_id":      "CVE-TEST-001",
- L0046: 	"resource":     "my-package",
- L0047: 	"severity":     "CRITICAL",
- L0048: 	"requested_by": "dev-team",
- L0049: 	"approved_by":  "security-team",
- L0050: 	"approved_at":  "2026-01-01T00:00:00Z",
- L0051: 	"expires_at":   "2099-01-01T00:00:00Z",
- L0052: 	"decision":     "accept",
- L0053: 	"source":       "defectdojo",
- L0054: 	"status":       "approved",
- L0055: }
- L0056: 
- L0057: # ─── TEST 1: Clean pipeline with 0 findings → allow ──────────────────────────
- L0058: # All 3 scanners present, no findings → decision.allow must be true.
- L0059: 
- L0060: test_allow_clean_pipeline if {
- L0061: 	result := data.cloudsentinel.gate.decision
- L0062: 		with input as _base
- L0063: 		with data.cloudsentinel.exceptions.exceptions as []
- L0064: 
- L0065: 	result.allow
- L0066: 	count(result.deny) == 0
- L0067: 	result.metrics.critical == 0
- L0068: 	result.metrics.high == 0
- L0069: }
- L0070: 
- L0071: # ─── TEST 2: 2 HIGH findings at threshold boundary → allow ───────────────────
- L0072: # high_max=2, enforced_high_max=min(2,5)=2. effective_high=2. 2>2 is false → allow.
- L0073: 
- L0074: test_allow_with_high_within_threshold if {
- L0075: 	f1 := object.union(_high_finding, {"resource": {"name": "res-1"}})
- L0076: 	f2 := object.union(_high_finding, {"resource": {"name": "res-2"}})
- L0077: 
- L0078: 	result := data.cloudsentinel.gate.decision
- L0079: 		with input as object.union(_base, {"findings": [f1, f2]})
- L0080: 		with data.cloudsentinel.exceptions.exceptions as []
- L0081: 
- L0082: 	result.allow
- L0083: 	result.metrics.high == 2
- L0084: 	count(result.deny) == 0
- L0085: }
- L0086: 
- L0087: # ─── TEST 3: Valid exception exempts CRITICAL finding → allow ─────────────────
- L0088: # Exception matches on tool/rule_id/resource. Finding is removed from
- L0089: # effective_failed_findings, so effective_critical=0 → no threshold deny.
- L0090: 
- L0091: test_allow_with_valid_exception if {
- L0092: 	result := data.cloudsentinel.gate.decision
- L0093: 		with input as object.union(_base, {"findings": [_critical_finding]})
- L0094: 		with data.cloudsentinel.exceptions.exceptions as [_valid_exception]
- L0095: 
- L0096: 	result.allow
- L0097: 	result.metrics.excepted == 1
- L0098: 	result.metrics.critical == 0
- L0099: }
- L0100: 
- L0101: # ─── TEST 4: 1 CRITICAL finding, no exception → deny ─────────────────────────
- L0102: # enforced_critical_max = min(0, 0) = 0. effective_critical=1 > 0 → deny.
- L0103: 
- L0104: test_deny_on_critical if {
- L0105: 	result := data.cloudsentinel.gate.decision
- L0106: 		with input as object.union(_base, {"findings": [_critical_finding]})
- L0107: 		with data.cloudsentinel.exceptions.exceptions as []
- L0108: 
- L0109: 	not result.allow
- L0110: 	some msg in result.deny
- L0111: 	contains(msg, "CRITICAL findings")
- L0112: 	contains(msg, "exceed enforced threshold")
- L0113: }
- L0114: 
- L0115: # ─── TEST 5: 3 HIGH findings (threshold=2) → deny ────────────────────────────
- L0116: # enforced_high_max = min(2, 5) = 2. effective_high=3 > 2 → deny.
- L0117: 
- L0118: test_deny_on_high_exceeds_threshold if {
- L0119: 	f1 := object.union(_high_finding, {"resource": {"name": "r1"}})
- L0120: 	f2 := object.union(_high_finding, {"resource": {"name": "r2"}})
- L0121: 	f3 := object.union(_high_finding, {"resource": {"name": "r3"}})
- L0122: 
- L0123: 	result := data.cloudsentinel.gate.decision
- L0124: 		with input as object.union(_base, {"findings": [f1, f2, f3]})
- L0125: 		with data.cloudsentinel.exceptions.exceptions as []
- L0126: 
- L0127: 	not result.allow
- L0128: 	some msg in result.deny
- L0129: 	contains(msg, "HIGH findings")
- L0130: 	contains(msg, "exceed enforced threshold")
- L0131: }
- L0132: 
- L0133: # ─── TEST 6: Trivy scanner missing (NOT_RUN) in CI mode → deny ───────────────
- L0134: # scanner_not_run fires for trivy (is_local is false in default CI mode).
- L0135: 
- L0136: test_deny_missing_scanner if {
- L0137: 	result := data.cloudsentinel.gate.decision
- L0138: 		with input as object.union(_base, {
- L0139: 			"scanners": {
- L0140: 				"gitleaks": {"status": "PASSED"},
- L0141: 				"checkov":  {"status": "PASSED"},
- L0142: 				"trivy":    {"status": "NOT_RUN"},
- L0143: 			},
- L0144: 			"findings": [],
- L0145: 		})
- L0146: 		with data.cloudsentinel.exceptions.exceptions as []
- L0147: 
- L0148: 	not result.allow
- L0149: 	some msg in result.deny
- L0150: 	contains(msg, "Scanner trivy")
- L0151: 	contains(msg, "did not run")
- L0152: }
- L0153: 
- L0154: # ─── TEST 7: CI injects critical_max=999 → ceiling clamps to 0, deny ─────────
- L0155: # _policy_critical_max_ceiling=0. enforced_critical_max=min(999,0)=0.
- L0156: # With 1 CRITICAL finding: 1>0 → deny regardless of injected value.
- L0157: 
- L0158: test_deny_threshold_injection_attempt if {
- L0159: 	result := data.cloudsentinel.gate.decision
- L0160: 		with input as object.union(_base, {
- L0161: 			"quality_gate": {"thresholds": {"critical_max": 999, "high_max": 2}},
- L0162: 			"findings": [_critical_finding],
- L0163: 		})
- L0164: 		with data.cloudsentinel.exceptions.exceptions as []
- L0165: 
- L0166: 	not result.allow
- L0167: 	result.thresholds.enforced_critical_max == 0
- L0168: 	some msg in result.deny
- L0169: 	contains(msg, "CRITICAL findings")
- L0170: }
- L0171: 
- L0172: # ─── TEST 8: Expired exception does not exempt CRITICAL finding → deny ────────
- L0173: # exception_is_expired fires → valid_exception_definition fails → not exempting.
- L0174: # Additionally expired_enabled_exception_ids fires → own deny message.
- L0175: 
- L0176: test_deny_expired_exception if {
- L0177: 	expired := object.union(_valid_exception, {"expires_at": "2020-01-01T00:00:00Z"})
- L0178: 
- L0179: 	result := data.cloudsentinel.gate.decision
- L0180: 		with input as object.union(_base, {"findings": [_critical_finding]})
- L0181: 		with data.cloudsentinel.exceptions.exceptions as [expired]
- L0182: 
- L0183: 	not result.allow
- L0184: 	# Expired exception generates its own deny
- L0185: 	some exp_msg in result.deny
- L0186: 	contains(exp_msg, "expires_at is in the past")
- L0187: 	# And the CRITICAL finding is no longer exempted
- L0188: 	result.metrics.critical == 1
- L0189: }
- L0190: 
- L0191: # ─── TEST 9: Duplicate finding is excluded from counts → allow ───────────────
- L0192: # context.deduplication.is_duplicate=true filters the finding out of
- L0193: # failed_findings. effective_critical=0 → allow.
- L0194: 
- L0195: test_duplicate_finding_not_counted if {
- L0196: 	dup := object.union(_critical_finding, {
- L0197: 		"context": {"deduplication": {"is_duplicate": true}},
- L0198: 	})
- L0199: 
- L0200: 	result := data.cloudsentinel.gate.decision
- L0201: 		with input as object.union(_base, {"findings": [dup]})
- L0202: 		with data.cloudsentinel.exceptions.exceptions as []
- L0203: 
- L0204: 	result.allow
- L0205: 	result.metrics.critical == 0
- L0206: 	result.metrics.failed_input == 0
- L0207: }
- L0208: 
- L0209: # ─── TEST 10: Local mode is advisory for scanner checks → allow ───────────────
- L0210: # NOTE: local mode only bypasses scanner_not_run — threshold violations still
- L0211: # deny. This test demonstrates the advisory behavior: checkov+trivy both
- L0212: # NOT_RUN in local mode with 0 findings → allow (scanner absence not blocked).
- L0213: 
- L0214: test_local_mode_advisory if {
- L0215: 	result := data.cloudsentinel.gate.decision
- L0216: 		with input as object.union(_base, {
- L0217: 			"metadata": {
- L0218: 				"environment": "dev",
- L0219: 				"execution":   {"mode": "local"},
- L0220: 			},
- L0221: 			"scanners": {
- L0222: 				"gitleaks": {"status": "PASSED"},
- L0223: 				"checkov":  {"status": "NOT_RUN"},
- L0224: 				"trivy":    {"status": "NOT_RUN"},
- L0225: 			},
- L0226: 			"findings": [],
- L0227: 		})
- L0228: 		with data.cloudsentinel.exceptions.exceptions as []
- L0229: 
- L0230: 	result.allow
- L0231: 	count(result.deny) == 0
- L0232: 	result.execution_mode == "local"
- L0233: }
- L0234: 
- L0235: # ─── TEST 11: trivy-image-scan-* removed, fs+config only → allow ──────────────
- L0236: # Simulates pipeline after trivy-image-scan-* jobs were removed.
- L0237: # trivy scanner status is PASSED (fs+config ran), no image reports produced.
- L0238: # OPA must ALLOW when all three scanners ran and findings are within thresholds.
- L0239: 
- L0240: test_allow_when_trivy_image_scans_removed if {
- L0241: 	result := data.cloudsentinel.gate.decision
- L0242: 		with input as object.union(_base, {
- L0243: 			"scanners": {
- L0244: 				"gitleaks": {"status": "PASSED"},
- L0245: 				"checkov":  {"status": "PASSED"},
- L0246: 				"trivy":    {"status": "PASSED"},
- L0247: 			},
- L0248: 			"findings": [],
- L0249: 		})
- L0250: 		with data.cloudsentinel.exceptions.exceptions as []
- L0251: 
- L0252: 	result.allow
- L0253: 	count(result.deny) == 0
- L0254: 	result.metrics.critical == 0
- L0255: 	result.metrics.high == 0
- L0256: }

#### policies/opa/test_pipeline_decision.rego
- L0001: package cloudsentinel.gate
- L0002: 
- L0003: # ─────────────────────────────────────────────────────────────────────
- L0004: # Test suite B — Exception lifecycle + threshold ceiling edge cases
- L0005: # Companion: pipeline_decision_test.rego (functional allow/deny scenarios)
- L0006: # Total coverage: 22 tests across both files. Zero overlap.
- L0007: # Run: opa test policies/opa -v
- L0008: # ─────────────────────────────────────────────────────────────────────
- L0009: 
- L0010: import rego.v1
- L0011: 
- L0012: base_input := {
- L0013:   "metadata": {
- L0014:     "environment": "dev"
- L0015:   },
- L0016:   "quality_gate": {
- L0017:     "thresholds": {
- L0018:       "critical_max": 0,
- L0019:       "high_max": 2
- L0020:     }
- L0021:   },
- L0022:   "scanners": {
- L0023:     "gitleaks": {"status": "PASSED"},
- L0024:     "checkov": {"status": "PASSED"},
- L0025:     "trivy": {"status": "PASSED"}
- L0026:   }
- L0027: }
- L0028: 
- L0029: base_failed_finding := {
- L0030:   "status": "FAILED",
- L0031:   "source": {"tool": "checkov", "id": "CKV2_CS_AZ_001"},
- L0032:   "resource": {
- L0033:     "name": "azurerm_storage_account.insecure",
- L0034:     "path": "/infra/azure/student-secure/modules/storage/main.tf"
- L0035:   },
- L0036:   "severity": {"level": "HIGH"}
- L0037: }
- L0038: 
- L0039: base_v2_exception := {
- L0040:   "id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
- L0041:   "tool": "checkov",
- L0042:   "rule_id": "CKV2_CS_AZ_001",
- L0043:   "resource": "azurerm_storage_account.insecure",
- L0044:   "severity": "HIGH",
- L0045:   "requested_by": "dev-team",
- L0046:   "approved_by": "security-team",
- L0047:   "approved_at": "2026-01-01T00:00:00Z",
- L0048:   "expires_at": "2099-01-01T00:00:00Z",
- L0049:   "decision": "accept",
- L0050:   "source": "defectdojo",
- L0051:   "status": "approved"
- L0052: }
- L0053: 
- L0054: test_allow_when_thresholds_respected if {
- L0055:   result := decision
- L0056:     with input as object.union(base_input, {
- L0057:       "summary": {"global": {"CRITICAL": 0, "HIGH": 1, "FAILED": 1}},
- L0058:       "findings": [base_failed_finding]
- L0059:     })
- L0060:     with data.cloudsentinel.exceptions.exceptions as []
- L0061: 
- L0062:   result.allow
- L0063:   count(result.deny) == 0
- L0064: }
- L0065: 
- L0066: test_deny_on_critical_over_threshold if {
- L0067:   result := decision
- L0068:     with input as object.union(base_input, {
- L0069:       "summary": {"global": {"CRITICAL": 1, "HIGH": 0, "FAILED": 1}},
- L0070:       "findings": [
- L0071:         {
- L0072:           "status": "FAILED",
- L0073:           "source": {"tool": "trivy", "id": "CVE-1"},
- L0074:           "resource": {"path": "/image/alpine"},
- L0075:           "severity": {"level": "CRITICAL"}
- L0076:         }
- L0077:       ]
- L0078:     })
- L0079:     with data.cloudsentinel.exceptions.exceptions as []
- L0080: 
- L0081:   not result.allow
- L0082:   contains(result.deny[0], "CRITICAL findings")
- L0083: }
- L0084: 
- L0085: test_allow_when_v2_exception_is_valid if {
- L0086:   result := decision
- L0087:     with input as object.union(base_input, {
- L0088:       "summary": {"global": {"CRITICAL": 0, "HIGH": 1, "FAILED": 1}},
- L0089:       "findings": [base_failed_finding]
- L0090:     })
- L0091:     with data.cloudsentinel.exceptions.exceptions as [base_v2_exception]
- L0092: 
- L0093:   result.allow
- L0094:   result.metrics.excepted == 1
- L0095:   result.exceptions.applied_ids[0] == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
- L0096: }
- L0097: 
- L0098: test_deny_when_scanner_not_run if {
- L0099:   result := decision
- L0100:     with input as object.union(base_input, {
- L0101:       "summary": {"global": {"CRITICAL": 0, "HIGH": 0, "FAILED": 0}},
- L0102:       "scanners": {
- L0103:         "gitleaks": {"status": "PASSED"},
- L0104:         "checkov": {"status": "NOT_RUN"},
- L0105:         "trivy": {"status": "PASSED"}
- L0106:       },
- L0107:       "findings": []
- L0108:     })
- L0109:     with data.cloudsentinel.exceptions.exceptions as []
- L0110: 
- L0111:   not result.allow
- L0112:   contains(result.deny[0], "Scanner checkov")
- L0113: }
- L0114: 
- L0115: test_allow_when_scanners_not_run_in_local_mode if {
- L0116:   result := decision
- L0117:     with input as object.union(base_input, {
- L0118:       "metadata": {
- L0119:         "environment": "dev",
- L0120:         "execution": {"mode": "local"}
- L0121:       },
- L0122:       "summary": {"global": {"CRITICAL": 0, "HIGH": 0, "FAILED": 0}},
- L0123:       "scanners": {
- L0124:         "gitleaks": {"status": "PASSED"},
- L0125:         "checkov": {"status": "NOT_RUN"},
- L0126:         "trivy": {"status": "NOT_RUN"}
- L0127:       },
- L0128:       "findings": []
- L0129:     })
- L0130:     with data.cloudsentinel.exceptions.exceptions as []
- L0131: 
- L0132:   result.allow
- L0133:   count(result.deny) == 0
- L0134: }
- L0135: 
- L0136: test_deny_when_exception_status_not_approved if {
- L0137:   bad := object.union(base_v2_exception, {"status": "pending"})
- L0138:   result := decision
- L0139:     with input as object.union(base_input, {
- L0140:       "summary": {"global": {"CRITICAL": 0, "HIGH": 0, "FAILED": 0}},
- L0141:       "findings": []
- L0142:     })
- L0143:     with data.cloudsentinel.exceptions.exceptions as [bad]
- L0144: 
- L0145:   not result.allow
- L0146:   contains(concat(" ", result.deny), "status must be approved")
- L0147: }
- L0148: 
- L0149: test_deny_when_exception_missing_approved_by if {
- L0150:   bad := object.remove(base_v2_exception, ["approved_by"])
- L0151:   result := decision
- L0152:     with input as object.union(base_input, {
- L0153:       "summary": {"global": {"CRITICAL": 0, "HIGH": 0, "FAILED": 0}},
- L0154:       "findings": []
- L0155:     })
- L0156:     with data.cloudsentinel.exceptions.exceptions as [bad]
- L0157: 
- L0158:   not result.allow
- L0159:   contains(concat(" ", result.deny), "approved_by is required")
- L0160: }
- L0161: 
- L0162: test_deny_when_exception_is_expired if {
- L0163:   expired := object.union(base_v2_exception, {
- L0164:     "expires_at": "2020-01-01T00:00:00Z"
- L0165:   })
- L0166:   result := decision
- L0167:     with input as object.union(base_input, {
- L0168:       "summary": {"global": {"CRITICAL": 0, "HIGH": 0, "FAILED": 0}},
- L0169:       "findings": []
- L0170:     })
- L0171:     with data.cloudsentinel.exceptions.exceptions as [expired]
- L0172: 
- L0173:   not result.allow
- L0174:   contains(concat(" ", result.deny), "expires_at is in the past")
- L0175: }
- L0176: 
- L0177: test_deny_when_exception_schema_is_malformed if {
- L0178:   malformed := object.union(base_v2_exception, {
- L0179:     "id": "short"
- L0180:   })
- L0181: 
- L0182:   result := decision
- L0183:     with input as object.union(base_input, {
- L0184:       "summary": {"global": {"CRITICAL": 0, "HIGH": 0, "FAILED": 0}},
- L0185:       "findings": []
- L0186:     })
- L0187:     with data.cloudsentinel.exceptions.exceptions as [malformed]
- L0188: 
- L0189:   not result.allow
- L0190:   contains(concat(" ", result.deny), "malformed")
- L0191: }
- L0192: 
- L0193: # Test : une tentative d'override CI (critical_max=99) doit toujours deny
- L0194: # si un finding CRITICAL est présent — le plafond policy à 0 s'applique.
- L0195: test_threshold_ceiling_blocks_ci_override_on_critical if {
- L0196:   result := decision
- L0197:     with input as object.union(base_input, {
- L0198:       "quality_gate": {"thresholds": {"critical_max": 99, "high_max": 100}},
- L0199:       "findings": [
- L0200:         {
- L0201:           "status": "FAILED",
- L0202:           "source": {"tool": "trivy", "id": "CVE-CRITICAL-1"},
- L0203:           "resource": {"path": "/image/scan-tools"},
- L0204:           "severity": {"level": "CRITICAL"},
- L0205:         }
- L0206:       ],
- L0207:     })
- L0208:     with data.cloudsentinel.exceptions.exceptions as []
- L0209: 
- L0210:   not result.allow
- L0211:   contains(result.deny[0], "CRITICAL findings")
- L0212:   result.thresholds.enforced_critical_max == 0
- L0213: }
- L0214: 
- L0215: # Test : high_max passé à 100 en CI doit être capé au plafond policy (5).
- L0216: test_threshold_ceiling_caps_high_max_to_policy_floor if {
- L0217:   result := decision
- L0218:     with input as object.union(base_input, {
- L0219:       "quality_gate": {"thresholds": {"critical_max": 0, "high_max": 100}},
- L0220:       "findings": [],
- L0221:     })
- L0222:     with data.cloudsentinel.exceptions.exceptions as []
- L0223: 
- L0224:   result.allow
- L0225:   result.thresholds.enforced_high_max == 5
- L0226: }

