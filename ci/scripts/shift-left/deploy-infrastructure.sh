#!/usr/bin/env bash
set -euo pipefail

# Distributed integrity model: deploy verifies the decision artifact locally
# instead of relying on a centralized integrity job.
OPA_DECISION_ARTIFACT=".cloudsentinel/opa_decision.json"
if [[ ! -s "${OPA_DECISION_ARTIFACT}" ]]; then
  echo "[deploy][ERROR] Missing/empty OPA decision artifact: ${OPA_DECISION_ARTIFACT}" >&2
  exit 1
fi

bash ci/scripts/verify-hmac.sh "${OPA_DECISION_ARTIFACT}"

if ! jq -e '
  type == "object"
  and ((.scan_id // "") | type == "string" and length > 0)
  and (.result | type == "object")
  and (.result.allow | type == "boolean")
  and (.result.deny | type == "array")
' "${OPA_DECISION_ARTIFACT}" >/dev/null 2>&1; then
  echo "[deploy][ERROR] Invalid OPA decision payload. Refusing deployment." >&2
  exit 1
fi

if ! jq -e '.result.allow == true' "${OPA_DECISION_ARTIFACT}" >/dev/null 2>&1; then
  echo "[deploy][ERROR] OPA denied deployment. Refusing infrastructure apply." >&2
  jq -r '.result.deny[]? | "[deploy][DENY] " + .' "${OPA_DECISION_ARTIFACT}" >&2 || true
  exit 1
fi

echo "[deploy] OPA decision integrity verified and allow=true confirmed."

required_vars=(
  ARM_CLIENT_ID
  ARM_CLIENT_SECRET
  ARM_TENANT_ID
  ARM_SUBSCRIPTION_ID
  TFSTATE_RESOURCE_GROUP
  TFSTATE_STORAGE_ACCOUNT
  TFSTATE_CONTAINER
  TF_VAR_postgres_admin_password
)
for name in "${required_vars[@]}"; do
  if [ -z "${!name:-}" ]; then
    echo "[deploy][ERROR] missing required variable: ${name}" >&2
    exit 2
  fi
done

# Backward-compatible bridge: old variable name -> new Azure modular env variable.
export TF_VAR_vm_admin_ssh_public_key="${TF_VAR_vm_admin_ssh_public_key:-${TF_VAR_admin_ssh_public_key:-}}"
if [[ -z "${TF_VAR_vm_admin_ssh_public_key}" ]]; then
  echo "[deploy][ERROR] missing required variable: TF_VAR_vm_admin_ssh_public_key (or legacy TF_VAR_admin_ssh_public_key)" >&2
  exit 2
fi

SSH_PUBKEY_REGEX='^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp(256|384|521))[[:space:]]+[A-Za-z0-9+/]+={0,2}([[:space:]].*)?$'
if ! printf '%s' "${TF_VAR_vm_admin_ssh_public_key}" | grep -Eq "${SSH_PUBKEY_REGEX}"; then
  echo "[deploy][ERROR] TF_VAR_vm_admin_ssh_public_key must be a valid OpenSSH public key (ssh-ed25519, ecdsa-sha2-nistp256/384/521, or ssh-rsa)." >&2
  echo "[deploy][ERROR] Recommended: ssh-keygen -t ed25519 -C \"gitlab-ci\" -f ~/.ssh/student_secure_ed25519" >&2
  exit 2
fi

# ── ARM_CLIENT_SECRET governance check ─────────────────────────────────────
# Detects stale credentials. ARM_CLIENT_SECRET_CREATED_AT must be set in
# GitLab CI/CD Settings → Variables (format: YYYY-MM-DD).
# If unset: warning only (non-blocking) to avoid breaking existing pipelines.
# If set and age > 90 days: pipeline FAILS to enforce rotation policy.
# Rotation procedure: az ad sp credential reset → update GitLab masked variable.
# Reference: NIST 800-53 IA-5 / CIS Azure 1.x
ARM_MAX_SECRET_AGE_DAYS="${ARM_MAX_SECRET_AGE_DAYS:-90}"
if [[ -n "${ARM_CLIENT_SECRET_CREATED_AT:-}" ]]; then
  SECRET_CREATED_EPOCH="$(date -u -d "${ARM_CLIENT_SECRET_CREATED_AT}" +%s 2>/dev/null || echo 0)"
  NOW_EPOCH="$(date -u +%s)"
  if [[ "$SECRET_CREATED_EPOCH" -gt 0 ]]; then
    SECRET_AGE_DAYS=$(( (NOW_EPOCH - SECRET_CREATED_EPOCH) / 86400 ))
    if [[ "$SECRET_AGE_DAYS" -gt "$ARM_MAX_SECRET_AGE_DAYS" ]]; then
      echo "[deploy][SECURITY] FAIL: ARM_CLIENT_SECRET is ${SECRET_AGE_DAYS} days old" \
           "(max: ${ARM_MAX_SECRET_AGE_DAYS}). Rotate now:" >&2
      echo "[deploy][SECURITY]   az ad sp credential reset --id \$ARM_CLIENT_ID" >&2
      echo "[deploy][SECURITY]   Then update GitLab masked variable ARM_CLIENT_SECRET" >&2
      echo "[deploy][SECURITY]   And update ARM_CLIENT_SECRET_CREATED_AT to $(date -u +%Y-%m-%d)" >&2
      exit 2
    else
      echo "[deploy] ARM_CLIENT_SECRET age: ${SECRET_AGE_DAYS} days (max: ${ARM_MAX_SECRET_AGE_DAYS}) — OK"
    fi
  else
    echo "[deploy][WARN] ARM_CLIENT_SECRET_CREATED_AT='${ARM_CLIENT_SECRET_CREATED_AT}'" \
         "is not a valid date — skipping age check" >&2
  fi
else
  echo "[deploy][WARN] ARM_CLIENT_SECRET_CREATED_AT not set in CI variables." \
       "Set it to the credential creation date (YYYY-MM-DD) to enforce rotation policy." >&2
  echo "[deploy][WARN] This warning will become a hard FAIL in a future version." >&2
fi
# ── end credential age governance ──────────────────────────────────────────

tofu version
cosign version
export ARM_USE_AZUREAD=true
export ARM_STORAGE_USE_AZUREAD=true

# Sanitize TFSTATE key: strip path separators to prevent traversal.
# CI_COMMIT_REF_SLUG is derived from branch name — treat as untrusted input.
TFSTATE_KEY_RAW="${TFSTATE_KEY:-student-secure-${CI_COMMIT_REF_SLUG}.tfstate}"
TFSTATE_KEY_SAFE="$(echo "${TFSTATE_KEY_RAW}" | tr -d '/\\' | sed 's/\.\.//g')"
if [[ "${TFSTATE_KEY_SAFE}" != "${TFSTATE_KEY_RAW}" ]]; then
  echo "[deploy][SECURITY] TFSTATE key sanitized: '${TFSTATE_KEY_RAW}' → '${TFSTATE_KEY_SAFE}'" >&2
fi
if [[ -z "${TFSTATE_KEY_SAFE}" || "${TFSTATE_KEY_SAFE}" == ".tfstate" ]]; then
  echo "[deploy][ERROR] TFSTATE key is empty after sanitization. Refusing to continue." >&2
  exit 2
fi

TF_ROOT_DIR="${TF_ROOT_DIR:-infra/azure/envs/dev}"

tofu -chdir="${TF_ROOT_DIR}" init -input=false \
  -backend-config="resource_group_name=${TFSTATE_RESOURCE_GROUP}" \
  -backend-config="storage_account_name=${TFSTATE_STORAGE_ACCOUNT}" \
  -backend-config="container_name=${TFSTATE_CONTAINER}" \
  -backend-config="key=${TFSTATE_KEY_SAFE}" \
  -backend-config="use_azuread_auth=true"
export TF_VAR_subscription_id="${TF_VAR_subscription_id:-${ARM_SUBSCRIPTION_ID}}"
[ -n "${TF_VAR_subscription_id}" ] || { echo "[deploy][ERROR] TF_VAR_subscription_id is empty"; exit 2; }
echo "[deploy] TF_VAR_subscription_id is set"
export TF_VAR_location="${TF_VAR_location:-norwayeast}"
echo "[deploy] TF_VAR_location=${TF_VAR_location}"
export TF_VAR_tenant_id="${TF_VAR_tenant_id:-${ARM_TENANT_ID}}"
[ -n "${TF_VAR_tenant_id}" ] || { echo "[deploy][ERROR] TF_VAR_tenant_id is empty"; exit 2; }
echo "[deploy] TF_VAR_tenant_id is set"
tofu -chdir="${TF_ROOT_DIR}" plan -input=false -out=tfplan
tofu -chdir="${TF_ROOT_DIR}" apply -input=false -auto-approve tfplan
tofu -chdir="${TF_ROOT_DIR}" output -json \
  | jq 'to_entries
        | map(if .value.sensitive == true
              then .value.value = "REDACTED"
              else .
              end)
        | from_entries' \
  > .cloudsentinel/terraform_outputs_dev.json
