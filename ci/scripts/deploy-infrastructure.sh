#!/usr/bin/env bash
set -euo pipefail
required_vars=(
  ARM_CLIENT_ID
  ARM_CLIENT_SECRET
  ARM_TENANT_ID
  ARM_SUBSCRIPTION_ID
  TFSTATE_RESOURCE_GROUP
  TFSTATE_STORAGE_ACCOUNT
  TFSTATE_CONTAINER
  TF_VAR_admin_ssh_public_key
)
for name in "${required_vars[@]}"; do
  if [ -z "${!name:-}" ]; then
    echo "[deploy][ERROR] missing required variable: ${name}" >&2
    exit 2
  fi
done
if ! printf '%s' "${TF_VAR_admin_ssh_public_key}" | grep -Eq '^ssh-rsa[[:space:]]+[A-Za-z0-9+/=]+([[:space:]].*)?$'; then
  echo "[deploy][ERROR] TF_VAR_admin_ssh_public_key must be RSA format (starts with 'ssh-rsa ')." >&2
  echo "[deploy][ERROR] Generate with: ssh-keygen -t rsa -b 4096 -C \"gitlab-ci\" -f ~/.ssh/student_secure_rsa" >&2
  exit 2
fi

tofu version
cosign version
export ARM_USE_AZUREAD=true
export ARM_STORAGE_USE_AZUREAD=true
tofu -chdir=infra/azure/student-secure init -input=false \
  -backend-config="resource_group_name=${TFSTATE_RESOURCE_GROUP}" \
  -backend-config="storage_account_name=${TFSTATE_STORAGE_ACCOUNT}" \
  -backend-config="container_name=${TFSTATE_CONTAINER}" \
  -backend-config="key=${TFSTATE_KEY:-student-secure-${CI_COMMIT_REF_SLUG}.tfstate}" \
  -backend-config="use_azuread_auth=true"
export TF_VAR_subscription_id="${TF_VAR_subscription_id:-${ARM_SUBSCRIPTION_ID}}"
[ -n "${TF_VAR_subscription_id}" ] || { echo "[deploy][ERROR] TF_VAR_subscription_id is empty"; exit 2; }
echo "[deploy] TF_VAR_subscription_id is set"
tofu -chdir=infra/azure/student-secure plan -input=false -out=tfplan
tofu -chdir=infra/azure/student-secure apply -input=false -auto-approve tfplan
tofu -chdir=infra/azure/student-secure output -json \
  | jq 'to_entries
        | map(if .value.sensitive == true
              then .value.value = "REDACTED"
              else .
              end)
        | from_entries' \
  > .cloudsentinel/terraform_outputs_student_secure.json
