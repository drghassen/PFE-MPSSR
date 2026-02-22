#!/usr/bin/env bash
set -euo pipefail

log() { echo "[E2E][DEV-PROD] $*"; }
fail() { echo "[E2E][DEV-PROD][ERROR] $*" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "Missing command: $1"
}

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

require_cmd bash
require_cmd jq
require_cmd gitleaks
require_cmd checkov
require_cmd trivy
require_cmd opa

SCAN_TARGET="${1:-infra/azure/dev}"
TRIVY_TARGET="${2:-../../infra/azure/dev}"
TRIVY_SCAN_TYPE="${3:-config}"

mkdir -p .cloudsentinel

TMP_EXCEPTIONS="$(mktemp -t opa-exceptions-devprod.XXXXXX.json)"
trap 'rm -f "$TMP_EXCEPTIONS"' EXIT

# This temporary exception is intentionally scoped to dev only.
cat > "$TMP_EXCEPTIONS" <<'JSON'
{
  "cloudsentinel": {
    "exceptions": {
      "exceptions": [
        {
          "id": "EXC-E2E-DEV-001",
          "enabled": true,
          "tool": "checkov",
          "rule_id": "CKV2_CS_AZ_001",
          "resource_path": "/state_storage.tf",
          "environments": ["dev"],
          "max_severity": "HIGH",
          "reason": "E2E demonstration exception in dev",
          "ticket": "SEC-E2E-001",
          "requested_by": "dev@example.com",
          "approved_by": "security.lead@example.com",
          "commit_hash": "abc1234",
          "request_date": "2026-02-21T09:30:00Z",
          "created_at": "2026-02-21T10:00:00Z",
          "expires_at": "2099-01-01T00:00:00Z"
        }
      ]
    }
  }
}
JSON

run_scans() {
  log "Running advisory scanners..."
  bash shift-left/gitleaks/run-gitleaks.sh
  bash shift-left/checkov/run-checkov.sh "$SCAN_TARGET"

  # Run Trivy from its own folder so .trivyignore is correctly resolved.
  (
    cd shift-left/trivy
    bash scripts/run-trivy.sh "$TRIVY_TARGET" "$TRIVY_SCAN_TYPE"
  )
}

eval_env() {
  local env="$1"
  local decision_file=".cloudsentinel/opa_decision_${env}.json"

  log "Normalizing and evaluating OPA for environment=${env}"
  ENVIRONMENT="$env" HIGH_MAX=1 CRITICAL_MAX=0 bash shift-left/normalizer/normalize.sh >/tmp/cloudsentinel_normalize_"$env".log

  opa eval \
    --format json \
    --input .cloudsentinel/golden_report.json \
    --data policies/opa/pipeline_decision.rego \
    --data "$TMP_EXCEPTIONS" \
    "data.cloudsentinel.gate.decision" > "$decision_file"

  local allow
  local excepted
  local ids
  local deny
  allow="$(jq -r '.result[0].expressions[0].value.allow' "$decision_file")"
  excepted="$(jq -r '.result[0].expressions[0].value.exceptions.applied_count' "$decision_file")"
  ids="$(jq -r '.result[0].expressions[0].value.exceptions.applied_ids | join(",")' "$decision_file")"
  deny="$(jq -r '.result[0].expressions[0].value.deny | join(" | ")' "$decision_file")"

  log "env=${env} allow=${allow} excepted=${excepted} ids=[${ids}]"
  [[ -n "$deny" ]] && log "env=${env} deny_reasons=${deny}"

  if [[ "$env" == "dev" ]]; then
    [[ "$allow" == "true" ]] || fail "Expected ALLOW=true in dev when exception is valid"
    [[ "$excepted" -ge 1 ]] || fail "Expected at least one applied exception in dev"
  fi

  if [[ "$env" == "prod" ]]; then
    [[ "$allow" == "false" ]] || fail "Expected ALLOW=false in prod when exception does not apply"
    [[ "$excepted" -eq 0 ]] || fail "Expected zero applied exceptions in prod"
  fi
}

run_scans
eval_env dev
eval_env prod

log "SUCCESS: dev/prod pipeline behavior validated."
