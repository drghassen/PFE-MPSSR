#!/usr/bin/env bash

cloudsentinel_epoch_ms() {
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY'
import time
print(int(time.time() * 1000))
PY
  else
    printf '%s000\n' "$(date +%s)"
  fi
}

: "${CLOUDSENTINEL_JOB_START_EPOCH_MS:=$(cloudsentinel_epoch_ms)}"
export CLOUDSENTINEL_JOB_START_EPOCH_MS

cloudsentinel_invalidate_downstream_artifacts() {
  if [[ "${CLOUDSENTINEL_PRESERVE_DOWNSTREAM_ARTIFACTS:-false}" == "true" ]]; then
    return 0
  fi

  rm -f \
    .cloudsentinel/golden_report.json \
    .cloudsentinel/golden_report.json.hmac \
    .cloudsentinel/opa_decision.json \
    .cloudsentinel/opa_decision.json.hmac \
    .cloudsentinel/decision_audit_events.jsonl \
    .cloudsentinel/artifact_contract_report.json
}

cloudsentinel_finalize_audit() {
  local rc="$1"
  local job_name="$2"
  local stage_name="$3"
  local component="$4"
  shift 4

  local end_epoch_ms duration_ms
  end_epoch_ms="$(cloudsentinel_epoch_ms)"
  duration_ms=$(( end_epoch_ms - CLOUDSENTINEL_JOB_START_EPOCH_MS ))
  if [[ "${duration_ms}" -lt 0 ]]; then
    duration_ms=0
  fi

  local status="success"
  if [[ "${rc}" -ne 0 ]]; then
    status="failure"
  fi

  local output=".cloudsentinel/audit/${job_name}_audit.json"
  local cmd=(
    python3 ci/scripts/shift-left/audit_artifact.py
    --job "${job_name}"
    --stage "${stage_name}"
    --component "${component}"
    --status "${status}"
    --exit-code "${rc}"
    --output "${output}"
    --metric "duration_ms=${duration_ms}"
  )
  local artifact
  for artifact in "$@"; do
    cmd+=(--artifact "${artifact}")
  done

  if command -v python3 >/dev/null 2>&1 && [[ -f ci/scripts/shift-left/audit_artifact.py ]]; then
    "${cmd[@]}" || true
  else
    mkdir -p "$(dirname "${output}")"
    jq -n \
      --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --arg job_name "${job_name}" \
      --arg stage_name "${stage_name}" \
      --arg component "${component}" \
      --arg status "${status}" \
      --argjson exit_code "${rc}" \
      '{
        schema_version: "1.0.0",
        generated_at: $generated_at,
        job: {
          name: $job_name,
          stage: $stage_name,
          component: $component,
          status: $status,
          exit_code: $exit_code
        },
        audit_mode: "minimal",
        reason: "python3_unavailable"
      }' > "${output}" 2>/dev/null || true
  fi

  if [[ -n "${CLOUDSENTINEL_HMAC_SECRET:-}" && -f "${output}" ]]; then
    if command -v python3 >/dev/null 2>&1 && [[ -f ci/scripts/shift-left/artifact_hmac.py ]]; then
      python3 ci/scripts/shift-left/artifact_hmac.py sign "${output}" || true
    elif command -v openssl >/dev/null 2>&1; then
      openssl dgst -sha256 -hmac "${CLOUDSENTINEL_HMAC_SECRET}" "${output}" | awk '{print $NF}' > "${output}.hmac" || true
    fi
  fi

  chmod a+r "${output}" "${output}.hmac" 2>/dev/null || true
  exit "${rc}"
}
