#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 <artifact-path>" >&2
}

if [[ $# -ne 1 ]]; then
  usage
  exit 2
fi

artifact_path="$1"
sidecar_path="${artifact_path}.hmac"
secret="${CLOUDSENTINEL_HMAC_SECRET:-}"
in_ci="${CI:-}"

if [[ ! -f "${artifact_path}" ]]; then
  echo "[verify-hmac][ERROR] Artifact not found: ${artifact_path}" >&2
  exit 1
fi
if [[ ! -s "${artifact_path}" ]]; then
  echo "[verify-hmac][ERROR] Artifact is empty: ${artifact_path}" >&2
  exit 1
fi
if [[ ! -f "${sidecar_path}" ]]; then
  echo "[verify-hmac][ERROR] HMAC sidecar missing: ${sidecar_path}" >&2
  exit 1
fi
if [[ ! -s "${sidecar_path}" ]]; then
  echo "[verify-hmac][ERROR] HMAC sidecar is empty: ${sidecar_path}" >&2
  exit 1
fi

if [[ -z "${secret}" ]]; then
  if [[ -n "${in_ci}" ]]; then
    echo "[verify-hmac][ERROR] CLOUDSENTINEL_HMAC_SECRET is not set in CI." >&2
    exit 1
  fi
  echo "[verify-hmac][WARN] CLOUDSENTINEL_HMAC_SECRET not set outside CI; skipping verification for ${artifact_path}."
  exit 0
fi

stored_hmac="$(tr -d '[:space:]' < "${sidecar_path}")"
if [[ ! "${stored_hmac}" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "[verify-hmac][ERROR] Invalid HMAC format in ${sidecar_path} (expected 64 hex chars)." >&2
  exit 1
fi

computed_hmac="$(openssl dgst -sha256 -hmac "${secret}" "${artifact_path}" | awk '{print $NF}')"

if [[ "${computed_hmac}" != "${stored_hmac}" ]]; then
  echo "[verify-hmac][ERROR] HMAC mismatch for ${artifact_path}" >&2
  exit 1
fi

echo "[verify-hmac] Verified ${artifact_path} (HMAC-SHA256 OK)"
