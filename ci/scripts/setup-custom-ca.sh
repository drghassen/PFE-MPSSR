#!/usr/bin/env bash
set -euo pipefail

# CloudSentinel custom CA bootstrap for non-root CI containers.
# This script is intended to be sourced by job scripts:
#   source ci/scripts/setup-custom-ca.sh
#
# Supported inputs:
# - CLOUDSENTINEL_CUSTOM_CA_PEM_B64: base64-encoded PEM certificate chain
# - CLOUDSENTINEL_CUSTOM_CA_PEM: raw PEM certificate chain
# - CLOUDSENTINEL_CA_BUNDLE: explicit CA bundle file path (already available in job FS)
#
# Outputs:
# - Exports SSL_CERT_FILE / REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE / GIT_SSL_CAINFO
# - Exports CLOUDSENTINEL_CA_BUNDLE for Python fetchers

log()  { echo "[custom-ca] $*"; }
warn() { echo "[custom-ca][WARN] $*" >&2; }
err()  { echo "[custom-ca][ERROR] $*" >&2; }
_finish() { return "$1" 2>/dev/null || exit "$1"; }

custom_ca_b64="${CLOUDSENTINEL_CUSTOM_CA_PEM_B64:-}"
custom_ca_pem="${CLOUDSENTINEL_CUSTOM_CA_PEM:-}"
explicit_bundle="${CLOUDSENTINEL_CA_BUNDLE:-}"

if [[ -n "${explicit_bundle}" ]]; then
  if [[ ! -s "${explicit_bundle}" ]]; then
    err "CLOUDSENTINEL_CA_BUNDLE is set but file is missing/empty: ${explicit_bundle}"
    _finish 2
  fi
  export SSL_CERT_FILE="${explicit_bundle}"
  export REQUESTS_CA_BUNDLE="${explicit_bundle}"
  export CURL_CA_BUNDLE="${explicit_bundle}"
  export GIT_SSL_CAINFO="${explicit_bundle}"
  log "Using explicit CA bundle: ${explicit_bundle}"
  _finish 0
fi

if [[ -z "${custom_ca_b64}" && -z "${custom_ca_pem}" ]]; then
  log "No custom CA provided (CLOUDSENTINEL_CUSTOM_CA_PEM_B64/CLOUDSENTINEL_CUSTOM_CA_PEM). Using image trust store."
  _finish 0
fi

out_dir=".cloudsentinel/tls"
custom_ca_file="${out_dir}/custom-ca.pem"
bundle_file="${out_dir}/ca-bundle.pem"
mkdir -p "${out_dir}"

if [[ -n "${custom_ca_b64}" ]]; then
  if ! printf '%s' "${custom_ca_b64}" | base64 -d > "${custom_ca_file}" 2>/dev/null; then
    err "Failed to decode CLOUDSENTINEL_CUSTOM_CA_PEM_B64."
    _finish 2
  fi
else
  printf '%s\n' "${custom_ca_pem}" > "${custom_ca_file}"
fi

if ! grep -q "BEGIN CERTIFICATE" "${custom_ca_file}"; then
  err "Custom CA payload is not a valid PEM certificate chain."
  _finish 2
fi

python3 - "${custom_ca_file}" <<'PY'
import ssl
import sys
from pathlib import Path

p = Path(sys.argv[1])
data = p.read_text(encoding="utf-8")
for block in data.split("-----END CERTIFICATE-----"):
    if "-----BEGIN CERTIFICATE-----" not in block:
        continue
    pem = block + "-----END CERTIFICATE-----\n"
    ssl.PEM_cert_to_DER_cert(pem)
PY

base_bundle="${SSL_CERT_FILE:-/etc/ssl/certs/ca-certificates.crt}"
if [[ -s "${base_bundle}" ]]; then
  cat "${base_bundle}" > "${bundle_file}"
else
  warn "Base trust bundle not found at ${base_bundle}; building custom-only bundle."
  : > "${bundle_file}"
fi

printf '\n' >> "${bundle_file}"
cat "${custom_ca_file}" >> "${bundle_file}"

export CLOUDSENTINEL_CA_BUNDLE="${bundle_file}"
export SSL_CERT_FILE="${bundle_file}"
export REQUESTS_CA_BUNDLE="${bundle_file}"
export CURL_CA_BUNDLE="${bundle_file}"
export GIT_SSL_CAINFO="${bundle_file}"

log "Custom CA bundle initialized: ${bundle_file}"
_finish 0
