#!/usr/bin/env bash
set -euo pipefail

# =========================
# trivy-fs-scan.sh
# =========================
# Single trivy-scan job in the scan stage:
#   1. Filesystem scan  → CVE only (OS/library pkgs) — IaC misconfigs owned by Checkov
#   2. Image scan loop  → CVE + container misconfigs for each TRIVY_IMAGE_TARGETS entry
# DB warm-up is handled by the separate trivy-db-warm job (guard stage).

trivy --version
mkdir -p shift-left/trivy/reports/raw/image .cloudsentinel

readonly DEFAULT_TRIVY_TARGET="."
TRIVY_TARGET_EFF="${TRIVY_FS_TARGET:-${TRIVY_TARGET:-${DEFAULT_TRIVY_TARGET}}}"

# ── 1. Filesystem scan (CVE + Dockerfile misconfigs) ─────────────────────────
bash shift-left/trivy/scripts/run-trivy.sh "${TRIVY_TARGET_EFF}" "fs"
python3 ci/libs/cloudsentinel_contracts.py stamp-artifact-metadata \
  --artifact shift-left/trivy/reports/raw/trivy-fs-raw.json \
  --tool trivy \
  --executed-target "${TRIVY_TARGET_EFF}" \
  --scan-status success

if [[ -n "${CLOUDSENTINEL_HMAC_SECRET:-}" ]]; then
  python3 ci/scripts/shift-left/artifact_hmac.py sign shift-left/trivy/reports/raw/trivy-fs-raw.json
elif [[ -n "${CI:-}" ]]; then
  echo "[trivy-fs][ERROR] CLOUDSENTINEL_HMAC_SECRET is not set in CI." >&2
  exit 1
else
  echo "[trivy-fs][WARN] CLOUDSENTINEL_HMAC_SECRET not set — skipping HMAC signing (non-CI mode)."
fi

jq -r '"[scan-summary] trivy_fs_raw_results=" + (((.Results // []) | length) | tostring)' \
  shift-left/trivy/reports/raw/trivy-fs-raw.json

# ── 2. Image scan loop (CVE + container misconfigs) ──────────────────────────
# Set TRIVY_IMAGE_TARGETS in GitLab CI/CD Settings as a comma-separated list
# of image references to scan, e.g.:
#   registry.gitlab.com/org/project/scan-tools:latest,python:3.12-alpine
# If empty, image scanning is skipped (advisory mode).
TRIVY_IMAGE_TARGETS="${TRIVY_IMAGE_TARGETS:-}"

if [[ -z "$TRIVY_IMAGE_TARGETS" ]]; then
  echo "[trivy-image][INFO] TRIVY_IMAGE_TARGETS is empty — image scanning skipped."
else
  IMAGE_COUNT=0
  IMAGE_ERRORS=0

  IFS=',' read -r -a _images <<< "$TRIVY_IMAGE_TARGETS"
  for _img in "${_images[@]}"; do
    _img="$(echo "$_img" | xargs)"
    [[ -z "$_img" ]] && continue

    # Sanitize image reference → safe filename token (replace /:@. with -)
    _img_slug="$(echo "$_img" | tr '/:@.' '----' | tr -dc '[:alnum:]-_' | cut -c1-80)"
    _out="shift-left/trivy/reports/raw/image/trivy-image-${_img_slug}-raw.json"

    echo "[trivy-image][INFO] Scanning image: ${_img}"

    if TRIVY_IMAGE_OUTPUT_PATH="${_out}" \
         bash shift-left/trivy/scripts/run-trivy.sh "${_img}" "image"; then

      if [[ -n "${CLOUDSENTINEL_HMAC_SECRET:-}" ]]; then
        python3 ci/scripts/shift-left/artifact_hmac.py sign "${_out}"
      fi

      _count=$(jq '[.Results[]? | (.Vulnerabilities // [], .Misconfigurations // []) | length] | add // 0' "${_out}" 2>/dev/null || echo "?")
      echo "[trivy-image][INFO] Image ${_img} — findings: ${_count} → ${_out}"
      IMAGE_COUNT=$(( IMAGE_COUNT + 1 ))
    else
      echo "[trivy-image][WARN] Image scan failed for: ${_img} (non-blocking)" >&2
      IMAGE_ERRORS=$(( IMAGE_ERRORS + 1 ))
    fi
  done

  echo "[trivy-image][INFO] Image scan complete — scanned: ${IMAGE_COUNT}, errors: ${IMAGE_ERRORS}"
fi

chmod -R a+r shift-left/trivy/reports/raw 2>/dev/null || true
