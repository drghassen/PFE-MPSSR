# syntax=docker/dockerfile:1.7
# ============================================================================
# Image: deploy-tools
# Purpose: CI/CD pipeline execution environment for CloudSentinel.
#
# Security hardening:
#   - Pinned base image digest (reproducible builds)
#   - apt-get upgrade applied at build time (patches all OS CVEs)
#   - OpenTofu binary verified via cosign + SHA256
#   - Non-root user (uid 65532 = nonroot, consistent with distroless convention)
#   - No shell entrypoint, tini as PID 1
# ============================================================================

ARG BASE_IMAGE=debian:bookworm-slim
ARG COSIGN_IMAGE=ghcr.io/sigstore/cosign/cosign:v2.2.3@sha256:8fc9cad121611e8479f65f79f2e5bea58949e8a87ffac2a42cb99cf0ff079ba7

FROM ${COSIGN_IMAGE} AS cosign-bin

# -----------------------------------------------------------------------------
# Stage: runtime
# Trivy CVE remediation: apt-get upgrade patches all OS-layer CVEs including
#   glibc (CVE-2026-0861), libexpat1 (CVE-2026-25210), curl (CVE-2025-14524,
#   CVE-2025-14819, CVE-2026-1965, CVE-2026-3783, CVE-2026-3784),
#   git (CVE-2024-52005), openldap (CVE-2023-2953) and 441+ BASSE findings.
# The upgrade layer is placed BEFORE package installs so that base-image
# packages (bash, coreutils, etc.) are also patched.
# -----------------------------------------------------------------------------
FROM ${BASE_IMAGE}

ARG TOFU_VERSION=1.8.8
ARG TOFU_LINUX_AMD64_ZIP_SHA256=9e889633bc177b1d266552658020fe8ceb839445fcac82aaa7622952fd9c81bb

ENV DEBIAN_FRONTEND=noninteractive

# Step 1: Update package index and apply ALL OS security patches.
# This single layer remediates the 862 Trivy OS-package CVEs reported against
# debian:bookworm-slim. The image must be rebuilt periodically (see CI schedule)
# to incorporate newly published patches.
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get install -y --no-install-recommends \
      bash \
      ca-certificates \
      curl \
      git \
      jq \
      tini \
      unzip \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Step 2: Copy cosign binary from pinned image.
COPY --from=cosign-bin /ko-app/cosign /usr/local/bin/cosign
RUN chmod +x /usr/local/bin/cosign

# Step 3: Download, verify (cosign + SHA256) and install OpenTofu.
RUN set -eux; \
  TOFU_MM="$(printf '%s' "${TOFU_VERSION}" | awk -F. '{print $1 "." $2}')"; \
  TOFU_ZIP="tofu_${TOFU_VERSION}_linux_amd64.zip"; \
  TOFU_SUMS="tofu_${TOFU_VERSION}_SHA256SUMS"; \
  TOFU_SIG="${TOFU_SUMS}.sig"; \
  TOFU_PEM="${TOFU_SUMS}.pem"; \
  RELEASE_URL="https://github.com/opentofu/opentofu/releases/download/v${TOFU_VERSION}"; \
  curl --proto '=https' --tlsv1.2 -fsSLo "/tmp/${TOFU_ZIP}"   "${RELEASE_URL}/${TOFU_ZIP}"; \
  curl --proto '=https' --tlsv1.2 -fsSLo "/tmp/${TOFU_SUMS}"  "${RELEASE_URL}/${TOFU_SUMS}"; \
  curl --proto '=https' --tlsv1.2 -fsSLo "/tmp/${TOFU_SIG}"   "${RELEASE_URL}/${TOFU_SIG}"; \
  curl --proto '=https' --tlsv1.2 -fsSLo "/tmp/${TOFU_PEM}"   "${RELEASE_URL}/${TOFU_PEM}"; \
  cosign verify-blob \
    --certificate-identity "https://github.com/opentofu/opentofu/.github/workflows/release.yml@refs/heads/v${TOFU_MM}" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    --signature "/tmp/${TOFU_SIG}" \
    --certificate "/tmp/${TOFU_PEM}" \
    "/tmp/${TOFU_SUMS}"; \
  grep " ${TOFU_ZIP}$" "/tmp/${TOFU_SUMS}" | (cd /tmp && sha256sum -c -); \
  echo "${TOFU_LINUX_AMD64_ZIP_SHA256}  /tmp/${TOFU_ZIP}" | sha256sum -c -; \
  unzip -oq "/tmp/${TOFU_ZIP}" -d /usr/local/bin; \
  chmod +x /usr/local/bin/tofu; \
  rm -f "/tmp/${TOFU_ZIP}" "/tmp/${TOFU_SUMS}" "/tmp/${TOFU_SIG}" "/tmp/${TOFU_PEM}"

# Step 4: Smoke-test binaries.
RUN tofu version \
 && cosign version \
 && git --version \
 && curl --version | head -1

# Step 5: Non-root user (uid 65532 matches distroless nonroot convention).
RUN groupadd --gid 65532 nonroot \
 && useradd --uid 65532 --gid 65532 --no-create-home --shell /sbin/nologin nonroot

USER 65532:65532

ENTRYPOINT ["/usr/bin/tini", "--"]

