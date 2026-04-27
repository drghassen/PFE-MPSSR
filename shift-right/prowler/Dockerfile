# =============================================================================
# CloudSentinel — Prowler Sensor Image
#
# Base: prowlercloud/prowler:5.24.4 (Prowler OSS, Debian Bookworm slim)
#       Tag 4.6.0 never existed on Docker Hub — Prowler jumped directly to v5.
#       Digest pinned to the manifest-list sha256 (multi-arch index), matching
#       what `docker pull` and `docker inspect --format '{{index .RepoDigests 0}}'`
#       would return. Update after each upstream Prowler release:
#         docker pull prowlercloud/prowler:5.24.4
#         docker inspect prowlercloud/prowler:5.24.4 \
#           --format '{{index .RepoDigests 0}}'
#
# Added on top of the base image:
#   jq   — OCSF→Generic Findings conversion in run-prowler.sh
#   curl — health checks and DefectDojo API calls in CI scripts
#   (python3 + azure-identity + requests are already in the prowler base)
#
# ENTRYPOINT ["prowler"] lets the image be used standalone:
#   docker run <image> azure --subscription-ids <sub> --sp-env-auth ...
# GitLab CI jobs override with entrypoint: [""] and run bash scripts directly.
# =============================================================================

FROM prowlercloud/prowler:5.24.4@sha256:29b5f26932b536c545d65ea7b77b33f884747486589ecff45a4b10f7583c256b

LABEL org.opencontainers.image.title="CloudSentinel Prowler Sensor" \
      org.opencontainers.image.version="5.24.4" \
      org.opencontainers.image.source="https://gitlab.com/drghassen/pfe-cloud-sentinel" \
      cloudsentinel.component="sensor" \
      cloudsentinel.role="compliance-audit-prowler"

# Switch to root only for package installation; drop back immediately.
USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         jq \
         curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && jq --version \
    && curl --version | head -1

# Return to the non-root prowler user shipped by the base image.
USER prowler

# Container health is defined as "toolchain is executable".
# This image is a batch scanner (not a long-running API), so healthcheck must
# remain local and deterministic: no external network calls to Azure/DefectDojo.
HEALTHCHECK --interval=5m --timeout=15s --start-period=30s --retries=3 \
  CMD /bin/bash -lc '\
    command -v jq >/dev/null 2>&1 && \
    command -v curl >/dev/null 2>&1 && \
    if command -v prowler >/dev/null 2>&1; then \
      prowler --version >/dev/null 2>&1; \
    else \
      _p="$(find /home /root /usr /opt -maxdepth 7 -name prowler -type f -executable 2>/dev/null | head -1 || true)"; \
      test -n "${_p}" && "${_p}" --version >/dev/null 2>&1; \
    fi'

# Allow CI to pass arbitrary subcommands: azure, aws, --version, etc.
ENTRYPOINT ["prowler"]
CMD ["--help"]
