ARG PYTHON_IMAGE=python:3.11-slim-bookworm
FROM ${PYTHON_IMAGE}

# c7n and c7n-azure are released from the same monorepo but use independent
# version numbers: c7n follows 0.9.x, c7n-azure follows 0.7.x.
ARG C7N_VERSION=0.9.43
ARG C7N_AZURE_VERSION=0.7.49

# Install OS-level dependencies first, then Python packages.
# jq is required by the CI wrapper scripts (custodian-autofix.sh) for audit
# log generation via sr_build_details() in pipeline-guard.sh.
# git is required by c7n-azure for source tracking metadata.
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get install -y --no-install-recommends \
      bash \
      ca-certificates \
      curl \
      git \
      jq \
 && pip install --disable-pip-version-check --no-cache-dir \
      "c7n==${C7N_VERSION}" \
      "c7n-azure==${C7N_AZURE_VERSION}" \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Smoke test: verify the tools are present and importable before tagging the image.
# This runs at build time, not at container start — a broken install fails the build.
RUN custodian version \
 && python3 -c "import c7n_azure; print('c7n-azure import ok')" \
 && jq --version \
 && python3 --version

# Non-root user, same uid/gid as every other CloudSentinel image.
# Running as root in CI containers is a security risk: a compromised container
# step would have full write access to the runner filesystem.
RUN groupadd --gid 65532 nonroot \
 && useradd --uid 65532 --gid 65532 --no-create-home nonroot

USER 65532:65532

# Healthcheck used by docker-compose (local dev) and GitLab CI service containers.
# start-period is 30s because c7n-azure loads Azure SDK modules on startup.
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD ["/usr/local/bin/custodian", "version"]
