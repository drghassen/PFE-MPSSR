ARG PYTHON_IMAGE=python:3.11-slim-bookworm
FROM ${PYTHON_IMAGE}

ARG PROWLER_VERSION=5.24.4

RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get install -y --no-install-recommends bash ca-certificates curl git jq \
 && pip install --disable-pip-version-check --no-cache-dir "prowler==${PROWLER_VERSION}" \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN prowler --version \
 && jq --version \
 && python3 --version

RUN groupadd --gid 65532 nonroot \
 && useradd --uid 65532 --gid 65532 --no-create-home nonroot

USER 65532:65532

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["/usr/local/bin/prowler", "--version"]
