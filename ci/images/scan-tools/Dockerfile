ARG PYTHON_IMAGE=python:3.11-bookworm
FROM ${PYTHON_IMAGE}

ARG GITLEAKS_VERSION=8.21.2
ARG CHECKOV_VERSION=3.2.502
ARG TRIVY_VERSION=0.69.1
ARG JSONSCHEMA_VERSION=4.25.1

RUN apt-get update \
 && apt-get install -y --no-install-recommends bash ca-certificates curl git jq tar gzip \
 && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
  gitleaks_tgz="gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"; \
  gitleaks_sum="gitleaks_${GITLEAKS_VERSION}_checksums.txt"; \
  curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${gitleaks_tgz}" -o "/tmp/${gitleaks_tgz}"; \
  curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${gitleaks_sum}" -o "/tmp/${gitleaks_sum}"; \
  (cd /tmp && grep " ${gitleaks_tgz}$" "${gitleaks_sum}" | sha256sum -c -); \
  tar -xzf "/tmp/${gitleaks_tgz}" -C /usr/local/bin gitleaks; \
  chmod +x /usr/local/bin/gitleaks; \
  rm -f "/tmp/${gitleaks_tgz}" "/tmp/${gitleaks_sum}"

RUN set -eux; \
  trivy_tgz="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"; \
  trivy_sum="trivy_${TRIVY_VERSION}_checksums.txt"; \
  curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${trivy_tgz}" -o "/tmp/${trivy_tgz}"; \
  curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${trivy_sum}" -o "/tmp/${trivy_sum}"; \
  (cd /tmp && grep " ${trivy_tgz}$" "${trivy_sum}" | sha256sum -c -); \
  tar -xzf "/tmp/${trivy_tgz}" -C /usr/local/bin trivy; \
  chmod +x /usr/local/bin/trivy; \
  rm -f "/tmp/${trivy_tgz}" "/tmp/${trivy_sum}"

RUN pip install --disable-pip-version-check --no-cache-dir \
      "checkov==${CHECKOV_VERSION}" \
      "jsonschema==${JSONSCHEMA_VERSION}"

RUN gitleaks version \
 && checkov --version \
 && trivy --version \
 && jq --version \
 && python3 -c "import jsonschema; print(jsonschema.__version__)"
