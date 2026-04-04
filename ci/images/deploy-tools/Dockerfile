ARG BASE_IMAGE=debian:bookworm-slim
ARG COSIGN_IMAGE=ghcr.io/sigstore/cosign/cosign:v2.2.3@sha256:8fc9cad121611e8479f65f79f2e5bea58949e8a87ffac2a42cb99cf0ff079ba7

FROM ${COSIGN_IMAGE} AS cosign-bin

FROM ${BASE_IMAGE}

ARG TOFU_VERSION=1.8.8
ARG TOFU_LINUX_AMD64_ZIP_SHA256=9e889633bc177b1d266552658020fe8ceb839445fcac82aaa7622952fd9c81bb

RUN apt-get update \
 && apt-get install -y --no-install-recommends bash ca-certificates curl git jq unzip \
 && rm -rf /var/lib/apt/lists/*

COPY --from=cosign-bin /ko-app/cosign /usr/local/bin/cosign

RUN chmod +x /usr/local/bin/cosign

RUN set -eux; \
  TOFU_MM="$(printf '%s' "${TOFU_VERSION}" | awk -F. '{print $1 "." $2}')"; \
  TOFU_ZIP="tofu_${TOFU_VERSION}_linux_amd64.zip"; \
  TOFU_SUMS="tofu_${TOFU_VERSION}_SHA256SUMS"; \
  TOFU_SIG="${TOFU_SUMS}.sig"; \
  TOFU_PEM="${TOFU_SUMS}.pem"; \
  RELEASE_URL="https://github.com/opentofu/opentofu/releases/download/v${TOFU_VERSION}"; \
  curl --proto '=https' --tlsv1.2 -fsSLo "/tmp/${TOFU_ZIP}" "${RELEASE_URL}/${TOFU_ZIP}"; \
  curl --proto '=https' --tlsv1.2 -fsSLo "/tmp/${TOFU_SUMS}" "${RELEASE_URL}/${TOFU_SUMS}"; \
  curl --proto '=https' --tlsv1.2 -fsSLo "/tmp/${TOFU_SIG}" "${RELEASE_URL}/${TOFU_SIG}"; \
  curl --proto '=https' --tlsv1.2 -fsSLo "/tmp/${TOFU_PEM}" "${RELEASE_URL}/${TOFU_PEM}"; \
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

RUN tofu version \
 && cosign version

