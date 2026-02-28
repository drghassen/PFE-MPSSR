ARG OPA_VERSION=1.13.1
FROM openpolicyagent/opa:${OPA_VERSION}-static AS opa

FROM debian:bookworm-slim
ARG OPA_VERSION=1.13.1

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash curl jq git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=opa /opa /usr/local/bin/opa
COPY --from=opa /opa /opa

# Smoke-check binary compatibility during build; fail fast if broken.
RUN /usr/local/bin/opa version >/dev/null

RUN groupadd -r opa && useradd -r -g opa -u 10001 opa
USER 10001

ENV OPA_VERSION=${OPA_VERSION}
