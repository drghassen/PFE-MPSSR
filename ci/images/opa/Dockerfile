ARG OPA_VERSION=1.13.1
FROM openpolicyagent/opa:${OPA_VERSION}-static AS opa

FROM debian:bookworm-slim
ARG OPA_VERSION=1.13.1

RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get install -y --no-install-recommends \
      bash curl jq git ca-certificates openssl \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=opa /opa /usr/local/bin/opa
COPY --from=opa /opa /opa

# Smoke-check binary compatibility during build; fail fast if broken.
RUN /usr/local/bin/opa version >/dev/null

RUN groupadd -r opa && useradd -r -g opa -u 10001 opa
USER 10001

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["/usr/local/bin/opa", "version"]

ENV OPA_VERSION=${OPA_VERSION}
