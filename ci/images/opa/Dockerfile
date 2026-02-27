ARG OPA_VERSION=1.13.1
FROM openpolicyagent/opa:${OPA_VERSION}-static AS opa

FROM alpine:3.20
ARG OPA_VERSION=1.13.1

RUN apk add --no-cache bash curl jq git ca-certificates \
 && update-ca-certificates
COPY --from=opa /opa /usr/local/bin/opa
COPY --from=opa /opa /opa

# Smoke-check binary compatibility during build; fail fast if broken.
RUN /usr/local/bin/opa version >/dev/null

RUN addgroup -S opa && adduser -S -G opa -u 10001 opa
USER 10001

ENV OPA_VERSION=${OPA_VERSION}
