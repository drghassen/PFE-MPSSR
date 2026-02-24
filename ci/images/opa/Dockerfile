ARG OPA_VERSION=1.13.1
FROM openpolicyagent/opa:${OPA_VERSION} AS opa

FROM alpine:3.20
ARG OPA_VERSION=1.13.1

RUN apk add --no-cache bash curl jq git ca-certificates
COPY --from=opa /opa /usr/local/bin/opa

RUN adduser -D -u 10001 opa
USER 10001

ENV OPA_VERSION=${OPA_VERSION}
