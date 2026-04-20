#!/usr/bin/env bash
set -euo pipefail

mkdir -p .cloudsentinel
opa version
bash --version | head -n1
curl --version | head -n1
jq --version
git --version

# Generate ephemeral token for smoke test (same pattern as opa-decision.sh)
_SMOKE_TOKEN="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
cat > .cloudsentinel/opa_auth_config.json <<EOF
{"opa_config":{"auth_token":"${_SMOKE_TOKEN}"}}
EOF

opa run --server --addr=127.0.0.1:8181 \
  --authentication=token \
  --authorization=basic \
  --log-level=error \
  --set=decision_logs.console=true \
  policies/opa/gate \
  policies/opa/system/authz.rego \
  .cloudsentinel/exceptions.json \
  .cloudsentinel/opa_auth_config.json \
  > .cloudsentinel/opa-image-smoke.log 2>&1 &
for i in {1..10}; do
  if curl -sf "http://127.0.0.1:8181/health"; then
    echo "[smoke] OPA server is UP (Zero Trust mode)"
    break
  fi
  echo "[smoke] Waiting for OPA... ($i/10)"
  sleep 2
done
# Verify authenticated read works
curl -sf -H "Authorization: Bearer ${_SMOKE_TOKEN}" \
  "http://127.0.0.1:8181/v1/policies" >/dev/null
echo "[smoke] Authenticated policy read: OK"
# Verify unauthenticated read is DENIED (Zero Trust enforcement)
# OPA may return 401 (auth layer) or 403 (authz layer) — both are correct.
_http_code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8181/v1/policies")"
if [[ "$_http_code" != "200" ]]; then
  echo "[smoke] Unauthenticated read rejected (${_http_code}): OK — Zero Trust enforced"
else
  echo "[smoke][ERROR] Unauthenticated read returned 200 — Zero Trust NOT enforced" >&2
  exit 1
fi