#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

REAL_PYTHON="$(command -v python3)"
TMPBIN="$(mktemp -d)"
trap 'rm -rf "$TMPBIN"' EXIT

cat > "$TMPBIN/python" <<'PYWRAP'
#!/usr/bin/env bash
set -euo pipefail
REAL_PYTHON="${REAL_PYTHON:?}"
for arg in "$@"; do
  if [[ "$arg" == *"fetch_drift_exceptions.py"* || "$arg" == *"fetch_prowler_exceptions.py"* ]]; then
    exit 1
  fi
done
exec "$REAL_PYTHON" "$@"
PYWRAP
chmod +x "$TMPBIN/python"

export REAL_PYTHON
export PATH="$TMPBIN:$PATH"

rm -rf .cloudsentinel
mkdir -p .cloudsentinel/last-known-good shift-right/drift-engine/output

# signed snapshot for drift degraded mode
cat > .cloudsentinel/last-known-good/drift_exceptions.json <<'JSON'
{"cloudsentinel":{"drift_exceptions":{"schema_version":"1.0.0","exceptions":[]}}}
JSON
(cd .cloudsentinel/last-known-good && sha256sum drift_exceptions.json > drift_exceptions.json.sha256)

# fake drift engine config/entrypoint
cat > /tmp/drift-config-test.yaml <<'YAML'
noop: true
YAML
cat > /tmp/fake-drift-engine.py <<'PY'
#!/usr/bin/env python3
import json, os
out = os.environ.get("DRIFT_OUTPUT_PATH", "shift-right/drift-engine/output/drift-report.json")
os.makedirs(os.path.dirname(out), exist_ok=True)
report = {
  "cloudsentinel": {"correlation_id": "corr-drift", "duration_ms": 10, "terraform_workspace": "default"},
  "drift": {"summary": {}, "items": [], "detected": False, "exit_code": 0},
  "errors": []
}
with open(out, "w", encoding="utf-8") as f:
  json.dump(report, f)
PY
chmod +x /tmp/fake-drift-engine.py

EXCEPTIONS_FETCH_MODE=degraded \
ARM_SUBSCRIPTION_ID=sub-123 \
DRIFT_CONFIG_PATH=/tmp/drift-config-test.yaml \
DRIFT_ENGINE_ENTRYPOINT=/tmp/fake-drift-engine.py \
bash ci/scripts/shift-right/drift-detect.sh

test -f .cloudsentinel/drift_degraded_mode.json
jq -e '.reason=="defectdojo_fetch_failed_snapshot_used"' .cloudsentinel/drift_degraded_mode.json >/dev/null

# signed snapshot for prowler degraded mode
cat > .cloudsentinel/last-known-good/prowler_exceptions.json <<'JSON'
{"cloudsentinel":{"prowler_exceptions":{"schema_version":"1.0.0","exceptions":[]}}}
JSON
(cd .cloudsentinel/last-known-good && sha256sum prowler_exceptions.json > prowler_exceptions.json.sha256)

EXCEPTIONS_FETCH_MODE=degraded \
PROWLER_DETECT_SKIP_SCAN=true \
PROWLER_OCSF_INPUT_PATH=integration-tests/fixtures/prowler-ocsf-minimal.json \
ARM_SUBSCRIPTION_ID=sub-123 \
ARM_CLIENT_ID=cid \
ARM_TENANT_ID=tid \
ARM_CLIENT_SECRET=sec \
bash ci/scripts/shift-right/prowler-detect.sh

test -f .cloudsentinel/prowler_degraded_mode.json
jq -e '.reason=="defectdojo_fetch_failed_snapshot_used"' .cloudsentinel/prowler_degraded_mode.json >/dev/null

echo "test_degraded_mode: OK"
