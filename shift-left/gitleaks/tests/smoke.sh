#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
OUT_FILE="$REPO_ROOT/.cloudsentinel/gitleaks_raw.json"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

export SCAN_MODE="local"
export SCAN_TARGET="repo"
export USE_BASELINE="false"
export CLOUDSENTINEL_TIMEOUT="${CLOUDSENTINEL_TIMEOUT:-120}"

bash "$REPO_ROOT/shift-left/gitleaks/run-gitleaks.sh"

test -f "$OUT_FILE"
jq -e 'type == "array"' "$OUT_FILE" >/dev/null
jq -e 'all(.[]; ((.CloudSentinelSecretHash // .SecretHash // "") | type == "string" and test("^[0-9a-f]{64}$")))' "$OUT_FILE" >/dev/null

cat > "$TMP_DIR/secrets.tf" <<'EOF'
variable "admin_password" {
  default = "Password123!"
}

admin_password = "Password123!"
db_password = "SuperSecretPassword123!"
ARM_CLIENT_SECRET = "abcdefghijklmnopqrstuvwxyzABCDEF123456"
EOF

set +e
gitleaks detect \
  --no-git \
  --source "$TMP_DIR" \
  --redact \
  --config "$REPO_ROOT/shift-left/gitleaks/gitleaks.toml" \
  --report-format json \
  --report-path "$TMP_DIR/report.json" \
  --no-banner >/dev/null 2>&1
SYNTH_RC=$?
set -e

if [[ "$SYNTH_RC" -gt 1 ]]; then
  echo "[smoke][gitleaks][FAIL] synthetic secret scan execution failed rc=$SYNTH_RC" >&2
  exit 1
fi

jq -e '
  ([.[].RuleID] | index("terraform-password-variable-default"))
  and ([.[].RuleID] | index("generic-password-assignment"))
  and ([.[].RuleID] | index("azure-client-secret"))
' "$TMP_DIR/report.json" >/dev/null

echo "[smoke][gitleaks] PASS"
