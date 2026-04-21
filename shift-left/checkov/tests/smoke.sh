#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
OUT_FILE="$REPO_ROOT/.cloudsentinel/checkov_raw.json"
TMP_DIR="$(mktemp -d -t cs-checkov-smoke-XXXXXX)"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

cat > "$TMP_DIR/main.tf" <<'TF'
resource "azurerm_network_security_rule" "ssh_any_allow" {
  name                        = "ssh-any-allow"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-demo"
  network_security_group_name = "nsg-demo"
}
TF

export CHECKOV_SKIP_PATHS=""
bash "$REPO_ROOT/shift-left/checkov/run-checkov.sh" "$TMP_DIR"

test -f "$OUT_FILE"
jq -e 'type == "object" and (.results | type == "object")' "$OUT_FILE" >/dev/null

echo "[smoke][checkov] PASS"
