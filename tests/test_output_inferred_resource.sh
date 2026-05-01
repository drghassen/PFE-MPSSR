#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

python - <<'PY'
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path("shift-right/drift-engine").resolve()))
from utils.json_normalizer import normalize_terraform_plan

plan = {
    "output_changes": {
        "vm_name": {"actions": ["update"], "before": "old", "after": "new"}
    },
    "resource_changes": [
        {
            "address": "azurerm_linux_virtual_machine.vm",
            "mode": "managed",
            "type": "azurerm_linux_virtual_machine",
            "name": "vm",
            "provider_name": "registry.terraform.io/hashicorp/azurerm",
            "change": {
                "actions": ["update"],
                "before": {"name": "new"},
                "after": {"name": "new"},
            },
        }
    ],
    "configuration": {
        "root_module": {
            "outputs": {
                "vm_name": {
                    "expression": {
                        "references": ["azurerm_linux_virtual_machine.vm"]
                    }
                }
            }
        }
    },
}
summary, items = normalize_terraform_plan(plan)
addresses = {item["address"] for item in items}
assert "output.vm_name" in addresses
assert "azurerm_linux_virtual_machine.vm" in addresses
inferred = next(item for item in items if item["address"] == "azurerm_linux_virtual_machine.vm")
assert inferred["provenance"] == "inferred_from_output"
assert inferred["resource_id"] is None
assert summary.resources_changed == 2

plan_output_only = {
    "output_changes": {
        "vm_name": {"actions": ["update"], "before": "old", "after": "new"}
    }
}
_, output_only_items = normalize_terraform_plan(plan_output_only)
assert [item["address"] for item in output_only_items] == ["output.vm_name"]

records = []
class Capture(logging.Handler):
    def emit(self, record):
        records.append(record.getMessage())

logger = logging.getLogger("utils.json_normalizer")
handler = Capture()
logger.addHandler(handler)
logger.setLevel(logging.WARNING)
try:
    normalize_terraform_plan(plan_output_only)
finally:
    logger.removeHandler(handler)
assert "infer_resources_skipped" in records
PY

echo "test_output_inferred_resource: OK"
