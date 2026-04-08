import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from utils.json_normalizer import drift_items_to_defectdojo_generic_findings, normalize_terraform_plan


class TestDriftEngineNormalization(unittest.TestCase):
    def test_normalize_filters_noop_and_counts_actions(self) -> None:
        plan_json = {
            "resource_changes": [
                {
                    "address": "azurerm_resource_group.rg",
                    "mode": "managed",
                    "type": "azurerm_resource_group",
                    "name": "rg",
                    "provider_name": "registry.terraform.io/hashicorp/azurerm",
                    "change": {"actions": ["no-op"], "before": {"id": "x"}, "after": {"id": "x"}},
                },
                {
                    "address": "azurerm_storage_account.sa",
                    "mode": "managed",
                    "type": "azurerm_storage_account",
                    "name": "sa",
                    "provider_name": "registry.terraform.io/hashicorp/azurerm",
                    "change": {
                        "actions": ["update"],
                        "before": {"id": "sa-id", "min_tls_version": "TLS1_0"},
                        "after": {"id": "sa-id", "min_tls_version": "TLS1_2"},
                    },
                },
            ]
        }

        summary, items = normalize_terraform_plan(plan_json)

        self.assertEqual(summary.resources_changed, 1)
        self.assertEqual(summary.resources_by_action.get("update"), 1)
        self.assertEqual(items[0]["address"], "azurerm_storage_account.sa")
        self.assertIn("min_tls_version", " ".join(items[0]["changed_paths"]))

    def test_defectdojo_generic_findings_shape(self) -> None:
        items = [
            {
                "address": "azurerm_storage_account.sa",
                "provider_name": "registry.terraform.io/hashicorp/azurerm",
                "actions": ["update"],
                "changed_paths": ["min_tls_version"],
            }
        ]
        payload = drift_items_to_defectdojo_generic_findings(items, scan_date="2026-04-07")
        self.assertIn("findings", payload)
        self.assertEqual(len(payload["findings"]), 1)
        finding = payload["findings"][0]
        self.assertIn("title", finding)
        self.assertIn("severity", finding)
        self.assertIn("date", finding)
        self.assertIn("description", finding)


if __name__ == "__main__":
    unittest.main()
