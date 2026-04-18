import unittest
from copy import deepcopy
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from utils.enrichment import enrich_drift_items_with_opa


class TestOPAEnrichment(unittest.TestCase):
    def test_enrichment_uses_effective_and_excepted_violations(self) -> None:
        drift_items = [
            {"address": "azurerm_storage_account.a", "type": "azurerm_storage_account"},
            {
                "address": "azurerm_network_security_group.b",
                "type": "azurerm_network_security_group",
            },
            {"address": "azurerm_resource_group.c", "type": "azurerm_resource_group"},
            {"address": "azurerm_virtual_network.d", "type": "azurerm_virtual_network"},
        ]
        opa_decisions = {
            "violations": [
                {
                    "resource_id": "azurerm_storage_account.a",
                    "severity": "HIGH",
                    "reason": "High-severity drift",
                    "action_required": "auto_remediate",
                    "custodian_policy": "enforce-storage-tls",
                },
                {
                    "resource_id": "azurerm_network_security_group.b",
                    "severity": "CRITICAL",
                    "reason": "Critical drift",
                    "action_required": "immediate_review",
                    "custodian_policy": "enforce-nsg-no-open-inbound",
                },
            ],
            "effective_violations": [
                {
                    "resource_id": "azurerm_storage_account.a",
                    "severity": "HIGH",
                    "reason": "High-severity drift",
                    "action_required": "auto_remediate",
                    "custodian_policy": "enforce-storage-tls",
                }
            ],
            "excepted_violations": [
                {
                    "resource_id": "azurerm_network_security_group.b",
                    "severity": "CRITICAL",
                    "reason": "Critical drift",
                    "action_required": "immediate_review",
                    "custodian_policy": "enforce-nsg-no-open-inbound",
                }
            ],
            "compliant": [
                {"resource_id": "azurerm_resource_group.c", "status": "COMPLIANT"}
            ],
        }

        enriched = enrich_drift_items_with_opa(deepcopy(drift_items), opa_decisions)
        by_address = {i["address"]: i for i in enriched}

        self.assertEqual(by_address["azurerm_storage_account.a"]["severity"], "High")
        self.assertEqual(
            by_address["azurerm_storage_account.a"]["action_required"], "auto_remediate"
        )
        self.assertEqual(
            by_address["azurerm_storage_account.a"]["custodian_policy"],
            "enforce-storage-tls",
        )
        self.assertFalse(by_address["azurerm_storage_account.a"]["opa_excepted"])

        self.assertEqual(
            by_address["azurerm_network_security_group.b"]["severity"], "Info"
        )
        self.assertEqual(
            by_address["azurerm_network_security_group.b"]["action_required"], "none"
        )
        self.assertTrue(by_address["azurerm_network_security_group.b"]["opa_excepted"])

        self.assertEqual(by_address["azurerm_resource_group.c"]["severity"], "Info")
        self.assertTrue(by_address["azurerm_resource_group.c"]["opa_evaluated"])

        self.assertEqual(by_address["azurerm_virtual_network.d"]["severity"], "Medium")
        self.assertEqual(
            by_address["azurerm_virtual_network.d"]["action_required"], "manual_review"
        )
        self.assertFalse(by_address["azurerm_virtual_network.d"]["opa_evaluated"])

    def test_fallback_to_raw_violations_when_effective_missing(self) -> None:
        drift_items = [
            {"address": "azurerm_sql_server.main", "type": "azurerm_sql_server"}
        ]
        opa_decisions = {
            "violations": [
                {
                    "resource_id": "azurerm_sql_server.main",
                    "severity": "CRITICAL",
                    "reason": "Critical drift on SQL password",
                    "action_required": "immediate_review",
                    "custodian_policy": "enforce-sql-password-rotation",
                }
            ],
            "compliant": [],
        }

        enriched = enrich_drift_items_with_opa(deepcopy(drift_items), opa_decisions)
        item = enriched[0]
        self.assertEqual(item["severity"], "Critical")
        self.assertEqual(item["action_required"], "immediate_review")
        self.assertEqual(item["custodian_policy"], "enforce-sql-password-rotation")


if __name__ == "__main__":
    unittest.main()
