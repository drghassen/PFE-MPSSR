import unittest
import json
from copy import deepcopy
from pathlib import Path
import sys

from jinja2 import Environment, FileSystemLoader

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from utils.enrichment import enrich_drift_items_with_opa


class TestDriftReportTemplate(unittest.TestCase):
    def test_template_serializes_pipeline_correlation_id(self) -> None:
        engine_root = Path(__file__).resolve().parents[1]
        template_dir = engine_root / "templates"
        template = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=False,
        ).get_template("drift-report-template.j2")

        payload = json.loads(
            template.render(
                schema_version="1.0.0",
                ocsf={
                    "version": "1.3.0",
                    "class_uid": 2001,
                    "category_uid": 2,
                    "type_uid": 200100,
                    "time": "2026-05-01T00:00:00Z",
                    "severity_id": 3,
                    "severity": "Medium",
                    "activity_name": "Detect",
                    "activity_id": 1,
                    "metadata": {
                        "product": {
                            "name": "CloudSentinel Drift Engine",
                            "vendor_name": "CloudSentinel",
                            "version": "0.1.0",
                        }
                    },
                },
                cloudsentinel={
                    "run_id": "engine-run-1",
                    "correlation_id": "engine-run-1",
                    "engine": "cloudsentinel-drift-engine",
                    "engine_version": "0.1.0",
                    "tenant_id": None,
                    "subscription_id": None,
                    "pipeline_correlation_id": "cspipe-12345",
                    "terraform_workspace": "default",
                    "terraform_working_dir": "/tmp/iac",
                    "started_at": "2026-05-01T00:00:00Z",
                    "finished_at": "2026-05-01T00:00:01Z",
                    "duration_ms": 1000,
                    "run_status": "drifted",
                },
                drift={
                    "detected": True,
                    "exit_code": 2,
                    "summary": {
                        "resources_changed": 1,
                        "resources_by_action": {"update": 1},
                        "provider_names": ["registry.terraform.io/hashicorp/azurerm"],
                    },
                    "items": [],
                },
                terraform={"version": "1.9.0", "init": {}, "plan": {}},
                errors=[],
            )
        )

        self.assertEqual(
            payload["cloudsentinel"]["pipeline_correlation_id"],
            "cspipe-12345",
        )


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
                    "action_required": "ticket_and_notify",
                    "custodian_policy": None,
                },
                {
                    "resource_id": "azurerm_network_security_group.b",
                    "severity": "CRITICAL",
                    "reason": "Critical drift",
                    "action_required": "runtime_remediation",
                    "custodian_policy": "enforce-nsg-no-open-inbound",
                },
            ],
            "effective_violations": [
                {
                    "resource_id": "azurerm_storage_account.a",
                    "severity": "HIGH",
                    "reason": "High-severity drift",
                    "action_required": "ticket_and_notify",
                    "custodian_policy": None,
                }
            ],
            "excepted_violations": [
                {
                    "resource_id": "azurerm_network_security_group.b",
                    "severity": "CRITICAL",
                    "reason": "Critical drift",
                    "action_required": "runtime_remediation",
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
            by_address["azurerm_storage_account.a"]["action_required"],
            "ticket_and_notify",
        )
        self.assertEqual(
            by_address["azurerm_storage_account.a"]["custodian_policy"],
            None,
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
                    "action_required": "runtime_remediation",
                    "custodian_policy": "enforce-sql-password-rotation",
                }
            ],
            "compliant": [],
        }

        enriched = enrich_drift_items_with_opa(deepcopy(drift_items), opa_decisions)
        item = enriched[0]
        self.assertEqual(item["severity"], "Critical")
        self.assertEqual(item["action_required"], "runtime_remediation")
        self.assertEqual(item["custodian_policy"], "enforce-sql-password-rotation")


if __name__ == "__main__":
    unittest.main()
