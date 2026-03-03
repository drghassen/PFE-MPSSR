import importlib.util
import pathlib
import unittest
from datetime import datetime, timedelta, timezone


MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "fetch-exceptions.py"
SPEC = importlib.util.spec_from_file_location("fetch_exceptions", MODULE_PATH)
fetch_exceptions = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fetch_exceptions)


def rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class FetchExceptionsMappingTests(unittest.TestCase):
    def base_ra(self):
        now = datetime.now(timezone.utc)
        return {
            "id": 101,
            "name": "CKV2_CS_AZ_001",
            "owner": "dev@example.com",
            "approver": "security@example.com",
            "created": rfc3339(now - timedelta(days=2)),
            "expiration_date": (now + timedelta(days=10)).strftime("%Y-%m-%d"),
            "description": "Temporary exception with compensating control",
            "is_active": True,
            "status": "accepted",
            "custom_fields": {
                "scanner": "checkov",
                "resource_id": "azurerm_storage_account.insecure",
                "fingerprint": "fp-abc-123",
                "repo": "cloud-infra",
                "scope_type": "repo",
                "branch_scope": "main",
                "severity": "HIGH",
                "approved_by_role": "APPSEC_L3",
            },
        }

    def test_extract_v2_exception_has_required_enterprise_fields(self):
        ra = self.base_ra()
        ex, error = fetch_exceptions.extract_v2_exception(ra)

        self.assertIsNone(error)
        self.assertIsNotNone(ex)
        self.assertRegex(ex["exception_id"], r"^[0-9a-f-]{36}$")
        self.assertEqual(ex["scanner"], "checkov")
        self.assertEqual(ex["rule_id"], "CKV2_CS_AZ_001")
        self.assertEqual(ex["resource_id"], "azurerm_storage_account.insecure")
        self.assertEqual(ex["fingerprint"], "fp-abc-123")
        self.assertEqual(ex["scope_type"], "repo")
        self.assertEqual(ex["approved_by_role"], "APPSEC_L3")
        self.assertEqual(ex["severity"], "HIGH")

    def test_extract_v2_exception_rejects_missing_fingerprint(self):
        ra = self.base_ra()
        ra["custom_fields"].pop("fingerprint")
        ex, error = fetch_exceptions.extract_v2_exception(ra)

        self.assertIsNone(ex)
        self.assertIn("missing fingerprint/resource_hash", error)

    def test_extract_v2_exception_uses_recommendation_details_fingerprint_fallback(self):
        ra = self.base_ra()
        ra["custom_fields"] = {}
        ra["name"] = "CKV2_CS_AZ_021"
        ra["path"] = "azurerm_network_security_rule.rdp_any_allow"
        ra["recommendation_details"] = (
            "Q0tWMl9DU19BWl8wMjE6L2luZnJhL2F6dXJlL2Rldi90ZXN0cy9jaGVja292L2ZpeHR1cmVzL25zZ19vcGVuXzIyLnRmOjIz"
        )

        ex, error = fetch_exceptions.extract_v2_exception(ra)

        self.assertIsNone(error)
        self.assertIsNotNone(ex)
        self.assertEqual(ex["rule_id"], "CKV2_CS_AZ_021")
        self.assertEqual(ex["resource_id"], "azurerm_network_security_rule.rdp_any_allow")
        self.assertEqual(
            ex["fingerprint"],
            "Q0tWMl9DU19BWl8wMjE6L2luZnJhL2F6dXJlL2Rldi90ZXN0cy9jaGVja292L2ZpeHR1cmVzL25zZ19vcGVuXzIyLnRmOjIz",
        )
        self.assertEqual(ex["requested_by"], "dev@example.com")

    def test_extract_v2_exception_handles_numeric_owner_and_accepted_by_email(self):
        ra = self.base_ra()
        ra["custom_fields"] = {}
        ra["owner"] = 1
        ra["accepted_by"] = "security@example.com"
        ra["name"] = "CKV2_CS_AZ_021"
        ra["path"] = "azurerm_network_security_rule.rdp_any_allow"
        ra["recommendation_details"] = (
            "Q0tWMl9DU19BWl8wMjE6L2luZnJhL2F6dXJlL2Rldi90ZXN0cy9jaGVja292L2ZpeHR1cmVzL25zZ19vcGVuXzIyLnRmOjIz"
        )

        ex, error = fetch_exceptions.extract_v2_exception(ra)

        self.assertIsNone(error)
        self.assertIsNotNone(ex)
        self.assertEqual(ex["requested_by"], "dev-system@example.com")
        self.assertEqual(ex["approved_by"], "security@example.com")

    def test_extract_v2_exception_uses_accepted_finding_component_for_resource(self):
        ra = self.base_ra()
        ra["custom_fields"] = {}
        ra["owner"] = 1
        ra["accepted_by"] = "security@example.com"
        ra["name"] = "CKV2_CS_AZ_021"
        ra["path"] = "No proof has been supplied"
        ra["recommendation_details"] = (
            "Q0tWMl9DU19BWl8wMjE6L2luZnJhL2F6dXJlL2Rldi90ZXN0cy9jaGVja292L2ZpeHR1cmVzL25zZ19vcGVuXzIyLnRmOjIz"
        )
        ra["accepted_findings"] = [178]
        ra["accepted_finding_details"] = [
            {
                "id": 178,
                "component_name": "azurerm_network_security_rule.rdp_any_allow",
                "severity": "CRITICAL",
            }
        ]

        ex, error = fetch_exceptions.extract_v2_exception(ra)

        self.assertIsNone(error)
        self.assertIsNotNone(ex)
        self.assertEqual(ex["resource_id"], "azurerm_network_security_rule.rdp_any_allow")
        self.assertEqual(ex["severity"], "CRITICAL")
        self.assertEqual(ex["accepted_finding_ids"], [178])

    def test_extract_v2_exception_uses_decision_details_as_justification(self):
        ra = self.base_ra()
        ra["custom_fields"] = {}
        ra["name"] = "CKV2_CS_AZ_021"
        ra["path"] = "azurerm_network_security_rule.rdp_any_allow"
        ra["description"] = "Generic description should not win"
        ra["decision_details"] = "Temporary exception approved with compensating controls."
        ra["recommendation_details"] = (
            "Q0tWMl9DU19BWl8wMjE6L2luZnJhL2F6dXJlL2Rldi90ZXN0cy9jaGVja292L2ZpeHR1cmVzL25zZ19vcGVuXzIyLnRmOjIz"
        )

        ex, error = fetch_exceptions.extract_v2_exception(ra)

        self.assertIsNone(error)
        self.assertIsNotNone(ex)
        self.assertEqual(ex["justification"], "Temporary exception approved with compensating controls.")

    def test_extract_v2_exception_rejects_break_glass_ttl_over_7_days(self):
        ra = self.base_ra()
        now = datetime.now(timezone.utc)
        ra["custom_fields"]["break_glass"] = "true"
        ra["custom_fields"]["incident_id"] = "INC-42"
        ra["created"] = rfc3339(now - timedelta(days=1))
        ra["expiration_date"] = (now + timedelta(days=10)).strftime("%Y-%m-%d")

        ex, error = fetch_exceptions.extract_v2_exception(ra)
        self.assertIsNone(ex)
        self.assertIn("break-glass TTL exceeds", error)

    def test_normalize_severity_maps_aliases(self):
        self.assertEqual(fetch_exceptions.normalize_severity("critical"), "CRITICAL")
        self.assertEqual(fetch_exceptions.normalize_severity("informational"), "INFO")
        self.assertEqual(fetch_exceptions.normalize_severity("moderate"), "MEDIUM")


if __name__ == "__main__":
    unittest.main()
