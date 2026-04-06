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
    def setUp(self):
        fetch_exceptions.DROPPED.clear()

    def base_ra(self):
        now = datetime.now(timezone.utc)
        return {
            "id": 101,
            "name": "Accept CKV2_CS_AZ_001",
            "owner": "Dev-Team",
            "accepted_by": "Security-Team",
            "decision": "Accept",
            "created": rfc3339(now - timedelta(days=1)),
            "expiration_date": (now + timedelta(days=10)).strftime("%Y-%m-%d"),
            "status": "approved",
            "is_active": True,
            "accepted_findings": [
                "[HIGH] CKV2_CS_AZ_001 /infra/azure/storage/main.tf (Checkov Scan)"
            ],
            "notes": "temporary risk acceptance",
        }

    def test_extract_v2_exception_has_required_strict_fields(self):
        ra = self.base_ra()
        ex, error = fetch_exceptions.extract_v2_exception(ra)

        self.assertIsNone(error)
        self.assertIsNotNone(ex)
        self.assertRegex(ex["id"], r"^[a-f0-9]{64}$")
        self.assertEqual(ex["tool"], "checkov")
        self.assertEqual(ex["rule_id"], "CKV2_CS_AZ_001")
        self.assertEqual(ex["resource"], "infra/azure/storage/main.tf")
        self.assertEqual(ex["severity"], "HIGH")
        self.assertEqual(ex["decision"], "accept")
        self.assertEqual(ex["requested_by"], "dev-team")
        self.assertEqual(ex["approved_by"], "security-team")
        self.assertEqual(ex["source"], "defectdojo")
        self.assertEqual(ex["status"], "approved")

    def test_extract_v2_exception_rejects_four_eyes_violation(self):
        ra = self.base_ra()
        ra["accepted_by"] = "Dev-Team"

        ex, error = fetch_exceptions.extract_v2_exception(ra)

        self.assertIsNone(ex)
        self.assertIn("four_eyes_violation", error)

    def test_extract_v2_exception_rejects_missing_expiration(self):
        ra = self.base_ra()
        ra["expiration_date"] = ""

        ex, error = fetch_exceptions.extract_v2_exception(ra)

        self.assertIsNone(ex)
        self.assertIn("missing_fields", error)

    def test_extract_v2_exception_rejects_invalid_severity(self):
        ra = self.base_ra()
        ra["accepted_findings"] = ["CKV2_CS_AZ_001 infra/main.tf severity=UNKNOWN (Checkov Scan)"]

        ex, error = fetch_exceptions.extract_v2_exception(ra)

        self.assertIsNone(ex)
        self.assertIn("invalid_severity", error)

    def test_extract_v2_exception_rejects_wildcard_resource(self):
        ra = self.base_ra()
        ra["accepted_findings"] = ["CKV2_CS_AZ_001 infra/**/*.tf HIGH (Checkov Scan)"]

        ex, error = fetch_exceptions.extract_v2_exception(ra)

        self.assertIsNone(ex)
        self.assertIn("parsing_error", error)

    def test_extract_v2_exception_fuzzy_fallback_uses_detail_title(self):
        ra = self.base_ra()
        ra["accepted_findings"] = ["CKV2_CS_AZ_001 Storage encryption missing (Checkov Scan)"]
        ra["accepted_finding_details"] = [
            {
                "title": "CKV2_CS_AZ_001 Storage encryption missing (Checkov Scan)",
                "severity": "HIGH",
                "file_path": "infra/azure/storage/main.tf",
            }
        ]

        ex, error = fetch_exceptions.extract_v2_exception(ra)

        self.assertIsNone(error)
        self.assertIsNotNone(ex)
        self.assertEqual(ex["tool"], "checkov")
        self.assertEqual(ex["rule_id"], "CKV2_CS_AZ_001")

    def test_extract_v2_exception_accepts_defectdojo_ui_native_fields(self):
        now = datetime.now(timezone.utc)
        ra = {
            "id": 2,
            "name": "Accept: Ensure That SSH Access Is Restricted From the Internet",
            "decision": "A",
            "owner": "admin",
            "accepted_by": "ghassendridi007@gmail.com",
            "created": rfc3339(now - timedelta(hours=2)),
            "expiration_date": rfc3339(now + timedelta(days=1)),
            "status": "APPROVED",
            "is_active": True,
            "accepted_findings": [364],
            "accepted_finding_details": [
                {
                    "id": 364,
                    "title": "Ensure That SSH Access Is Restricted From the Internet",
                    "severity": "Medium",
                    "description": "Check Type: terraform\nCheck Id: CKV_AZURE_10\nEnsure that SSH access is restricted from the internet",
                    "file_path": "/modules/network/main.tf",
                    "component_name": "module.network.azurerm_network_security_group.public",
                }
            ],
        }

        ex, error = fetch_exceptions.extract_v2_exception(ra)

        self.assertIsNone(error)
        self.assertIsNotNone(ex)
        self.assertEqual(ex["decision"], "accept")
        self.assertEqual(ex["tool"], "checkov")
        self.assertEqual(ex["rule_id"], "CKV_AZURE_10")
        self.assertEqual(ex["resource"], "modules/network/main.tf")
        self.assertEqual(ex["severity"], "MEDIUM")

    def test_is_active_accepted_supports_status_alias_a(self):
        ra = self.base_ra()
        ra["status"] = "A"
        ra["is_active"] = True
        self.assertTrue(fetch_exceptions.is_active_accepted(ra))

    def test_extract_v2_exception_infers_approved_status_when_missing(self):
        now = datetime.now(timezone.utc)
        ra = {
            "id": 2,
            "name": "Accept: Ensure That SSH Access Is Restricted From the Internet",
            "decision": "A",
            "owner": "admin",
            "accepted_by": "ghassendridi007@gmail.com",
            "created": rfc3339(now - timedelta(hours=2)),
            "expiration_date": rfc3339(now + timedelta(days=1)),
            "is_active": True,
            "accepted_findings": [364],
            "accepted_finding_details": [
                {
                    "id": 364,
                    "title": "Ensure That SSH Access Is Restricted From the Internet",
                    "severity": "Medium",
                    "description": "Check Type: terraform\nCheck Id: CKV_AZURE_10\nEnsure that SSH access is restricted from the internet",
                    "file_path": "/modules/network/main.tf",
                    "component_name": "module.network.azurerm_network_security_group.public",
                }
            ],
        }

        ex, error = fetch_exceptions.extract_v2_exception(ra)
        self.assertIsNone(error)
        self.assertIsNotNone(ex)
        self.assertEqual(ex["status"], "approved")

    def test_map_risk_acceptances_drops_when_no_valid_findings(self):
        ra = self.base_ra()
        ra["accepted_findings"] = []

        mapped, meta = fetch_exceptions.map_risk_acceptances([ra])

        self.assertEqual(mapped, [])
        self.assertEqual(meta["total_valid_exceptions"], 0)
        self.assertGreaterEqual(meta["total_dropped"], 1)
        self.assertTrue(any(x["reason"] == "parsing_error" for x in fetch_exceptions.DROPPED))

    def test_is_active_accepted_requires_active_and_approved_status(self):
        ra = self.base_ra()
        self.assertTrue(fetch_exceptions.is_active_accepted(ra))

        ra_inactive = dict(ra)
        ra_inactive["is_active"] = False
        self.assertFalse(fetch_exceptions.is_active_accepted(ra_inactive))

        ra_pending = dict(ra)
        ra_pending["status"] = "pending"
        self.assertFalse(fetch_exceptions.is_active_accepted(ra_pending))


if __name__ == "__main__":
    unittest.main()
