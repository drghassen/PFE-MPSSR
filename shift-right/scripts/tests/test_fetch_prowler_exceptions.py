import importlib.util
import os
import pathlib
import unittest
from requests.exceptions import HTTPError
from unittest.mock import patch


MODULE_PATH = (
    pathlib.Path(__file__).resolve().parents[1] / "fetch_prowler_exceptions.py"
)
SPEC = importlib.util.spec_from_file_location("fetch_prowler_exceptions", MODULE_PATH)
fetch_prowler_exceptions = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fetch_prowler_exceptions)


class FetchProwlerExceptionsTests(unittest.TestCase):
    def _base_finding(self):
        return {
            "id": 9001,
            "risk_accepted": True,
            "title": "Prowler finding: storage_default_network_access_rule_is_denied",
            "vuln_id_from_tool": "prowler_check:storage_default_network_access_rule_is_denied",
            "component_name": "/subscriptions/123/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1",
            "resource_type": "Microsoft.Storage/storageAccounts",
            "accepted_risks": [
                {
                    "id": 77,
                    "owner": {"id": 1, "username": "alice"},
                    "accepted_by": {"id": 2, "username": "bob"},
                    "created": "2026-04-01T10:00:00Z",
                    "expiration_date": "2026-05-01",
                }
            ],
        }

    def _scope(self):
        return {
            "repos": ["group/project"],
            "branches": ["main"],
            "environments": ["production"],
        }

    def test_parse_ra_to_exception_uses_structured_fields(self):
        finding = self._base_finding()
        ex = fetch_prowler_exceptions._parse_ra_to_exception(finding, self._scope())

        self.assertIsNotNone(ex)
        self.assertEqual(
            ex["check_id"], "storage_default_network_access_rule_is_denied"
        )
        self.assertEqual(ex["resource_id"], finding["component_name"])
        self.assertEqual(ex["resource_type"], finding["resource_type"])
        self.assertEqual(ex["requested_by"], "alice")
        self.assertEqual(ex["approved_by"], "bob")

    def test_parse_ra_to_exception_rejects_missing_structured_context(self):
        finding = self._base_finding()
        finding.pop("vuln_id_from_tool", None)
        finding.pop("component_name", None)
        finding["description"] = "Prowler finding without context"

        ex = fetch_prowler_exceptions._parse_ra_to_exception(finding, self._scope())
        self.assertIsNone(ex)

    def test_parse_ra_to_exception_uses_resource_type_from_description(self):
        finding = self._base_finding()
        finding.pop("resource_type", None)
        finding["description"] = (
            "- check_id: storage_default_network_access_rule_is_denied\n"
            "- resource_id: /subscriptions/123/resourceGroups/rg/providers/"
            "Microsoft.Storage/storageAccounts/sa1\n"
            "- resource_type: Microsoft.Storage/storageAccounts"
        )

        ex = fetch_prowler_exceptions._parse_ra_to_exception(finding, self._scope())
        self.assertIsNotNone(ex)
        self.assertEqual(ex["resource_type"], "Microsoft.Storage/storageAccounts")

    def test_build_scope_omits_empty_repo_branch_values(self):
        with patch.dict(os.environ, {}, clear=True):
            scope = fetch_prowler_exceptions._build_scope("production")

        self.assertEqual(scope["repos"], [])
        self.assertEqual(scope["branches"], [])
        self.assertEqual(scope["environments"], ["production"])

    def test_fetch_risk_acceptances_applies_explicit_engagement_filter(self):
        class _FakeResponse:
            def raise_for_status(self):
                return None

            def json(self):
                return {"results": [{"id": 1, "risk_accepted": True}], "next": None}

        with patch.object(
            fetch_prowler_exceptions.requests, "get", return_value=_FakeResponse()
        ) as mocked_get:
            out = fetch_prowler_exceptions.fetch_risk_acceptances(
                base_url="http://dojo.local",
                api_key="token",
                engagement="1234",
            )

        self.assertEqual(len(out), 1)
        _, kwargs = mocked_get.call_args
        self.assertEqual(kwargs["params"]["engagement"], "1234")

    def test_fetch_risk_acceptances_fallback_mode_filters_strictly(self):
        class _RejectedResponse:
            status_code = 400

        class _RejectedCall:
            def raise_for_status(self):
                raise HTTPError(response=_RejectedResponse())

        class _FallbackCall:
            def raise_for_status(self):
                return None

            def json(self):
                return {
                    "results": [
                        {"id": 1, "risk_accepted": True, "engagement": "1234"},
                        {"id": 2, "risk_accepted": True, "engagement": "8888"},
                        {"id": 3, "risk_accepted": True},
                    ],
                    "next": None,
                }

        with patch.object(
            fetch_prowler_exceptions.requests,
            "get",
            side_effect=[_RejectedCall(), _FallbackCall()],
        ):
            out = fetch_prowler_exceptions.fetch_risk_acceptances(
                base_url="http://dojo.local",
                api_key="token",
                engagement="1234",
            )

        self.assertEqual([f["id"] for f in out], [1])


if __name__ == "__main__":
    unittest.main()
