from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import unittest

from utils.json_normalizer import (
    DriftSummary,
    _diff_paths,
    classify_drift_severity,
    drift_items_to_defectdojo_generic_findings,
    normalize_terraform_plan,
)


# ---------------------------------------------------------------------------
# _diff_paths
# ---------------------------------------------------------------------------


class TestDiffPaths(unittest.TestCase):
    def test_equal_scalars_returns_empty(self):
        self.assertEqual(_diff_paths("foo", "foo"), [])

    def test_different_scalars_returns_root(self):
        self.assertEqual(_diff_paths("foo", "bar"), ["$"])

    def test_type_mismatch_returns_path(self):
        self.assertEqual(_diff_paths(1, "1"), ["$"])

    def test_null_vs_absent_key(self):
        # {"a": None} vs {"a": "x"} → a changed
        paths = _diff_paths({"a": None}, {"a": "x"})
        self.assertIn("a", paths)

    def test_absent_key_in_before(self):
        paths = _diff_paths({}, {"new_key": "value"})
        self.assertIn("new_key", paths)

    def test_absent_key_in_after(self):
        paths = _diff_paths({"old_key": "value"}, {})
        self.assertIn("old_key", paths)

    def test_nested_dict_change(self):
        before = {"network_acls": {"default_action": "Allow"}}
        after = {"network_acls": {"default_action": "Deny"}}
        paths = _diff_paths(before, after)
        self.assertIn("network_acls.default_action", paths)

    def test_list_length_change(self):
        paths = _diff_paths([1, 2], [1, 2, 3])
        # root list path must appear
        self.assertTrue(any(p == "$" or "[" in p or p == "" for p in paths))

    def test_list_element_change(self):
        paths = _diff_paths([1, 2, 3], [1, 99, 3])
        self.assertIn("[1]", paths)

    def test_identical_dicts_returns_empty(self):
        d = {"a": 1, "b": [1, 2], "c": {"x": True}}
        self.assertEqual(_diff_paths(d, d), [])

    def test_max_paths_cap(self):
        # Many keys differ — result must not exceed max_paths
        before = {str(i): i for i in range(100)}
        after = {str(i): i + 1 for i in range(100)}
        paths = _diff_paths(before, after, max_paths=10)
        self.assertLessEqual(len(paths), 10)

    def test_prefix_prepended(self):
        paths = _diff_paths({"x": 1}, {"x": 2}, prefix="root")
        self.assertTrue(all(p.startswith("root") for p in paths))

    def test_entire_output_value_changed(self):
        # Mirrors the real drift: output value "cs-dev-vm" → "new-vm"
        paths = _diff_paths("cs-dev-vm", "new-vm")
        self.assertEqual(paths, ["$"])


# ---------------------------------------------------------------------------
# normalize_terraform_plan — resource drift
# ---------------------------------------------------------------------------


def _make_plan(resource_drift=None, resource_changes=None, output_changes=None):
    plan = {}
    if resource_drift is not None:
        plan["resource_drift"] = resource_drift
    if resource_changes is not None:
        plan["resource_changes"] = resource_changes
    if output_changes is not None:
        plan["output_changes"] = output_changes
    return plan


class TestNormalizeTerraformPlan(unittest.TestCase):
    def test_empty_plan_returns_zero_items(self):
        summary, items = normalize_terraform_plan({})
        self.assertEqual(summary.resources_changed, 0)
        self.assertEqual(items, [])

    def test_resource_drift_detected(self):
        plan = _make_plan(
            resource_drift=[
                {
                    "address": "azurerm_storage_account.sa",
                    "mode": "managed",
                    "type": "azurerm_storage_account",
                    "name": "sa",
                    "provider_name": "registry.terraform.io/hashicorp/azurerm",
                    "change": {
                        "actions": ["update"],
                        "before": {"min_tls_version": "TLS1_0", "id": "/sub/rg/sa"},
                        "after": {"min_tls_version": "TLS1_2", "id": "/sub/rg/sa"},
                    },
                }
            ]
        )
        summary, items = normalize_terraform_plan(plan)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["address"], "azurerm_storage_account.sa")
        self.assertIn("min_tls_version", items[0]["changed_paths"])
        self.assertEqual(items[0]["resource_id"], "/sub/rg/sa")
        self.assertTrue(items[0]["drifted"])

    def test_resource_changes_also_processed(self):
        plan = _make_plan(
            resource_changes=[
                {
                    "address": "azurerm_resource_group.rg",
                    "mode": "managed",
                    "type": "azurerm_resource_group",
                    "name": "rg",
                    "provider_name": "registry.terraform.io/hashicorp/azurerm",
                    "change": {
                        "actions": ["update"],
                        "before": {"tags": {"env": "dev"}},
                        "after": {"tags": {"env": "prod"}},
                    },
                }
            ]
        )
        summary, items = normalize_terraform_plan(plan)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["type"], "azurerm_resource_group")

    def test_noop_with_no_diff_is_skipped(self):
        # no-op where before == after must produce zero drift items
        plan = _make_plan(
            resource_drift=[
                {
                    "address": "azurerm_virtual_network.vnet",
                    "mode": "managed",
                    "type": "azurerm_virtual_network",
                    "name": "vnet",
                    "provider_name": "registry.terraform.io/hashicorp/azurerm",
                    "change": {
                        "actions": ["no-op"],
                        "before": {"address_space": ["10.0.0.0/16"]},
                        "after": {"address_space": ["10.0.0.0/16"]},
                    },
                }
            ]
        )
        summary, items = normalize_terraform_plan(plan)
        self.assertEqual(len(items), 0)

    def test_noop_with_diff_is_reported_as_drift(self):
        # Terraform sometimes emits no-op even when refresh-only detects a delta.
        plan = _make_plan(
            resource_drift=[
                {
                    "address": "azurerm_linux_virtual_machine.vm",
                    "mode": "managed",
                    "type": "azurerm_linux_virtual_machine",
                    "name": "vm",
                    "provider_name": "registry.terraform.io/hashicorp/azurerm",
                    "change": {
                        "actions": ["no-op"],
                        "before": {"os_disk": [{"caching": "None"}]},
                        "after": {"os_disk": [{"caching": "ReadWrite"}]},
                    },
                }
            ]
        )
        summary, items = normalize_terraform_plan(plan)
        self.assertEqual(len(items), 1)

    def test_duplicate_addresses_deduplicated(self):
        rc = {
            "address": "azurerm_storage_account.sa",
            "mode": "managed",
            "type": "azurerm_storage_account",
            "name": "sa",
            "provider_name": "registry.terraform.io/hashicorp/azurerm",
            "change": {
                "actions": ["update"],
                "before": {"min_tls_version": "TLS1_0"},
                "after": {"min_tls_version": "TLS1_2"},
            },
        }
        plan = _make_plan(resource_drift=[rc], resource_changes=[rc])
        summary, items = normalize_terraform_plan(plan)
        addresses = [i["address"] for i in items]
        self.assertEqual(len(addresses), len(set(addresses)))

    def test_provider_names_collected(self):
        plan = _make_plan(
            resource_drift=[
                {
                    "address": "azurerm_resource_group.rg",
                    "mode": "managed",
                    "type": "azurerm_resource_group",
                    "name": "rg",
                    "provider_name": "registry.terraform.io/hashicorp/azurerm",
                    "change": {
                        "actions": ["update"],
                        "before": {"location": "westeurope"},
                        "after": {"location": "eastus"},
                    },
                }
            ]
        )
        summary, items = normalize_terraform_plan(plan)
        self.assertIn("registry.terraform.io/hashicorp/azurerm", summary.provider_names)

    def test_resource_id_extracted_from_after(self):
        plan = _make_plan(
            resource_drift=[
                {
                    "address": "azurerm_key_vault.kv",
                    "mode": "managed",
                    "type": "azurerm_key_vault",
                    "name": "kv",
                    "provider_name": "registry.terraform.io/hashicorp/azurerm",
                    "change": {
                        "actions": ["update"],
                        "before": {"network_acls": {"default_action": "Allow"}, "id": "/sub/rg/kv"},
                        "after": {"network_acls": {"default_action": "Deny"}, "id": "/sub/rg/kv"},
                    },
                }
            ]
        )
        _, items = normalize_terraform_plan(plan)
        self.assertEqual(items[0]["resource_id"], "/sub/rg/kv")

    def test_resource_id_falls_back_to_before(self):
        plan = _make_plan(
            resource_drift=[
                {
                    "address": "azurerm_key_vault.kv",
                    "mode": "managed",
                    "type": "azurerm_key_vault",
                    "name": "kv",
                    "provider_name": "registry.terraform.io/hashicorp/azurerm",
                    "change": {
                        "actions": ["update"],
                        "before": {"network_acls": {}, "id": "/sub/rg/kv-old"},
                        "after": {"network_acls": {"default_action": "Deny"}},
                    },
                }
            ]
        )
        _, items = normalize_terraform_plan(plan)
        self.assertEqual(items[0]["resource_id"], "/sub/rg/kv-old")


# ---------------------------------------------------------------------------
# normalize_terraform_plan — output drift (mirrors the 4-output CI run)
# ---------------------------------------------------------------------------


class TestNormalizeTerraformPlanOutputs(unittest.TestCase):
    def _output_change(self, before, after, actions=None):
        return {
            "actions": actions or ["update"],
            "before": before,
            "after": after,
        }

    def test_four_output_drift_matches_ci_run(self):
        # Replicates the exact drift seen in the CI pipeline (2026-04-27)
        plan = _make_plan(
            output_changes={
                "db_admin_login": self._output_change("old-admin", "csadmin"),
                "db_name": self._output_change("old-db", "cloudsentinel"),
                "resource_group_name": self._output_change("old-rg", "cs-dev-rg"),
                "vm_name": self._output_change("old-vm", "cs-dev-vm"),
            }
        )
        summary, items = normalize_terraform_plan(plan)
        self.assertEqual(summary.resources_changed, 4)
        addresses = {i["address"] for i in items}
        self.assertEqual(
            addresses,
            {"output.db_admin_login", "output.db_name", "output.resource_group_name", "output.vm_name"},
        )
        for item in items:
            self.assertEqual(item["mode"], "output")
            self.assertEqual(item["type"], "output")
            self.assertIsNone(item["resource_id"])
            self.assertIn("$", item["changed_paths"])

    def test_unchanged_output_not_reported(self):
        plan = _make_plan(
            output_changes={
                "vm_name": self._output_change("cs-dev-vm", "cs-dev-vm"),  # no change
                "db_name": self._output_change("old-db", "new-db"),
            }
        )
        summary, items = normalize_terraform_plan(plan)
        self.assertEqual(summary.resources_changed, 1)
        self.assertEqual(items[0]["address"], "output.db_name")

    def test_output_actions_default_to_update(self):
        plan = _make_plan(
            output_changes={
                "vm_name": {"before": "old", "after": "new"},  # no "actions" key
            }
        )
        _, items = normalize_terraform_plan(plan)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["actions"], ["update"])

    def test_null_before_vs_string_after_is_drift(self):
        plan = _make_plan(
            output_changes={
                "vm_name": self._output_change(None, "cs-dev-vm"),
            }
        )
        _, items = normalize_terraform_plan(plan)
        self.assertEqual(len(items), 1)

    def test_string_before_vs_null_after_is_drift(self):
        plan = _make_plan(
            output_changes={
                "vm_name": self._output_change("cs-dev-vm", None),
            }
        )
        _, items = normalize_terraform_plan(plan)
        self.assertEqual(len(items), 1)


# ---------------------------------------------------------------------------
# classify_drift_severity
# ---------------------------------------------------------------------------


class TestClassifyDriftSeverity(unittest.TestCase):
    def test_critical_nsg_security_rule(self):
        sev = classify_drift_severity("azurerm_network_security_group", ["security_rule"])
        self.assertEqual(sev, "Critical")

    def test_critical_vm_admin_password(self):
        sev = classify_drift_severity("azurerm_linux_virtual_machine", ["admin_password"])
        self.assertEqual(sev, "Critical")

    def test_high_storage_tls(self):
        sev = classify_drift_severity("azurerm_storage_account", ["min_tls_version"])
        self.assertEqual(sev, "High")

    def test_medium_default_for_unknown_type(self):
        sev = classify_drift_severity("azurerm_resource_group", ["tags"])
        self.assertEqual(sev, "Medium")

    def test_medium_default_for_unknown_path(self):
        sev = classify_drift_severity("azurerm_storage_account", ["location"])
        self.assertEqual(sev, "Medium")

    def test_output_type_returns_medium(self):
        # Output-type drift has no entry in _SEVERITY_MAP → Medium
        sev = classify_drift_severity("output", ["$"])
        self.assertEqual(sev, "Medium")

    def test_first_matching_path_wins(self):
        # First path is a critical hit
        sev = classify_drift_severity(
            "azurerm_network_security_group",
            ["security_rule", "tags"],
        )
        self.assertEqual(sev, "Critical")

    def test_empty_changed_paths_returns_medium(self):
        sev = classify_drift_severity("azurerm_key_vault", [])
        self.assertEqual(sev, "Medium")


# ---------------------------------------------------------------------------
# drift_items_to_defectdojo_generic_findings
# ---------------------------------------------------------------------------


class TestDriftItemsToDefectDojo(unittest.TestCase):
    def _item(self, **kwargs):
        base = {
            "address": "azurerm_storage_account.sa",
            "type": "azurerm_storage_account",
            "actions": ["update"],
            "changed_paths": ["min_tls_version"],
            "provider_name": "registry.terraform.io/hashicorp/azurerm",
        }
        base.update(kwargs)
        return base

    def test_single_item_produces_one_finding(self):
        result = drift_items_to_defectdojo_generic_findings([self._item()], "2026-04-27")
        self.assertEqual(len(result["findings"]), 1)

    def test_severity_from_opa_evaluation_used(self):
        item = self._item(opa_evaluated=True, severity="Critical")
        result = drift_items_to_defectdojo_generic_findings([item], "2026-04-27")
        self.assertEqual(result["findings"][0]["severity"], "Critical")

    def test_static_classification_when_no_opa(self):
        item = self._item()  # no opa_evaluated key
        result = drift_items_to_defectdojo_generic_findings([item], "2026-04-27")
        self.assertEqual(result["findings"][0]["severity"], "High")

    def test_finding_title_contains_address(self):
        result = drift_items_to_defectdojo_generic_findings([self._item()], "2026-04-27")
        self.assertIn("azurerm_storage_account.sa", result["findings"][0]["title"])

    def test_empty_items_produces_empty_findings(self):
        result = drift_items_to_defectdojo_generic_findings([], "2026-04-27")
        self.assertEqual(result["findings"], [])

    def test_changed_paths_truncated_to_20(self):
        paths = [f"path_{i}" for i in range(30)]
        item = self._item(changed_paths=paths)
        result = drift_items_to_defectdojo_generic_findings([item], "2026-04-27")
        desc = result["findings"][0]["description"]
        # Only first 20 paths should appear in description
        self.assertIn("path_19", desc)
        self.assertNotIn("path_20", desc)


if __name__ == "__main__":
    unittest.main()
