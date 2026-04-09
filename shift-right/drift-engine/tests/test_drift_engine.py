import os
import tempfile
import unittest
from pathlib import Path
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import importlib.util

_engine_path = Path(__file__).resolve().parents[1] / "drift-engine.py"
_spec = importlib.util.spec_from_file_location("drift_engine", _engine_path)
if _spec and _spec.loader:
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    sys.modules.setdefault("drift_engine", _mod)

from drift_engine import _choose_tf_binary, _redact_sensitive, load_config
from utils.json_normalizer import _diff_paths
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
class TestLoadConfig(unittest.TestCase):
    def test_env_default_expansion(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write("engine:\n  name: ${MY_ENGINE_NAME:-sentinel-test}\n")
            path = Path(f.name)
        cfg = load_config(path)
        self.assertEqual(cfg.engine.name, "sentinel-test")
        path.unlink()

    def test_env_var_override(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write("engine:\n  name: ${MY_ENGINE_NAME:-sentinel-test}\n")
            path = Path(f.name)
        with patch.dict(os.environ, {"MY_ENGINE_NAME": "overridden"}):
            cfg = load_config(path)
        self.assertEqual(cfg.engine.name, "overridden")
        path.unlink()

    def test_missing_file_raises(self):
        with self.assertRaises(Exception):
            load_config(Path("/nonexistent/drift_config.yaml"))


class TestChooseTfBinary(unittest.TestCase):
    def test_explicit_tf_binary_env(self):
        with patch.dict(os.environ, {"TF_BINARY": "my-tofu"}):
            result = _choose_tf_binary(Path("/tmp"))
        self.assertEqual(result, "my-tofu")

    def test_explicit_tf_bin_env(self):
        env = {k: v for k, v in os.environ.items() if k not in ("TF_BINARY",)}
        env["TF_BIN"] = "custom-bin"
        with patch.dict(os.environ, env, clear=True):
            result = _choose_tf_binary(Path("/tmp"))
        self.assertEqual(result, "custom-bin")

    def test_fallback_to_terraform_no_lockfile(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ("TF_BINARY", "TF_BIN")}
        with patch.dict(os.environ, env, clear=True):
            result = _choose_tf_binary(Path("/nonexistent-dir-xyz"))
        self.assertEqual(result, "terraform")


class TestRedactSensitive(unittest.TestCase):
    def test_redacts_hcl_password_field(self):
        text = '  admin_password = "MySecret@99!"'
        result = _redact_sensitive(text)
        self.assertNotIn("MySecret@99!", result)
        self.assertIn("REDACTED", result)

    def test_redacts_github_pat(self):
        result = _redact_sensitive(
            "token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcd1234"
        )
        self.assertNotIn("ghp_", result)

    def test_redacts_gitlab_pat(self):
        token = "gl" + "pat-" + "abcdefghij1234567890-xyz"
        result = _redact_sensitive(f"ci_token = {token}")
        self.assertNotIn("glpat-", result)

    def test_empty_string_passthrough(self):
        self.assertEqual(_redact_sensitive(""), "")

    def test_clean_string_unchanged(self):
        text = "terraform plan completed successfully"
        self.assertEqual(_redact_sensitive(text), text)


class TestDiffPaths(unittest.TestCase):
    def test_detects_scalar_change(self):
        paths = _diff_paths({"tls": "TLS1_0"}, {"tls": "TLS1_2"})
        self.assertIn("tls", paths)

    def test_no_diff_equal_dicts(self):
        self.assertEqual(_diff_paths({"a": 1, "b": 2}, {"a": 1, "b": 2}), [])

    def test_detects_missing_key(self):
        paths = _diff_paths({"a": 1}, {"a": 1, "b": 2})
        self.assertIn("b", paths)

    def test_list_length_difference(self):
        paths = _diff_paths([1, 2], [1, 2, 3])
        self.assertTrue(len(paths) > 0)

    def test_nested_dict_change(self):
        paths = _diff_paths(
            {"os_disk": {"caching": "None"}},
            {"os_disk": {"caching": "ReadWrite"}},
        )
        self.assertTrue(any("caching" in p for p in paths))

    def test_max_paths_limit(self):
        before = {str(i): i for i in range(100)}
        after  = {str(i): i + 1 for i in range(100)}
        paths  = _diff_paths(before, after, max_paths=10)
        self.assertLessEqual(len(paths), 10)


if __name__ == "__main__":
    unittest.main()
