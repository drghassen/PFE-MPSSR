"""
Communication and contract tests for all drift-engine modules.

Verifies that every module interface, data flow, and state transition
works correctly after refactoring into separate utility modules.

Coverage:
  - Module imports and re-exports
  - plan_parser ↔ diff_engine data contract
  - security_taxonomy ↔ json_normalizer data contract
  - app_config loading and field propagation
  - redaction utilities
  - path_resolver utilities
  - report_builder output shape
  - DriftEngine phase isolation (each _run_* method independently)
  - DriftEngine state machine transitions across phases
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# ---------------------------------------------------------------------------
# Load drift-engine.py (hyphen in name requires importlib)
# ---------------------------------------------------------------------------

_ENGINE_PATH = Path(__file__).resolve().parents[1] / "drift-engine.py"
_spec = importlib.util.spec_from_file_location("drift_engine_module", _ENGINE_PATH)
_drift_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_drift_mod)
DriftEngine = _drift_mod.DriftEngine

# ---------------------------------------------------------------------------
# Imports under test
# ---------------------------------------------------------------------------

from utils.diff_engine import _diff_paths, _extract_changed_paths
from utils.plan_parser import (
    _actions_key,
    _guess_resource_address_from_reference,
    _iter_resource_changes,
    _resource_name_from_address,
    _resource_type_from_address,
    _safe_dict,
    _safe_list_str,
)
from utils.security_taxonomy import (
    _PATH_SEVERITY_MAP,
    _RESOURCE_TYPE_FALLBACK_SEVERITY,
    _SECURITY_DIMENSIONS,
    _SEVERITY_ORDER,
    classify_drift_severity,
    classify_security_dimensions,
)
from utils.json_normalizer import (
    DriftSummary,
    _diff_paths as jn_diff_paths,
    classify_drift_severity as jn_classify_severity,
    classify_security_dimensions as jn_classify_dims,
    drift_items_to_defectdojo_generic_findings,
    normalize_terraform_plan,
)
from utils.app_config import (
    AppConfig,
    AzureConfig,
    DefectDojoSection,
    EngineConfig,
    OPASection,
    ReportConfig,
    TerraformConfig,
    TerraformInitConfig,
    TerraformPlanConfig,
    _bool_from_env,
    _expand_env_placeholders,
    load_config,
)
from utils.redaction import redact_sensitive, safe_env_snapshot
from utils.path_resolver import choose_tf_binary, resolve_engine_root, resolve_path_under
from utils.report_builder import (
    SCHEMA_VERSION,
    build_report_context,
    render_report,
    write_json,
)
from utils.terraform_runner import TerraformCommandResult, TerraformRunner

_ENGINE_ROOT = Path(__file__).resolve().parents[1]
_TEMPLATE_PATH = _ENGINE_ROOT / "templates" / "drift-report-template.j2"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ===========================================================================
# 1. MODULE IMPORTS — tous les modules s'importent sans erreur
# ===========================================================================


class TestModuleImports(unittest.TestCase):

    def test_diff_engine_exports(self):
        self.assertTrue(callable(_diff_paths))
        self.assertTrue(callable(_extract_changed_paths))

    def test_plan_parser_exports(self):
        for fn in (_actions_key, _iter_resource_changes, _safe_dict,
                   _safe_list_str, _resource_type_from_address,
                   _resource_name_from_address, _guess_resource_address_from_reference):
            self.assertTrue(callable(fn))

    def test_security_taxonomy_exports(self):
        self.assertTrue(callable(classify_security_dimensions))
        self.assertTrue(callable(classify_drift_severity))
        self.assertIsInstance(_SECURITY_DIMENSIONS, dict)
        self.assertIsInstance(_PATH_SEVERITY_MAP, dict)
        self.assertIsInstance(_SEVERITY_ORDER, list)

    def test_json_normalizer_reexports_all_required_symbols(self):
        # These exact names are imported by test_json_normalizer.py
        self.assertIs(jn_diff_paths, _diff_paths)
        self.assertIs(jn_classify_severity, classify_drift_severity)
        self.assertIs(jn_classify_dims, classify_security_dimensions)
        self.assertTrue(callable(normalize_terraform_plan))
        self.assertTrue(callable(drift_items_to_defectdojo_generic_findings))
        self.assertTrue(issubclass(DriftSummary, object))

    def test_app_config_exports(self):
        cfg = AppConfig()
        self.assertIsInstance(cfg.terraform, TerraformConfig)
        self.assertIsInstance(cfg.azure, AzureConfig)
        self.assertIsInstance(cfg.opa, OPASection)

    def test_report_builder_schema_version(self):
        self.assertIsInstance(SCHEMA_VERSION, str)
        self.assertRegex(SCHEMA_VERSION, r"^\d+\.\d+\.\d+$")


# ===========================================================================
# 2. plan_parser — contrats de données des helpers internes
# ===========================================================================


class TestPlanParserContracts(unittest.TestCase):

    def test_safe_dict_returns_dict_unchanged(self):
        d = {"a": 1}
        self.assertIs(_safe_dict(d), d)

    def test_safe_dict_returns_empty_for_none(self):
        self.assertEqual(_safe_dict(None), {})

    def test_safe_dict_returns_empty_for_string(self):
        self.assertEqual(_safe_dict("not a dict"), {})

    def test_safe_list_str_filters_non_strings(self):
        result = _safe_list_str(["a", 1, None, "b"])
        self.assertEqual(result, ["a", "b"])

    def test_safe_list_str_returns_empty_for_none(self):
        self.assertEqual(_safe_list_str(None), [])

    def test_actions_key_empty_returns_unknown(self):
        self.assertEqual(_actions_key([]), "unknown")

    def test_actions_key_joins_with_plus(self):
        self.assertEqual(_actions_key(["create", "delete"]), "create+delete")

    def test_iter_resource_changes_yields_resource_drift_first(self):
        plan = {
            "resource_drift": [{"address": "A"}],
            "resource_changes": [{"address": "B"}],
        }
        result = list(_iter_resource_changes(plan))
        self.assertEqual(result[0]["address"], "A")
        self.assertEqual(result[1]["address"], "B")

    def test_resource_type_from_managed_address(self):
        self.assertEqual(
            _resource_type_from_address("azurerm_storage_account.sa"),
            "azurerm_storage_account",
        )

    def test_resource_type_from_module_address(self):
        self.assertEqual(
            _resource_type_from_address("module.compute.azurerm_linux_virtual_machine.vm"),
            "azurerm_linux_virtual_machine",
        )

    def test_resource_type_from_data_address(self):
        self.assertEqual(
            _resource_type_from_address("data.azurerm_client_config.current"),
            "azurerm_client_config",
        )

    def test_resource_name_from_address(self):
        self.assertEqual(
            _resource_name_from_address("azurerm_storage_account.my_sa"),
            "my_sa",
        )

    def test_resource_name_strips_index(self):
        self.assertEqual(
            _resource_name_from_address("azurerm_storage_account.sa[0]"),
            "sa",
        )

    def test_guess_resource_address_returns_none_for_var(self):
        self.assertIsNone(_guess_resource_address_from_reference("var.name"))

    def test_guess_resource_address_returns_none_for_local(self):
        self.assertIsNone(_guess_resource_address_from_reference("local.rg_name"))

    def test_guess_resource_address_returns_none_for_short(self):
        self.assertIsNone(_guess_resource_address_from_reference("single"))


# ===========================================================================
# 3. diff_engine ↔ plan_parser — contrat de communication
# ===========================================================================


class TestDiffEngineContracts(unittest.TestCase):

    def test_extract_changed_paths_calls_safe_dict_on_change_field(self):
        """_extract_changed_paths relies on _safe_dict from plan_parser."""
        rc = {
            "change": {
                "before": {"min_tls_version": "TLS1_2"},
                "after": {"min_tls_version": "TLS1_0"},
            }
        }
        paths = _extract_changed_paths(rc)
        self.assertIn("min_tls_version", paths)

    def test_extract_changed_paths_with_missing_change_field(self):
        """When 'change' key is absent, _safe_dict returns {} and paths fallback."""
        rc = {}
        paths = _extract_changed_paths(rc)
        # No diff between {} and {} → fallback sentinel
        self.assertEqual(paths, ["change"])

    def test_extract_changed_paths_returns_sentinel_when_no_diff(self):
        rc = {"change": {"before": {"x": 1}, "after": {"x": 1}}}
        paths = _extract_changed_paths(rc)
        self.assertEqual(paths, ["change"])

    def test_extract_changed_paths_detects_nested_change(self):
        rc = {
            "change": {
                "before": {"network_acls": {"default_action": "Allow"}},
                "after": {"network_acls": {"default_action": "Deny"}},
            }
        }
        paths = _extract_changed_paths(rc)
        self.assertIn("network_acls.default_action", paths)

    def test_diff_paths_symmetric_with_security_taxonomy_keys(self):
        """Paths produced by _diff_paths match the first-segment keys in _SECURITY_DIMENSIONS."""
        before = {"security_rule": [], "tags": {}}
        after = {"security_rule": [{"access": "Allow"}], "tags": {}}
        paths = _diff_paths(before, after)
        # First segment of path "security_rule" must match taxonomy key
        segments = {p.split(".")[0] for p in paths}
        self.assertIn("security_rule", segments)


# ===========================================================================
# 4. security_taxonomy — contrats internes et cohérence des tables
# ===========================================================================


class TestSecurityTaxonomyContracts(unittest.TestCase):

    def test_all_dimension_values_are_known_strings(self):
        known = {
            "network_exposure",
            "credential",
            "access_control",
            "data_protection",
            "audit_logging",
            "backup_resilience",
        }
        for key, val in _SECURITY_DIMENSIONS.items():
            self.assertIn(val, known, f"Unknown dimension '{val}' for key {key}")

    def test_all_path_severity_values_are_valid(self):
        valid = set(_SEVERITY_ORDER)
        for key, val in _PATH_SEVERITY_MAP.items():
            self.assertIn(val, valid, f"Invalid severity '{val}' for key {key}")

    def test_all_type_fallback_values_are_valid(self):
        valid = set(_SEVERITY_ORDER)
        for rtype, sev in _RESOURCE_TYPE_FALLBACK_SEVERITY.items():
            self.assertIn(sev, valid, f"Invalid severity '{sev}' for type '{rtype}'")

    def test_default_fallback_exists(self):
        self.assertIn("_default", _RESOURCE_TYPE_FALLBACK_SEVERITY)

    def test_classify_security_dimensions_returns_sorted_list(self):
        dims = classify_security_dimensions(
            "azurerm_linux_virtual_machine",
            ["admin_password", "network_interface_ids"],
        )
        self.assertEqual(dims, sorted(dims))

    def test_classify_security_dimensions_unknown_resource_returns_empty(self):
        dims = classify_security_dimensions("azurerm_nonexistent", ["any_path"])
        self.assertEqual(dims, [])

    def test_classify_drift_severity_never_returns_below_floor(self):
        # azurerm_key_vault floor = High; any unknown path must still return >= High
        sev = classify_drift_severity("azurerm_key_vault", ["some_unknown_path"])
        idx = _SEVERITY_ORDER.index(sev)
        floor_idx = _SEVERITY_ORDER.index("High")
        self.assertGreaterEqual(idx, floor_idx)

    def test_classify_drift_severity_returns_max_across_paths(self):
        # security_rule → Critical, tags → no match (floor Medium for NSG)
        sev = classify_drift_severity(
            "azurerm_network_security_group", ["tags", "security_rule"]
        )
        self.assertEqual(sev, "Critical")


# ===========================================================================
# 5. json_normalizer — flux de données plan → items
# ===========================================================================


class TestJsonNormalizerDataFlow(unittest.TestCase):

    def _rc(self, address, rtype, before, after, actions=None):
        return {
            "address": address,
            "mode": "managed",
            "type": rtype,
            "name": address.split(".")[-1],
            "provider_name": "registry.terraform.io/hashicorp/azurerm",
            "change": {
                "actions": actions or ["update"],
                "before": before,
                "after": after,
            },
        }

    def test_items_carry_security_dimensions_from_taxonomy(self):
        plan = {"resource_drift": [
            self._rc("azurerm_network_security_group.web", "azurerm_network_security_group",
                     before={"security_rule": []},
                     after={"security_rule": [{"access": "Allow"}]})
        ]}
        _, items = normalize_terraform_plan(plan)
        self.assertIn("network_exposure", items[0]["security_dimensions"])

    def test_items_carry_no_severity_field(self):
        plan = {"resource_drift": [
            self._rc("azurerm_storage_account.sa", "azurerm_storage_account",
                     {"min_tls_version": "TLS1_2"}, {"min_tls_version": "TLS1_0"})
        ]}
        _, items = normalize_terraform_plan(plan)
        self.assertNotIn("severity", items[0])

    def test_drift_summary_counts_managed_vs_output(self):
        plan = {
            "resource_drift": [
                self._rc("azurerm_resource_group.rg", "azurerm_resource_group",
                         {"location": "westeurope"}, {"location": "eastus"})
            ],
            "output_changes": {
                "rg_name": {"actions": ["update"], "before": "old-rg", "after": "new-rg"}
            },
        }
        summary, items = normalize_terraform_plan(plan)
        self.assertEqual(summary.resources_changed, 1)
        self.assertEqual(summary.outputs_changed, 1)

    def test_data_source_is_filtered_not_in_items(self):
        plan = {"resource_drift": [{
            "address": "data.azurerm_client_config.current",
            "mode": "data",
            "type": "azurerm_client_config",
            "name": "current",
            "provider_name": "registry.terraform.io/hashicorp/azurerm",
            "change": {"actions": ["read"], "before": {}, "after": {}},
        }]}
        summary, items = normalize_terraform_plan(plan)
        self.assertEqual(items, [])
        self.assertEqual(len(summary.filtered_items), 1)
        self.assertEqual(summary.filtered_items[0]["filter_reason"], "data_source")

    def test_defectdojo_output_contains_findings_key(self):
        items = [{"address": "azurerm_storage_account.sa", "type": "azurerm_storage_account",
                  "actions": ["update"], "changed_paths": ["min_tls_version"],
                  "provider_name": "provider", "severity": "High"}]
        result = drift_items_to_defectdojo_generic_findings(items, "2026-05-08")
        self.assertIn("findings", result)
        self.assertEqual(len(result["findings"]), 1)

    def test_defectdojo_unique_id_format(self):
        items = [{"address": "azurerm_storage_account.sa", "type": "azurerm_storage_account",
                  "actions": ["update"], "changed_paths": ["min_tls_version"],
                  "provider_name": "provider", "severity": "High"}]
        result = drift_items_to_defectdojo_generic_findings(items, "2026-05-08")
        uid = result["findings"][0]["unique_id_from_tool"]
        self.assertTrue(uid.startswith("cloudsentinel-drift:"))
        self.assertIn("azurerm_storage_account.sa", uid)


# ===========================================================================
# 6. app_config — chargement et propagation des champs
# ===========================================================================


class TestAppConfigContracts(unittest.TestCase):

    def test_default_config_has_expected_defaults(self):
        cfg = AppConfig()
        self.assertEqual(cfg.terraform.workspace, "default")
        self.assertEqual(cfg.terraform.working_dir, ".")
        self.assertFalse(cfg.defectdojo.enabled)
        self.assertTrue(cfg.opa.enabled)
        self.assertTrue(cfg.opa.fallback_on_error)

    def test_load_config_from_yaml(self):
        yaml_content = """
terraform:
  working_dir: /tmp/iac
  workspace: staging
opa:
  enabled: false
"""
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write(yaml_content)
            tmp = Path(f.name)
        try:
            cfg = load_config(tmp)
            self.assertEqual(cfg.terraform.working_dir, "/tmp/iac")
            self.assertEqual(cfg.terraform.workspace, "staging")
            self.assertFalse(cfg.opa.enabled)
        finally:
            tmp.unlink()

    def test_expand_env_placeholders_with_default(self):
        os.environ.pop("NONEXISTENT_VAR_CS", None)
        result = _expand_env_placeholders("${NONEXISTENT_VAR_CS:-fallback_value}")
        self.assertEqual(result, "fallback_value")

    def test_expand_env_placeholders_uses_env(self):
        os.environ["CS_TEST_VAR"] = "actual_value"
        result = _expand_env_placeholders("${CS_TEST_VAR}")
        del os.environ["CS_TEST_VAR"]
        self.assertEqual(result, "actual_value")

    def test_bool_from_env_truthy_values(self):
        for val in ("1", "true", "yes", "y", "on", "TRUE", "YES"):
            self.assertTrue(_bool_from_env(val), f"Expected True for '{val}'")

    def test_bool_from_env_falsy_values(self):
        for val in ("0", "false", "no", "n", "off", "FALSE", ""):
            self.assertFalse(_bool_from_env(val), f"Expected False for '{val}'")


# ===========================================================================
# 7. redaction — contrat des utilitaires de masquage
# ===========================================================================


class TestRedactionContracts(unittest.TestCase):

    def test_redact_sensitive_empty_string_returns_empty(self):
        self.assertEqual(redact_sensitive(""), "")

    def test_redact_sensitive_replaces_env_secret_value(self):
        os.environ["ARM_CLIENT_SECRET"] = "super-secret-value-xyz"
        result = redact_sensitive("Error: super-secret-value-xyz leaked")
        del os.environ["ARM_CLIENT_SECRET"]
        self.assertNotIn("super-secret-value-xyz", result)
        self.assertIn("***REDACTED***", result)

    def test_redact_sensitive_masks_hcl_assignment(self):
        text = 'admin_password = "MyP@ssw0rd123"'
        result = redact_sensitive(text)
        self.assertNotIn("MyP@ssw0rd123", result)

    def test_redact_sensitive_masks_github_pat(self):
        text = "token = ghp_abcdefghijklmnopqrstu"
        result = redact_sensitive(text)
        self.assertNotIn("ghp_abcdefghijklmnopqrstu", result)

    def test_redact_sensitive_masks_gitlab_pat(self):
        text = "token = glpat-abcdefghijklmnopqrstu"
        result = redact_sensitive(text)
        self.assertNotIn("glpat-abcdefghijklmnopqrstu", result)

    def test_safe_env_snapshot_excludes_secrets(self):
        os.environ["ARM_CLIENT_SECRET"] = "should-not-appear"
        snapshot = safe_env_snapshot()
        del os.environ["ARM_CLIENT_SECRET"]
        self.assertNotIn("ARM_CLIENT_SECRET", snapshot)

    def test_safe_env_snapshot_includes_whitelisted_keys(self):
        os.environ["ARM_SUBSCRIPTION_ID"] = "sub-123"
        snapshot = safe_env_snapshot()
        del os.environ["ARM_SUBSCRIPTION_ID"]
        self.assertIn("ARM_SUBSCRIPTION_ID", snapshot)
        self.assertEqual(snapshot["ARM_SUBSCRIPTION_ID"], "sub-123")


# ===========================================================================
# 8. path_resolver — résolution de chemins
# ===========================================================================


class TestPathResolverContracts(unittest.TestCase):

    def test_resolve_engine_root_from_drift_config_yaml(self):
        # config/drift_config.yaml → engine root = parent of config/
        with tempfile.TemporaryDirectory() as tmp:
            config_dir = Path(tmp) / "config"
            config_dir.mkdir()
            config_file = config_dir / "drift_config.yaml"
            config_file.touch()
            root = resolve_engine_root(config_file)
            self.assertEqual(root, Path(tmp))

    def test_resolve_engine_root_fallback_non_drift_config(self):
        # Any other filename → fallback to utils/../ = drift-engine root
        root = resolve_engine_root(Path("/tmp/some_other_config.yaml"))
        self.assertEqual(root, _ENGINE_ROOT)

    def test_resolve_path_under_absolute_path_returned_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            abs_file = str(Path(tmp) / "file.json")
            root = Path(tmp) / "engine"
            p = resolve_path_under(root, abs_file)
            self.assertEqual(p, Path(abs_file))

    def test_resolve_path_under_relative_path_resolved_under_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "engine"
            p = resolve_path_under(root, "output/report.json")
            self.assertEqual(p, (root / "output" / "report.json").resolve())

    def test_choose_tf_binary_explicit_env_var(self):
        os.environ["TF_BINARY"] = "/usr/local/bin/tofu"
        result = choose_tf_binary(Path("/tmp"))
        del os.environ["TF_BINARY"]
        self.assertEqual(result, "/usr/local/bin/tofu")

    def test_choose_tf_binary_default_is_terraform(self):
        os.environ.pop("TF_BINARY", None)
        os.environ.pop("TF_BIN", None)
        result = choose_tf_binary(Path("/tmp"))
        self.assertEqual(result, "terraform")


# ===========================================================================
# 9. report_builder — structure du contexte et écriture fichier
# ===========================================================================


class TestReportBuilderContracts(unittest.TestCase):

    def _make_config(self) -> AppConfig:
        return AppConfig(
            engine=EngineConfig(name="test-engine", version="0.0.1", ocsf_version="1.3.0"),
            azure=AzureConfig(subscription_id="sub-123", tenant_id="tenant-456"),
            terraform=TerraformConfig(working_dir="/tmp", workspace="default"),
        )

    def test_build_report_context_top_level_keys(self):
        config = self._make_config()
        now = _utc_now()
        ctx = build_report_context(
            config=config, run_id="r1", correlation_id="c1",
            started_at=now, finished_at=now, exit_code=0,
            detected=False, tf_version="1.9.0",
            init_result={}, plan_result={},
            drift_summary={"resources_changed": 0}, drift_items=[],
            drift_filtered_items=[], errors=[],
        )
        for key in ("schema_version", "ocsf", "cloudsentinel", "drift", "terraform", "errors"):
            self.assertIn(key, ctx)

    def test_build_report_context_severity_info_when_clean(self):
        config = self._make_config()
        now = _utc_now()
        ctx = build_report_context(
            config=config, run_id="r1", correlation_id="c1",
            started_at=now, finished_at=now, exit_code=0,
            detected=False, tf_version=None,
            init_result={}, plan_result={},
            drift_summary={}, drift_items=[],
            drift_filtered_items=[], errors=[],
        )
        self.assertEqual(ctx["ocsf"]["severity"], "Info")
        self.assertEqual(ctx["ocsf"]["severity_id"], 1)

    def test_build_report_context_severity_max_from_drift_items(self):
        config = self._make_config()
        now = _utc_now()
        ctx = build_report_context(
            config=config, run_id="r1", correlation_id="c1",
            started_at=now, finished_at=now, exit_code=2,
            detected=True, tf_version=None,
            init_result={}, plan_result={},
            drift_summary={},
            drift_items=[
                {"severity": "High"},
                {"severity": "Critical"},
                {"severity": "Medium"},
            ],
            drift_filtered_items=[], errors=[],
        )
        self.assertEqual(ctx["ocsf"]["severity"], "Critical")
        self.assertEqual(ctx["ocsf"]["severity_id"], 5)

    def test_build_report_context_run_status_error_when_errors(self):
        config = self._make_config()
        now = _utc_now()
        ctx = build_report_context(
            config=config, run_id="r1", correlation_id="c1",
            started_at=now, finished_at=now, exit_code=1,
            detected=False, tf_version=None,
            init_result={}, plan_result={},
            drift_summary={}, drift_items=[],
            drift_filtered_items=[],
            errors=[{"type": "SomeError", "message": "boom"}],
        )
        self.assertEqual(ctx["cloudsentinel"]["run_status"], "error")

    def test_build_report_context_pipeline_correlation_id_propagated(self):
        config = self._make_config()
        config.pipeline_correlation_id = "pipe-abc-123"
        now = _utc_now()
        ctx = build_report_context(
            config=config, run_id="r1", correlation_id="c1",
            started_at=now, finished_at=now, exit_code=0,
            detected=False, tf_version=None,
            init_result={}, plan_result={},
            drift_summary={}, drift_items=[],
            drift_filtered_items=[], errors=[],
        )
        self.assertEqual(ctx["cloudsentinel"]["pipeline_correlation_id"], "pipe-abc-123")

    def test_write_json_creates_file_with_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "subdir" / "report.json"
            payload = {"key": "value", "number": 42}
            write_json(out, payload)
            self.assertTrue(out.exists())
            data = json.loads(out.read_text())
            self.assertEqual(data["key"], "value")
            self.assertEqual(data["number"], 42)

    def test_write_json_creates_parent_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "a" / "b" / "c" / "report.json"
            write_json(out, {"ok": True})
            self.assertTrue(out.exists())


# ===========================================================================
# 10. DriftEngine — isolation des phases (chaque _run_* indépendamment)
# ===========================================================================

def _make_engine(tmp_path: Path, *, opa_enabled: bool = False) -> DriftEngine:
    """Create a DriftEngine with minimal config, mocked TerraformRunner."""
    config = AppConfig(
        terraform=TerraformConfig(working_dir=str(tmp_path)),
        report=ReportConfig(
            output_path=str(tmp_path / "drift-report.json"),
            template_path=str(_TEMPLATE_PATH),
            include_plan_json=True,
        ),
        opa=OPASection(enabled=opa_enabled),
        defectdojo=DefectDojoSection(enabled=False),
    )
    engine = DriftEngine(
        config=config,
        run_id="test-run",
        correlation_id="test-corr",
        started_at=_utc_now(),
        engine_root=_ENGINE_ROOT,
    )
    engine._tf_runner = MagicMock(spec=TerraformRunner)
    engine._out_path = tmp_path / "drift-report.json"
    engine._template_path = _TEMPLATE_PATH
    return engine


class TestDriftEnginePhaseValidateWorkingDir(unittest.TestCase):

    def test_returns_none_when_dir_exists_with_tf_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "main.tf").touch()
            engine = _make_engine(p)
            engine._emit_report = MagicMock()
            result = engine._validate_working_dir()
            self.assertIsNone(result)

    def test_returns_1_when_dir_does_not_exist(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            engine = _make_engine(p)
            engine._emit_report = MagicMock()
            engine._tf_working_dir = Path("/nonexistent/path/xyz")
            result = engine._validate_working_dir()
            self.assertEqual(result, 1)
            self.assertEqual(len(engine._errors), 1)
            self.assertEqual(engine._errors[0]["type"], "TerraformWorkingDirNotFound")

    def test_returns_1_when_no_tf_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            engine = _make_engine(p)
            engine._emit_report = MagicMock()
            result = engine._validate_working_dir()
            self.assertEqual(result, 1)
            self.assertEqual(engine._errors[0]["type"], "TerraformNoConfigFiles")

    def test_appends_error_with_remediation(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            engine = _make_engine(p)
            engine._emit_report = MagicMock()
            engine._validate_working_dir()
            self.assertIn("remediation", engine._errors[0])


class TestDriftEnginePhaseRunInit(unittest.TestCase):

    def _ok_result(self) -> TerraformCommandResult:
        return TerraformCommandResult(
            cmd=["tofu", "init"], return_code=0,
            stdout="Terraform initialized.", stderr="", duration_ms=100,
        )

    def _fail_result(self) -> TerraformCommandResult:
        return TerraformCommandResult(
            cmd=["tofu", "init"], return_code=1,
            stdout="", stderr="Error: backend unreachable", duration_ms=50,
        )

    def test_returns_none_on_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = _make_engine(Path(tmp))
            engine._tf_runner.init.return_value = self._ok_result()
            engine._emit_report = MagicMock()
            result = engine._run_init()
            self.assertIsNone(result)
            self.assertEqual(engine._errors, [])

    def test_returns_1_on_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = _make_engine(Path(tmp))
            engine._tf_runner.init.return_value = self._fail_result()
            engine._emit_report = MagicMock()
            result = engine._run_init()
            self.assertEqual(result, 1)

    def test_appends_init_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = _make_engine(Path(tmp))
            engine._tf_runner.init.return_value = self._fail_result()
            engine._emit_report = MagicMock()
            engine._run_init()
            self.assertEqual(engine._errors[0]["type"], "TerraformInitError")

    def test_stores_init_result_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = _make_engine(Path(tmp))
            engine._tf_runner.init.return_value = self._ok_result()
            engine._emit_report = MagicMock()
            engine._run_init()
            self.assertEqual(engine._init_result["return_code"], 0)
            self.assertIn("duration_ms", engine._init_result)


class TestDriftEnginePhaseRunWorkspace(unittest.TestCase):

    def _ok(self) -> TerraformCommandResult:
        return TerraformCommandResult(
            cmd=["tofu", "workspace", "select", "default"], return_code=0,
            stdout="", stderr="", duration_ms=10,
        )

    def _fail(self) -> TerraformCommandResult:
        return TerraformCommandResult(
            cmd=["tofu", "workspace", "select", "default"], return_code=1,
            stdout="", stderr="Workspace not found", duration_ms=10,
        )

    def test_returns_none_on_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = _make_engine(Path(tmp))
            engine._tf_runner.workspace_select_or_create.return_value = self._ok()
            engine._emit_report = MagicMock()
            self.assertIsNone(engine._run_workspace())
            self.assertEqual(engine._errors, [])

    def test_returns_1_on_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = _make_engine(Path(tmp))
            engine._tf_runner.workspace_select_or_create.return_value = self._fail()
            engine._emit_report = MagicMock()
            self.assertEqual(engine._run_workspace(), 1)
            self.assertEqual(engine._errors[0]["type"], "TerraformWorkspaceError")


class TestDriftEnginePhaseRunPlan(unittest.TestCase):

    def _plan_result(self, rc: int) -> TerraformCommandResult:
        return TerraformCommandResult(
            cmd=["tofu", "plan"], return_code=rc,
            stdout="", stderr="", duration_ms=200,
        )

    def test_exit_code_0_detected_false(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = _make_engine(Path(tmp))
            engine._tf_runner.plan_refresh_only.return_value = self._plan_result(0)
            engine._emit_report = MagicMock()
            exit_code, detected = engine._run_plan()
            self.assertEqual(exit_code, 0)
            self.assertFalse(detected)

    def test_exit_code_2_detected_true(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = _make_engine(Path(tmp))
            engine._tf_runner.plan_refresh_only.return_value = self._plan_result(2)
            engine._emit_report = MagicMock()
            exit_code, detected = engine._run_plan()
            self.assertEqual(exit_code, 2)
            self.assertTrue(detected)

    def test_exit_code_1_returns_none_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = _make_engine(Path(tmp))
            engine._tf_runner.plan_refresh_only.return_value = self._plan_result(1)
            engine._emit_report = MagicMock()
            exit_code, detected = engine._run_plan()
            self.assertIsNone(exit_code)
            self.assertIsNone(detected)
            self.assertEqual(engine._errors[0]["type"], "TerraformPlanError")

    def test_plan_result_stores_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = _make_engine(Path(tmp))
            engine._tf_runner.plan_refresh_only.return_value = self._plan_result(0)
            engine._emit_report = MagicMock()
            engine._run_plan()
            self.assertEqual(engine._plan_result["return_code"], 0)
            self.assertIn("duration_ms", engine._plan_result)


class TestDriftEnginePhaseNormalizeAndEvaluate(unittest.TestCase):

    def _storage_plan_json(self) -> dict:
        return {
            "resource_drift": [{
                "address": "azurerm_storage_account.sa",
                "mode": "managed",
                "type": "azurerm_storage_account",
                "name": "sa",
                "provider_name": "registry.terraform.io/hashicorp/azurerm",
                "change": {
                    "actions": ["update"],
                    "before": {"min_tls_version": "TLS1_2"},
                    "after": {"min_tls_version": "TLS1_0"},
                },
            }]
        }

    def test_no_plan_json_appends_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = _make_engine(Path(tmp))
            engine._tf_runner.show_plan_json.return_value = None
            engine._emit_report = MagicMock()
            rc, detected = engine._normalize_and_evaluate(detected=False)
            self.assertEqual(engine._errors[0]["type"], "TerraformShowJsonSkipped")

    def test_no_plan_json_with_detected_returns_exit_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = _make_engine(Path(tmp))
            engine._tf_runner.show_plan_json.return_value = None
            engine._emit_report = MagicMock()
            rc, detected = engine._normalize_and_evaluate(detected=True)
            self.assertEqual(rc, 1)
            self.assertFalse(detected)

    def test_valid_plan_json_populates_drift_items(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = _make_engine(Path(tmp))
            engine._tf_runner.show_plan_json.return_value = self._storage_plan_json()
            engine._emit_report = MagicMock()
            rc, detected = engine._normalize_and_evaluate(detected=True)
            self.assertIsNone(rc)
            self.assertTrue(detected)
            self.assertEqual(len(engine._drift_items), 1)
            self.assertEqual(engine._drift_items[0]["address"], "azurerm_storage_account.sa")

    def test_all_items_filtered_sets_detected_false(self):
        # Plan with only data sources → all filtered → detected downgraded
        plan = {"resource_drift": [{
            "address": "data.azurerm_client_config.current",
            "mode": "data",
            "type": "azurerm_client_config",
            "name": "current",
            "provider_name": "provider",
            "change": {"actions": ["read"], "before": {}, "after": {}},
        }]}
        with tempfile.TemporaryDirectory() as tmp:
            engine = _make_engine(Path(tmp))
            engine._tf_runner.show_plan_json.return_value = plan
            engine._emit_report = MagicMock()
            rc, detected = engine._normalize_and_evaluate(detected=True)
            self.assertIsNone(rc)
            self.assertFalse(detected)

    def test_fallback_severity_applied_when_opa_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = _make_engine(Path(tmp), opa_enabled=False)
            engine._tf_runner.show_plan_json.return_value = self._storage_plan_json()
            engine._emit_report = MagicMock()
            engine._normalize_and_evaluate(detected=True)
            self.assertIn("severity", engine._drift_items[0])
            self.assertEqual(engine._drift_items[0]["severity"], "High")

    def test_drift_summary_populated(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = _make_engine(Path(tmp))
            engine._tf_runner.show_plan_json.return_value = self._storage_plan_json()
            engine._emit_report = MagicMock()
            engine._normalize_and_evaluate(detected=True)
            self.assertIn("resources_changed", engine._drift_summary)
            self.assertEqual(engine._drift_summary["resources_changed"], 1)


# ===========================================================================
# 11. DriftEngine — machine d'état run() bout-en-bout (sans I/O externe)
# ===========================================================================


class TestDriftEngineStateMachine(unittest.TestCase):

    def _ok_cmd(self, rc: int = 0) -> TerraformCommandResult:
        return TerraformCommandResult(
            cmd=["tofu"], return_code=rc,
            stdout="", stderr="", duration_ms=10,
        )

    def _wire_happy_path(self, engine: DriftEngine, plan_json: dict | None = None) -> None:
        engine._tf_runner.version.return_value = "1.9.0"
        engine._tf_runner.init.return_value = self._ok_cmd(0)
        engine._tf_runner.workspace_select_or_create.return_value = self._ok_cmd(0)
        engine._tf_runner.plan_refresh_only.return_value = self._ok_cmd(0)
        engine._tf_runner.show_plan_json.return_value = plan_json or {}
        TerraformRunner.redact_cmd = staticmethod(lambda cmd: cmd)

    def test_clean_run_returns_0(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "main.tf").touch()
            engine = _make_engine(p)
            self._wire_happy_path(engine)
            result = engine.run()
            self.assertEqual(result, 0)

    def test_drift_detected_returns_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "main.tf").touch()
            engine = _make_engine(p)
            self._wire_happy_path(engine, plan_json={
                "resource_drift": [{
                    "address": "azurerm_resource_group.rg",
                    "mode": "managed",
                    "type": "azurerm_resource_group",
                    "name": "rg",
                    "provider_name": "provider",
                    "change": {
                        "actions": ["update"],
                        "before": {"location": "westeurope"},
                        "after": {"location": "eastus"},
                    },
                }]
            })
            engine._tf_runner.plan_refresh_only.return_value = self._ok_cmd(2)
            result = engine.run()
            self.assertEqual(result, 2)

    def test_plan_exit_2_but_all_items_filtered_returns_0_and_report_exit_0(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "main.tf").touch()
            engine = _make_engine(p)
            # Terraform signals drift (detailed-exitcode=2), but normalizer filters
            # all items as non-actionable (data source read), so effective status is clean.
            self._wire_happy_path(engine, plan_json={
                "resource_drift": [{
                    "address": "data.azurerm_client_config.current",
                    "mode": "data",
                    "type": "azurerm_client_config",
                    "name": "current",
                    "provider_name": "registry.terraform.io/hashicorp/azurerm",
                    "change": {
                        "actions": ["read"],
                        "before": {},
                        "after": {},
                    },
                }]
            })
            engine._tf_runner.plan_refresh_only.return_value = self._ok_cmd(2)

            result = engine.run()
            self.assertEqual(result, 0)

            report = json.loads(engine._out_path.read_text(encoding="utf-8"))
            self.assertFalse(report["drift"]["detected"])
            self.assertEqual(report["drift"]["exit_code"], 0)
            self.assertEqual(report["terraform"]["plan"]["return_code"], 2)

    def test_init_failure_returns_1_and_stops(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "main.tf").touch()
            engine = _make_engine(p)
            engine._tf_runner.version.return_value = "1.9.0"
            engine._tf_runner.init.return_value = self._ok_cmd(1)
            TerraformRunner.redact_cmd = staticmethod(lambda cmd: cmd)
            result = engine.run()
            self.assertEqual(result, 1)
            # workspace and plan must never have been called
            engine._tf_runner.workspace_select_or_create.assert_not_called()
            engine._tf_runner.plan_refresh_only.assert_not_called()

    def test_workspace_failure_returns_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "main.tf").touch()
            engine = _make_engine(p)
            engine._tf_runner.version.return_value = "1.9.0"
            engine._tf_runner.init.return_value = self._ok_cmd(0)
            engine._tf_runner.workspace_select_or_create.return_value = self._ok_cmd(1)
            TerraformRunner.redact_cmd = staticmethod(lambda cmd: cmd)
            result = engine.run()
            self.assertEqual(result, 1)
            engine._tf_runner.plan_refresh_only.assert_not_called()

    def test_plan_error_returns_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "main.tf").touch()
            engine = _make_engine(p)
            engine._tf_runner.version.return_value = "1.9.0"
            engine._tf_runner.init.return_value = self._ok_cmd(0)
            engine._tf_runner.workspace_select_or_create.return_value = self._ok_cmd(0)
            engine._tf_runner.plan_refresh_only.return_value = self._ok_cmd(1)
            TerraformRunner.redact_cmd = staticmethod(lambda cmd: cmd)
            result = engine.run()
            self.assertEqual(result, 1)

    def test_missing_working_dir_returns_1_immediately(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            engine = _make_engine(p)
            engine._tf_working_dir = Path("/nonexistent/iac-path")
            engine._tf_runner.version.return_value = "1.9.0"
            result = engine.run()
            self.assertEqual(result, 1)
            engine._tf_runner.init.assert_not_called()

    def test_errors_list_accumulates_across_phases(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "main.tf").touch()
            engine = _make_engine(p)
            self._wire_happy_path(engine)
            engine._tf_runner.show_plan_json.return_value = None  # triggers ShowJsonSkipped
            engine.run()
            error_types = [e["type"] for e in engine._errors]
            self.assertIn("TerraformShowJsonSkipped", error_types)

    def test_report_is_written_on_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "main.tf").touch()
            engine = _make_engine(p)
            self._wire_happy_path(engine)
            engine.run()
            report_path = p / "drift-report.json"
            self.assertTrue(report_path.exists())
            report = json.loads(report_path.read_text())
            self.assertIn("cloudsentinel", report)
            self.assertEqual(report["cloudsentinel"]["run_id"], "test-run")


if __name__ == "__main__":
    unittest.main()
