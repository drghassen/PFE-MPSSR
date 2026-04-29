"""
CloudSentinel Drift Engine (Shift-Right).

Scheduled batch job that detects configuration drift between Terraform IaC and live Azure resources
using `terraform plan -refresh-only -detailed-exitcode`, then emits a standardized drift report and
optionally pushes findings to DefectDojo (v2 API).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog
import yaml
from jinja2 import Environment, FileSystemLoader
from pydantic import BaseModel, Field

from utils.azure_client import AzureResourceClient, load_azure_env
from utils.defectdojo_client import DefectDojoClient, DefectDojoConfig
from utils.json_normalizer import (
    classify_drift_severity,
    drift_items_to_defectdojo_generic_findings,
    normalize_terraform_plan,
)
from utils.opa_client import OPAClient, OPAConfig
from utils.opa_normalizer import normalize_drift_for_opa
from utils.enrichment import enrich_drift_items_with_opa
from utils.terraform_runner import TerraformRunner


SCHEMA_VERSION = "1.0.0"


class TerraformInitConfig(BaseModel):
    upgrade: bool = False
    reconfigure: bool = False
    backend: bool = True


class TerraformPlanConfig(BaseModel):
    lock_timeout: str = "60s"
    parallelism: int = 10
    refresh_only: bool = True


class TerraformConfig(BaseModel):
    working_dir: str = "."
    workspace: str = "default"
    init: TerraformInitConfig = Field(default_factory=TerraformInitConfig)
    plan: TerraformPlanConfig = Field(default_factory=TerraformPlanConfig)


class AzureConfig(BaseModel):
    subscription_id: str | None = None
    tenant_id: str | None = None
    validate_access: bool = False
    list_resource_groups: bool = False


class ReportConfig(BaseModel):
    output_path: str = "output/drift-report.json"
    include_plan_json: bool = True
    include_raw_terraform_stdout: bool = False
    template_path: str = "templates/drift-report-template.j2"


class EngineConfig(BaseModel):
    name: str = "cloudsentinel-drift-engine"
    version: str = "0.1.0"
    ocsf_version: str = "1.3.0"


class DefectDojoSection(BaseModel):
    enabled: bool = False
    base_url: str = ""
    api_key: str = ""
    engagement_id: str = ""
    test_title: str = "CloudSentinel Drift Engine"
    close_old_findings: bool = True
    deduplication_on_engagement: bool = True
    minimum_severity: str = "Info"


class OPASection(BaseModel):
    """OPA Policy Decision Point configuration for Shift-Right drift evaluation."""

    enabled: bool = Field(default=True, description="Enable OPA evaluation")
    server_url: str = Field(
        default="http://localhost:8182", description="OPA server URL"
    )
    policy_path: str = Field(
        default="cloudsentinel.shiftright.drift", description="OPA policy path"
    )
    timeout: int = Field(default=30, description="HTTP timeout in seconds")
    fallback_on_error: bool = Field(
        default=True, description="Allow fallback to conservative decisions if OPA fails"
    )
    auth_token: str = Field(
        default="", description="Bearer token for OPA Zero Trust auth"
    )


class AppConfig(BaseModel):
    engine: EngineConfig = Field(default_factory=EngineConfig)
    azure: AzureConfig = Field(default_factory=AzureConfig)
    terraform: TerraformConfig = Field(default_factory=TerraformConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    defectdojo: DefectDojoSection = Field(default_factory=DefectDojoSection)
    opa: OPASection = Field(default_factory=OPASection)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _bool_from_env(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _expand_env_placeholders(value: Any) -> Any:
    """
    Expands ${VAR} and ${VAR:-default} in YAML-loaded objects.

    Notes:
    - Only expands when the entire string is a single placeholder.
    - Avoids bringing extra dependencies for templating config files.
    """

    if isinstance(value, str):
        pattern = re.compile(r"\$\{([^}]+)\}")

        def repl(match: re.Match[str]) -> str:
            expr = match.group(1)
            if ":-" in expr:
                var, default = expr.split(":-", 1)
                return os.getenv(var, default)
            return os.getenv(expr, "")

        return pattern.sub(repl, value)
    if isinstance(value, list):
        return [_expand_env_placeholders(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand_env_placeholders(v) for k, v in value.items()}
    return value


def load_config(path: Path) -> AppConfig:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    expanded = _expand_env_placeholders(raw)

    azure = expanded.get("azure") or {}
    if isinstance(azure, dict):
        for k in ("subscription_id", "tenant_id"):
            if azure.get(k) == "":
                logger.warning(
                    "config_empty_value_converted_to_none",
                    field=f"azure.{k}",
                    suggestion=f"Set {k} explicitly or use environment variable",
                )
                azure[k] = None
        expanded["azure"] = azure

    tf = expanded.get("terraform") or {}
    if isinstance(tf, dict) and tf.get("working_dir") == "":
        tf["working_dir"] = "."
        expanded["terraform"] = tf

    defect = expanded.get("defectdojo") or {}
    if isinstance(defect, dict) and isinstance(defect.get("enabled"), str):
        defect["enabled"] = _bool_from_env(defect["enabled"])
        expanded["defectdojo"] = defect

    return AppConfig.model_validate(expanded)


def configure_logging() -> structlog.stdlib.BoundLogger:
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ]
    )
    return structlog.get_logger()


def _safe_env_snapshot() -> dict[str, str]:
    """
    Never log secrets. Only include whitelisted, non-secret env keys.
    """

    allow = {
        "ARM_SUBSCRIPTION_ID",
        "ARM_TENANT_ID",
        "ARM_CLIENT_ID",
        "ARM_USE_MSI",
        "TF_WORKING_DIR",
        "TF_WORKSPACE",
        "DRIFT_OUTPUT_PATH",
        "DRIFT_PUSH_TO_DEFECTDOJO",
    }
    out: dict[str, str] = {}
    for key in sorted(allow):
        value = os.getenv(key)
        if value:
            out[key] = value
    return out


def _resolve_engine_root(config_path: Path) -> Path:
    """
    Derive the drift-engine root folder from `config/drift_config.yaml`.
    """

    resolved = config_path.resolve()
    if resolved.name != "drift_config.yaml":
        return Path(__file__).resolve().parent
    # .../drift-engine/config/drift_config.yaml -> .../drift-engine
    return resolved.parent.parent


def _resolve_path_under(root: Path, value: str) -> Path:
    """
    Resolve config paths (template/output) deterministically, regardless of the current working directory.
    """

    p = Path(value).expanduser()
    if p.is_absolute():
        return p
    return (root / p).resolve()


def _choose_tf_binary(tf_working_dir: Path) -> str:
    """
    Choose which IaC CLI to run:
    - If TF_BINARY/TF_BIN is set, use it.
    - If OpenTofu lockfile markers are present and `tofu` exists, prefer `tofu`.
    - Otherwise fall back to `terraform`.
    """

    explicit = (os.getenv("TF_BINARY") or os.getenv("TF_BIN") or "").strip()
    if explicit:
        return explicit

    lockfile_path = tf_working_dir / ".terraform.lock.hcl"
    if lockfile_path.exists():
        try:
            content = lockfile_path.read_text(encoding="utf-8", errors="ignore")
            if (
                "registry.opentofu.org" in content or "opentofu" in content
            ) and shutil.which("tofu"):
                return "tofu"
        except Exception:
            pass

    return "terraform"


def _redact_sensitive(text: str) -> str:
    """
    Best-effort redaction for Terraform/OpenTofu stdout/stderr.

    Terraform errors can sometimes echo literal values (e.g. `admin_password = "..."`).
    This function aims to remove common secret patterns without breaking debuggability.
    """

    if not text:
        return ""

    redacted = text

    # 1) Replace exact secret env values if they appear in output (strongest signal).
    for key in (
        "ARM_CLIENT_SECRET",
        "DEFECTDOJO_API_KEY",
        "AZURE_CLIENT_SECRET",
        "ARM_ACCESS_KEY",
        "OPA_AUTH_TOKEN",
    ):
        value = os.getenv(key)
        if value:
            redacted = redacted.replace(value, "***REDACTED***")

    # 2) Redact common assignment patterns (HCL-like).
    redacted = re.sub(
        r'(?im)^(\s*[\w\-.]*?(?:password|secret|token|api[_-]?key|access[_-]?key)[\w\-.]*\s*=\s*)"[^"]*"',
        r'\1"***REDACTED***"',
        redacted,
    )

    # 3) Redact some well-known token formats.
    redacted = re.sub(r"\bghp_[A-Za-z0-9_]{20,}\b", "***REDACTED***", redacted)
    redacted = re.sub(r"\bglpat-[A-Za-z0-9\-_]{20,}\b", "***REDACTED***", redacted)

    return redacted


def build_report_context(
    config: AppConfig,
    run_id: str,
    started_at: datetime,
    finished_at: datetime,
    exit_code: int,
    detected: bool,
    tf_version: str | None,
    init_result: dict[str, Any],
    plan_result: dict[str, Any],
    drift_summary: dict[str, Any],
    drift_items: list[dict[str, Any]],
    errors: list[dict[str, Any]],
) -> dict[str, Any]:
    """Builds the Jinja2 context used to render `drift-report.json`."""
    # OCSF severity order aligned with DefectDojo Title-case values.
    # "Info" matches the severity value used throughout the drift engine
    # (OPA normalizer, enrichment, DefectDojo minimum_severity).
    _OCSF_ORDER = ["Info", "Low", "Medium", "High", "Critical"]
    _OCSF_ID = {"Info": 1, "Low": 2, "Medium": 3, "High": 4, "Critical": 5}

    if not detected:
        severity = "Info"
    else:
        _item_severities = [
            # Use OPA-enriched severity if available, else classify statically
            item.get("severity")
            if item.get("opa_evaluated")
            else classify_drift_severity(
                str(item.get("type") or ""),
                item.get("changed_paths") or [],
            )
            for item in drift_items
        ]
        # Filter out None values before max()
        _item_severities = [s for s in _item_severities if s in _OCSF_ORDER]
        severity = (
            max(_item_severities, key=lambda s: _OCSF_ORDER.index(s))
            if _item_severities
            else "Medium"
        )

    severity_id = _OCSF_ID.get(severity, 3)

    ocsf = {
        "version": config.engine.ocsf_version,
        "class_uid": 2001,
        "category_uid": 2,
        "type_uid": 200100,
        "time": finished_at.isoformat(),
        "severity_id": severity_id,
        "severity": severity,
        "activity_name": "Detect",
        "activity_id": 1,
        "metadata": {
            "product": {
                "name": "CloudSentinel Drift Engine",
                "vendor_name": "CloudSentinel",
                "version": config.engine.version,
            }
        },
    }

    cloudsentinel = {
        "run_id": run_id,
        "correlation_id": run_id,
        "engine": config.engine.name,
        "engine_version": config.engine.version,
        "tenant_id": config.azure.tenant_id,
        "subscription_id": config.azure.subscription_id,
        "terraform_workspace": config.terraform.workspace,
        "terraform_working_dir": str(Path(config.terraform.working_dir).resolve()),
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_ms": int((finished_at - started_at).total_seconds() * 1000),
        "run_status": "error" if errors else ("drifted" if detected else "clean"),
    }

    terraform = {
        "version": tf_version,
        "init": init_result,
        "plan": plan_result,
    }

    drift = {
        "detected": detected,
        "exit_code": exit_code,
        "summary": drift_summary,
        "items": drift_items,
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "ocsf": ocsf,
        "cloudsentinel": cloudsentinel,
        "drift": drift,
        "terraform": terraform,
        "errors": errors,
    }


def render_report(template_path: Path, context: dict[str, Any]) -> dict[str, Any]:
    """Renders the report Jinja2 template and returns a JSON dict."""
    env = Environment(
        loader=FileSystemLoader(str(template_path.parent)), autoescape=False
    )
    template = env.get_template(template_path.name)
    rendered = template.render(**context)
    return json.loads(rendered)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    """Writes JSON output to disk (creates parent directories if needed)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def main(argv: list[str]) -> int:
    """Entrypoint. Returns process exit code (0 or 1)."""
    parser = argparse.ArgumentParser(
        description="CloudSentinel Drift Engine (scheduled batch job)"
    )
    parser.add_argument(
        "--config", default=os.getenv("DRIFT_CONFIG_PATH", "config/drift_config.yaml")
    )
    parser.add_argument(
        "--tf-dir", default=None, help="Override Terraform working directory"
    )
    parser.add_argument(
        "--output", default=None, help="Override drift report output path"
    )
    parser.add_argument(
        "--push-dojo", action="store_true", help="Force push findings to DefectDojo"
    )
    args = parser.parse_args(argv)

    logger = configure_logging()
    run_id = str(uuid.uuid4())
    os.environ["CLOUDSENTINEL_CORRELATION_ID"] = run_id
    started_at = _utc_now()
    errors: list[dict[str, Any]] = []

    config_path = Path(args.config).expanduser()
    engine_root = _resolve_engine_root(config_path)

    def write_minimal_error_report(message: str, remediation: str) -> None:
        finished_at = _utc_now()
        out_path = Path(
            args.output or os.getenv("DRIFT_OUTPUT_PATH") or "output/drift-report.json"
        ).expanduser()
        if not out_path.is_absolute():
            out_path = (engine_root / out_path).resolve()

        payload = {
            "schema_version": SCHEMA_VERSION,
            "ocsf": {
                "version": "1.3.0",
                "class_uid": 2001,
                "category_uid": 2,
                "type_uid": 200100,
                "time": finished_at.isoformat(),
                "severity_id": 4,
                "severity": "High",
            },
            "cloudsentinel": {
                "run_id": run_id,
                "correlation_id": run_id,
                "engine": "cloudsentinel-drift-engine",
                "engine_version": "unknown",
                "tenant_id": None,
                "subscription_id": None,
                "terraform_workspace": "unknown",
                "terraform_working_dir": args.tf_dir or ".",
                "started_at": started_at.isoformat(),
                "finished_at": finished_at.isoformat(),
                "duration_ms": int((finished_at - started_at).total_seconds() * 1000),
            },
            "drift": {
                "detected": False,
                "exit_code": 1,
                "summary": {
                    "resources_changed": 0,
                    "resources_by_action": {},
                    "provider_names": [],
                },
                "items": [],
            },
            "terraform": {"version": None, "init": {}, "plan": {}},
            "errors": [
                {
                    "type": "ConfigLoadError",
                    "message": message,
                    "remediation": remediation,
                }
            ],
        }
        write_json(out_path, payload)

    try:
        config = load_config(config_path)
        if args.tf_dir:
            config.terraform.working_dir = args.tf_dir
        if args.output:
            config.report.output_path = args.output
        if args.push_dojo:
            config.defectdojo.enabled = True
    except Exception as exc:
        logger.error("config_load_failed", error=str(exc))
        write_minimal_error_report(
            message=str(exc),
            remediation="Validate drift_config.yaml and required environment variables.",
        )
        return 1

    if config.defectdojo.enabled:
        if not (
            config.defectdojo.base_url
            and config.defectdojo.api_key
            and config.defectdojo.engagement_id
        ):
            logger.error("defectdojo_config_missing")
            write_minimal_error_report(
                message="DefectDojo config incomplete (base_url/api_key/engagement_id).",
                remediation="Set DEFECTDOJO_URL, DEFECTDOJO_API_KEY, and DOJO_ENGAGEMENT_ID_RIGHT (or DEFECTDOJO_ENGAGEMENT_ID_RIGHT) in the environment (.env or CI secrets).",
            )
            return 1

    logger.info(
        "run_started",
        run_id=run_id,
        engine=config.engine.name,
        version=config.engine.version,
        env=_safe_env_snapshot(),
    )

    template_path = _resolve_path_under(engine_root, config.report.template_path)
    out_path = _resolve_path_under(engine_root, config.report.output_path)

    tf_working_dir = Path(config.terraform.working_dir).expanduser().resolve()
    drift_work_dir = (
        Path(os.getenv("DRIFT_WORK_DIR", "/tmp/cloudsentinel-drift"))
        .expanduser()
        .resolve()
    )
    tf_plan_path = drift_work_dir / run_id / "tfplan"
    tf_bin = _choose_tf_binary(tf_working_dir)
    tf_runner = TerraformRunner(
        working_dir=tf_working_dir,
        terraform_bin=tf_bin,
        timeout_s=int(os.getenv("TF_PLAN_TIMEOUT_S", "600"))
    )
    logger.info(
        "iac_cli_selected",
        run_id=run_id,
        binary=tf_bin,
        working_dir=str(tf_working_dir),
    )

    tf_version: str | None = None
    init_result: dict[str, Any] = {}
    plan_result: dict[str, Any] = {}
    drift_items: list[dict[str, Any]] = []
    drift_summary_obj: dict[str, Any] = {
        "resources_changed": 0,
        "resources_by_action": {},
        "provider_names": [],
    }

    def emit_report(*, finished_at: datetime, exit_code: int, detected: bool) -> None:
        context = build_report_context(
            config=config,
            run_id=run_id,
            started_at=started_at,
            finished_at=finished_at,
            exit_code=exit_code,
            detected=detected,
            tf_version=tf_version,
            init_result=init_result,
            plan_result=plan_result,
            drift_summary=drift_summary_obj,
            drift_items=drift_items,
            errors=errors,
        )
        report_payload = render_report(template_path, context)
        write_json(out_path, report_payload)

    # Fail-fast: Terraform needs at least one *.tf/*.tf.json file in the working directory.
    if not tf_working_dir.exists() or not tf_working_dir.is_dir():
        errors.append(
            {
                "type": "TerraformWorkingDirNotFound",
                "message": f"Terraform working directory does not exist or is not a directory: {tf_working_dir}",
                "remediation": "Verify TF_WORKING_DIR and the docker volume mount (TF_IAC_PATH). Use an absolute host path in CI/CD.",
            }
        )
        finished_at = _utc_now()
        emit_report(finished_at=finished_at, exit_code=1, detected=False)
        logger.error("run_failed", run_id=run_id, output_path=str(out_path))
        return 1

    tf_files = sorted(
        list(tf_working_dir.glob("*.tf")) + list(tf_working_dir.glob("*.tf.json"))
    )
    if not tf_files:
        errors.append(
            {
                "type": "TerraformNoConfigFiles",
                "message": "No Terraform configuration files (*.tf or *.tf.json) found in working directory.",
                "details": {"working_dir": str(tf_working_dir)},
                "remediation": "Verify TF_WORKING_DIR points to the Terraform root (where main.tf lives) and that the volume mount contains the expected files.",
            }
        )
        finished_at = _utc_now()
        emit_report(finished_at=finished_at, exit_code=1, detected=False)
        logger.error("run_failed", run_id=run_id, output_path=str(out_path))
        return 1

    # tf_version updated here after runner is available.
    tf_version = tf_runner.version()

    # Optional Azure validation/enrichment (does not block drift detection).
    if config.azure.validate_access:
        env = load_azure_env()
        sub_id = config.azure.subscription_id or env.subscription_id
        if not sub_id:
            errors.append(
                {
                    "type": "AzureValidationSkipped",
                    "message": "Azure subscription id missing; cannot validate access.",
                    "remediation": "Set ARM_SUBSCRIPTION_ID.",
                }
            )
        else:
            try:
                az = AzureResourceClient(sub_id)
                if config.azure.list_resource_groups:
                    rg_count = az.count_resource_groups()
                    logger.info("azure_enrichment", resource_groups_count=rg_count)
            except Exception as exc:
                errors.append(
                    {
                        "type": "AzureValidationError",
                        "message": str(exc),
                        "remediation": "Verify Service Principal / Managed Identity permissions (Reader at subscription scope).",
                    }
                )

    init_cmd = tf_runner.init(
        upgrade=config.terraform.init.upgrade,
        reconfigure=config.terraform.init.reconfigure,
        backend=config.terraform.init.backend,
    )
    init_result = {
        "cmd": TerraformRunner.redact_cmd(init_cmd.cmd),
        "return_code": init_cmd.return_code,
        "duration_ms": init_cmd.duration_ms,
    }
    if init_cmd.return_code != 0:
        errors.append(
            {
                "type": "TerraformInitError",
                "message": "terraform init failed",
                "details": {
                    "cmd": TerraformRunner.redact_cmd(init_cmd.cmd),
                    "stderr": _redact_sensitive(init_cmd.stderr[-8000:]),
                    "stdout": _redact_sensitive(init_cmd.stdout[-8000:]),
                },
                "remediation": "Ensure backend credentials are available and the Terraform directory is correct.",
            }
        )
        finished_at = _utc_now()
        emit_report(finished_at=finished_at, exit_code=1, detected=False)
        logger.error("run_failed", run_id=run_id, output_path=str(out_path))
        return 1

    ws_res = tf_runner.workspace_select_or_create(config.terraform.workspace)
    if ws_res.return_code != 0:
        errors.append(
            {
                "type": "TerraformWorkspaceError",
                "message": f"Failed to select/create workspace '{config.terraform.workspace}'",
                "details": {
                    "stderr": ws_res.stderr[-4000:],
                    "stdout": ws_res.stdout[-4000:],
                },
                "remediation": "Check Terraform workspace settings and backend permissions.",
            }
        )
        finished_at = _utc_now()
        emit_report(finished_at=finished_at, exit_code=1, detected=False)
        logger.error(
            "run_failed",
            run_id=run_id,
            reason="workspace_error",
            output_path=str(out_path),
        )
        return 1

    plan_cmd = tf_runner.plan_refresh_only(
        plan_path=tf_plan_path,
        lock_timeout=config.terraform.plan.lock_timeout,
        parallelism=config.terraform.plan.parallelism,
    )
    plan_result = {
        "cmd": TerraformRunner.redact_cmd(plan_cmd.cmd),
        "return_code": plan_cmd.return_code,
        "duration_ms": plan_cmd.duration_ms,
    }
    if config.report.include_raw_terraform_stdout:
        plan_result["stdout_tail"] = plan_cmd.stdout[-8000:]
        plan_result["stderr_tail"] = plan_cmd.stderr[-8000:]

    detected = plan_cmd.return_code == 2
    exit_code = plan_cmd.return_code

    if plan_cmd.return_code not in {0, 2}:
        errors.append(
            {
                "type": "TerraformPlanError",
                "message": "terraform plan -refresh-only failed",
                "details": {
                    "cmd": TerraformRunner.redact_cmd(plan_cmd.cmd),
                    "stderr": _redact_sensitive(plan_cmd.stderr[-8000:]),
                    "stdout": _redact_sensitive(plan_cmd.stdout[-8000:]),
                },
                "remediation": "Verify Terraform configuration and Azure credentials (ARM_*).",
            }
        )
        finished_at = _utc_now()
        emit_report(finished_at=finished_at, exit_code=1, detected=False)
        logger.error("run_failed", run_id=run_id, output_path=str(out_path))
        return 1

    plan_json = (
        tf_runner.show_plan_json(tf_plan_path)
        if config.report.include_plan_json
        else None
    )
    if plan_json:
        summary, items = normalize_terraform_plan(plan_json)
        drift_items = items

        # ============================================================
        # OPA EVALUATION (Shift-Right Decision Point)
        # ============================================================
        if config.opa.enabled and drift_items:
            logger.info(
                "opa_evaluation_start", run_id=run_id, drift_count=len(drift_items)
            )

            try:
                # 1. Normaliser pour OPA
                opa_input = normalize_drift_for_opa(drift_items)

                # 2. Appeler OPA Server
                opa_client = OPAClient(
                    OPAConfig(
                        server_url=config.opa.server_url,
                        policy_path=config.opa.policy_path,
                        timeout=config.opa.timeout,
                        fallback_on_error=config.opa.fallback_on_error,
                        auth_token=config.opa.auth_token,
                    )
                )

                opa_decisions = opa_client.evaluate_drift(opa_input)

                # 3. Enrichir les drift items avec décisions OPA
                drift_items = enrich_drift_items_with_opa(drift_items, opa_decisions)

                logger.info(
                    "opa_evaluation_complete",
                    run_id=run_id,
                    violations=len(opa_decisions.get("violations", [])),
                    effective_violations=len(
                        opa_decisions.get("effective_violations", [])
                    ),
                    excepted_violations=len(
                        opa_decisions.get("excepted_violations", [])
                    ),
                    compliant=len(opa_decisions.get("compliant", [])),
                    drift_exception_summary=opa_decisions.get(
                        "drift_exception_summary", {}
                    ),
                    fallback_mode=opa_decisions.get("metadata", {}).get(
                        "fallback_mode", False
                    ),
                )

            except Exception as exc:
                logger.error("opa_evaluation_failed", run_id=run_id, error=str(exc))
                errors.append(
                    {
                        "type": "OPAEvaluationError",
                        "message": f"OPA evaluation failed: {exc}",
                        "remediation": "Check OPA server connectivity and policy validity.",
                    }
                )
                if config.opa.fallback_on_error:
                    logger.warning(
                        "opa_using_fallback_conservative_decision",
                        run_id=run_id,
                    )
        else:
            if not config.opa.enabled:
                logger.warning("opa_disabled_skipping_evaluation", run_id=run_id)
            elif not drift_items:
                logger.info("no_drift_items_skipping_opa", run_id=run_id)

        drift_summary_obj = {
            "resources_changed": summary.resources_changed,
            "resources_by_action": summary.resources_by_action,
            "provider_names": summary.provider_names,
        }
    else:
        errors.append(
            {
                "type": "TerraformShowJsonSkipped",
                "message": "terraform show -json was skipped or failed; drift items not available.",
            }
        )

    finished_at = _utc_now()
    emit_report(finished_at=finished_at, exit_code=exit_code, detected=detected)

    logger.info(
        "report_written",
        run_id=run_id,
        detected=detected,
        output_path=str(out_path),
        resources_changed=drift_summary_obj.get("resources_changed", 0),
    )

    if config.defectdojo.enabled:
        error_count_before = len(errors)
        try:
            if not (
                config.defectdojo.base_url
                and config.defectdojo.api_key
                and config.defectdojo.engagement_id
            ):
                raise ValueError(
                    "DefectDojo config incomplete (base_url/api_key/engagement_id)."
                )
            dd_cfg = DefectDojoConfig(
                base_url=config.defectdojo.base_url,
                api_key=config.defectdojo.api_key,
                engagement_id=int(config.defectdojo.engagement_id),
                test_title=config.defectdojo.test_title,
                close_old_findings=config.defectdojo.close_old_findings,
                deduplication_on_engagement=config.defectdojo.deduplication_on_engagement,
                minimum_severity=config.defectdojo.minimum_severity,
            )
            dd = DefectDojoClient(dd_cfg)
            scan_date = finished_at.date().isoformat()
            findings = drift_items_to_defectdojo_generic_findings(
                drift_items, scan_date=scan_date
            )
            response = dd.import_scan_generic_findings(findings, scan_date=scan_date)
            logger.info("defectdojo_import_success", run_id=run_id, response=response)
        except Exception as exc:
            errors.append(
                {
                    "type": "DefectDojoPushError",
                    "message": str(exc),
                    "remediation": "Verify DefectDojo URL, API key permissions, and engagement id.",
                }
            )
            logger.error("defectdojo_import_failed", run_id=run_id, error=str(exc))
        finally:
            if len(errors) != error_count_before:
                emit_report(
                    finished_at=_utc_now(), exit_code=exit_code, detected=detected
                )

    if errors:
        return 1
    # Exit codes: 0=clean, 2=drift, 1=error (best practice for schedulers/CI).
    if detected:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
