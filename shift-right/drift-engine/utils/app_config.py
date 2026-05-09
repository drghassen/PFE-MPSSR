from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import structlog
import yaml
from pydantic import BaseModel, Field

logger = structlog.get_logger()


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
    close_old_findings: bool = False
    deduplication_on_engagement: bool = True
    minimum_severity: str = "Info"


class OPASection(BaseModel):
    enabled: bool = Field(default=True)
    server_url: str = Field(default="http://localhost:8182")
    policy_path: str = Field(default="cloudsentinel.shiftright.drift")
    timeout: int = Field(default=30)
    fallback_on_error: bool = Field(default=True)
    auth_token: str = Field(default="")


class AppConfig(BaseModel):
    engine: EngineConfig = Field(default_factory=EngineConfig)
    azure: AzureConfig = Field(default_factory=AzureConfig)
    terraform: TerraformConfig = Field(default_factory=TerraformConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    defectdojo: DefectDojoSection = Field(default_factory=DefectDojoSection)
    opa: OPASection = Field(default_factory=OPASection)
    pipeline_correlation_id: str | None = None


def _bool_from_env(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _expand_env_placeholders(value: Any) -> Any:
    """Expands ${VAR} and ${VAR:-default} placeholders in YAML-loaded structures."""
    if isinstance(value, str):
        def repl(match: re.Match[str]) -> str:
            expr = match.group(1)
            if ":-" in expr:
                var, default = expr.split(":-", 1)
                return os.getenv(var, default)
            return os.getenv(expr, "")
        return re.compile(r"\$\{([^}]+)\}").sub(repl, value)
    if isinstance(value, list):
        return [_expand_env_placeholders(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand_env_placeholders(v) for k, v in value.items()}
    return value


def load_config(path: Path) -> AppConfig:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    expanded = _expand_env_placeholders(raw)

    pipeline_correlation_id = (
        os.getenv("CLOUDSENTINEL_PIPELINE_CORRELATION_ID") or ""
    ).strip()
    if pipeline_correlation_id:
        expanded["pipeline_correlation_id"] = pipeline_correlation_id

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
