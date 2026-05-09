"""
CloudSentinel Drift Engine (Shift-Right).

Scheduled batch job that detects configuration drift between Terraform IaC and live
Azure resources using `terraform plan -refresh-only -detailed-exitcode`, then emits
a standardized drift report and optionally pushes findings to DefectDojo (v2 API).
"""

from __future__ import annotations

import argparse
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from utils.app_config import AppConfig, load_config
from utils.azure_client import AzureResourceClient, load_azure_env
from utils.defectdojo_client import DefectDojoClient, DefectDojoConfig
from utils.enrichment import enrich_drift_items_with_opa
from utils.json_normalizer import (
    classify_drift_severity,
    drift_items_to_defectdojo_generic_findings,
    normalize_terraform_plan,
)
from utils.opa_client import OPAClient, OPAConfig
from utils.opa_normalizer import normalize_drift_for_opa
from utils.path_resolver import choose_tf_binary, resolve_engine_root, resolve_path_under
from utils.redaction import redact_sensitive, safe_env_snapshot
from utils.report_builder import (
    SCHEMA_VERSION,
    build_report_context,
    render_report,
    write_json,
)
from utils.terraform_runner import TerraformRunner

logger = structlog.get_logger()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def configure_logging() -> None:
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ]
    )


# ---------------------------------------------------------------------------
# Pre-config error reporter (used before AppConfig is available)
# ---------------------------------------------------------------------------

def _write_minimal_error_report(
    *,
    engine_root: Path,
    run_id: str,
    correlation_id: str,
    pipeline_correlation_id: str,
    started_at: datetime,
    tf_dir: str | None,
    output_override: str | None,
    message: str,
    remediation: str,
) -> None:
    finished_at = _utc_now()
    out_path = Path(
        output_override or os.getenv("DRIFT_OUTPUT_PATH") or "output/drift-report.json"
    ).expanduser()
    if not out_path.is_absolute():
        out_path = (engine_root / out_path).resolve()

    payload: dict[str, Any] = {
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
            "correlation_id": correlation_id,
            "engine": "cloudsentinel-drift-engine",
            "engine_version": "unknown",
            "tenant_id": None,
            "subscription_id": None,
            "terraform_workspace": "unknown",
            "terraform_working_dir": tf_dir or ".",
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
            {"type": "ConfigLoadError", "message": message, "remediation": remediation}
        ],
    }
    if pipeline_correlation_id:
        payload["cloudsentinel"]["pipeline_correlation_id"] = pipeline_correlation_id
    write_json(out_path, payload)


# ---------------------------------------------------------------------------
# DriftEngine — orchestrates all phases of a single drift detection run
# ---------------------------------------------------------------------------

class DriftEngine:
    def __init__(
        self,
        config: AppConfig,
        run_id: str,
        correlation_id: str,
        started_at: datetime,
        engine_root: Path,
    ) -> None:
        self._config = config
        self._run_id = run_id
        self._correlation_id = correlation_id
        self._started_at = started_at
        self._errors: list[dict[str, Any]] = []

        self._tf_version: str | None = None
        self._init_result: dict[str, Any] = {}
        self._plan_result: dict[str, Any] = {}
        self._drift_items: list[dict[str, Any]] = []
        self._drift_filtered_items: list[dict[str, Any]] = []
        self._drift_summary: dict[str, Any] = {
            "resources_changed": 0,
            "outputs_changed": 0,
            "resources_by_action": {},
            "provider_names": [],
            "filtered_count": 0,
        }

        self._template_path = resolve_path_under(engine_root, config.report.template_path)
        self._out_path = resolve_path_under(engine_root, config.report.output_path)

        tf_working_dir = Path(config.terraform.working_dir).expanduser().resolve()
        drift_work_dir = (
            Path(os.getenv("DRIFT_WORK_DIR", "/tmp/cloudsentinel-drift"))
            .expanduser()
            .resolve()
        )
        self._tf_working_dir = tf_working_dir
        self._tf_plan_path = drift_work_dir / run_id / "tfplan"

        tf_bin = choose_tf_binary(tf_working_dir)
        self._tf_runner = TerraformRunner(
            working_dir=tf_working_dir,
            terraform_bin=tf_bin,
            timeout_s=int(os.getenv("TF_PLAN_TIMEOUT_S", "600")),
        )
        logger.info(
            "iac_cli_selected",
            run_id=run_id,
            binary=tf_bin,
            working_dir=str(tf_working_dir),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _emit_report(self, *, finished_at: datetime, exit_code: int, detected: bool) -> None:
        context = build_report_context(
            config=self._config,
            run_id=self._run_id,
            correlation_id=self._correlation_id,
            started_at=self._started_at,
            finished_at=finished_at,
            exit_code=exit_code,
            detected=detected,
            tf_version=self._tf_version,
            init_result=self._init_result,
            plan_result=self._plan_result,
            drift_summary=self._drift_summary,
            drift_items=self._drift_items,
            drift_filtered_items=self._drift_filtered_items,
            errors=self._errors,
        )
        write_json(self._out_path, render_report(self._template_path, context))

    @staticmethod
    def _final_exit_code(*, detected: bool, has_errors: bool) -> int:
        """
        Canonical CloudSentinel exit code mapping.
        - 1: execution error (fail-closed)
        - 2: drift detected
        - 0: clean
        """
        if has_errors:
            return 1
        return 2 if detected else 0

    def _fail(self, exit_code: int, detected: bool) -> int:
        self._emit_report(finished_at=_utc_now(), exit_code=exit_code, detected=detected)
        logger.error("run_failed", run_id=self._run_id, output_path=str(self._out_path))
        return exit_code

    # ------------------------------------------------------------------
    # Phase methods
    # ------------------------------------------------------------------

    def _validate_working_dir(self) -> int | None:
        d = self._tf_working_dir
        if not d.exists() or not d.is_dir():
            self._errors.append({
                "type": "TerraformWorkingDirNotFound",
                "message": f"Terraform working directory does not exist or is not a directory: {d}",
                "remediation": (
                    "Verify TF_WORKING_DIR and the docker volume mount (TF_IAC_PATH). "
                    "Use an absolute host path in CI/CD."
                ),
            })
            return self._fail(1, False)

        tf_files = sorted(list(d.glob("*.tf")) + list(d.glob("*.tf.json")))
        if not tf_files:
            self._errors.append({
                "type": "TerraformNoConfigFiles",
                "message": "No Terraform configuration files (*.tf or *.tf.json) found in working directory.",
                "details": {"working_dir": str(d)},
                "remediation": (
                    "Verify TF_WORKING_DIR points to the Terraform root (where main.tf lives) "
                    "and that the volume mount contains the expected files."
                ),
            })
            return self._fail(1, False)
        return None

    def _run_azure_validation(self) -> None:
        env = load_azure_env()
        sub_id = self._config.azure.subscription_id or env.subscription_id
        if not sub_id:
            self._errors.append({
                "type": "AzureValidationSkipped",
                "message": "Azure subscription id missing; cannot validate access.",
                "remediation": "Set ARM_SUBSCRIPTION_ID.",
            })
            return
        try:
            az = AzureResourceClient(sub_id)
            if self._config.azure.list_resource_groups:
                rg_count = az.count_resource_groups()
                logger.info("azure_enrichment", resource_groups_count=rg_count)
        except Exception as exc:
            self._errors.append({
                "type": "AzureValidationError",
                "message": str(exc),
                "remediation": (
                    "Verify Service Principal / Managed Identity permissions "
                    "(Reader at subscription scope)."
                ),
            })

    def _run_init(self) -> int | None:
        cfg = self._config.terraform
        init_cmd = self._tf_runner.init(
            upgrade=cfg.init.upgrade,
            reconfigure=cfg.init.reconfigure,
            backend=cfg.init.backend,
        )
        self._init_result = {
            "cmd": TerraformRunner.redact_cmd(init_cmd.cmd),
            "return_code": init_cmd.return_code,
            "duration_ms": init_cmd.duration_ms,
        }
        if init_cmd.return_code != 0:
            self._errors.append({
                "type": "TerraformInitError",
                "message": "terraform init failed",
                "details": {
                    "cmd": TerraformRunner.redact_cmd(init_cmd.cmd),
                    "stderr": redact_sensitive(init_cmd.stderr[-8000:]),
                    "stdout": redact_sensitive(init_cmd.stdout[-8000:]),
                },
                "remediation": (
                    "Ensure backend credentials are available and the Terraform directory is correct."
                ),
            })
            return self._fail(1, False)
        return None

    def _run_workspace(self) -> int | None:
        workspace = self._config.terraform.workspace
        ws_res = self._tf_runner.workspace_select_or_create(workspace)
        if ws_res.return_code != 0:
            self._errors.append({
                "type": "TerraformWorkspaceError",
                "message": f"Failed to select/create workspace '{workspace}'",
                "details": {
                    "stderr": ws_res.stderr[-4000:],
                    "stdout": ws_res.stdout[-4000:],
                },
                "remediation": "Check Terraform workspace settings and backend permissions.",
            })
            return self._fail(1, False)
        return None

    def _run_plan(self) -> tuple[int, bool] | tuple[None, None]:
        """Returns (exit_code, detected) on success, or (None, None) on fatal error."""
        cfg = self._config.terraform
        plan_cmd = self._tf_runner.plan_refresh_only(
            plan_path=self._tf_plan_path,
            lock_timeout=cfg.plan.lock_timeout,
            parallelism=cfg.plan.parallelism,
        )
        self._plan_result = {
            "cmd": TerraformRunner.redact_cmd(plan_cmd.cmd),
            "return_code": plan_cmd.return_code,
            "duration_ms": plan_cmd.duration_ms,
        }
        if self._config.report.include_raw_terraform_stdout:
            self._plan_result["stdout_tail"] = plan_cmd.stdout[-8000:]
            self._plan_result["stderr_tail"] = plan_cmd.stderr[-8000:]

        if plan_cmd.return_code not in {0, 2}:
            self._errors.append({
                "type": "TerraformPlanError",
                "message": "terraform plan -refresh-only failed",
                "details": {
                    "cmd": TerraformRunner.redact_cmd(plan_cmd.cmd),
                    "stderr": redact_sensitive(plan_cmd.stderr[-8000:]),
                    "stdout": redact_sensitive(plan_cmd.stdout[-8000:]),
                },
                "remediation": "Verify Terraform configuration and Azure credentials (ARM_*).",
            })
            self._fail(1, False)
            return None, None

        return plan_cmd.return_code, plan_cmd.return_code == 2

    def _run_opa_evaluation(self) -> None:
        cfg = self._config.opa
        try:
            opa_input = normalize_drift_for_opa(self._drift_items)
            opa_client = OPAClient(
                OPAConfig(
                    server_url=cfg.server_url,
                    policy_path=cfg.policy_path,
                    timeout=cfg.timeout,
                    fallback_on_error=cfg.fallback_on_error,
                    auth_token=cfg.auth_token,
                )
            )
            opa_decisions = opa_client.evaluate_drift(opa_input)
            self._drift_items = enrich_drift_items_with_opa(self._drift_items, opa_decisions)
            logger.info(
                "opa_evaluation_complete",
                run_id=self._run_id,
                violations=len(opa_decisions.get("violations", [])),
                effective_violations=len(opa_decisions.get("effective_violations", [])),
                excepted_violations=len(opa_decisions.get("excepted_violations", [])),
                compliant=len(opa_decisions.get("compliant", [])),
                drift_exception_summary=opa_decisions.get("drift_exception_summary", {}),
                fallback_mode=opa_decisions.get("metadata", {}).get("fallback_mode", False),
            )
        except Exception as exc:
            logger.error("opa_evaluation_failed", run_id=self._run_id, error=str(exc))
            self._errors.append({
                "type": "OPAEvaluationError",
                "message": f"OPA evaluation failed: {exc}",
                "remediation": "Check OPA server connectivity and policy validity.",
            })
            if cfg.fallback_on_error:
                logger.warning(
                    "opa_using_fallback_conservative_decision", run_id=self._run_id
                )

    def _normalize_and_evaluate(self, detected: bool) -> tuple[int | None, bool]:
        """Normalize the plan JSON and run OPA. Returns (exit_code_override, updated_detected)."""
        plan_json = (
            self._tf_runner.show_plan_json(self._tf_plan_path)
            if self._config.report.include_plan_json
            else None
        )
        if plan_json is None:
            self._errors.append({
                "type": "TerraformShowJsonSkipped",
                "message": "terraform show -json was skipped or failed; drift items not available.",
            })
            if detected:
                logger.warning(
                    "drift_detected_but_plan_json_unavailable",
                    run_id=self._run_id,
                    hint="drift signal lost — report marked as error, not clean",
                )
                return 1, False
            return None, detected

        summary, items = normalize_terraform_plan(plan_json)
        self._drift_items = items
        self._drift_filtered_items = summary.filtered_items

        if detected and not self._drift_items:
            logger.info(
                "drift_ignored_all_items_filtered",
                run_id=self._run_id,
                filtered_count=len(summary.filtered_items),
                filtered=[
                    {
                        "address": f.get("address"),
                        "type": f.get("type"),
                        "filter_reason": f.get("filter_reason"),
                    }
                    for f in summary.filtered_items
                ],
            )
            detected = False

        if self._config.opa.enabled and self._drift_items:
            logger.info(
                "opa_evaluation_start",
                run_id=self._run_id,
                drift_count=len(self._drift_items),
            )
            self._run_opa_evaluation()
        elif not self._config.opa.enabled:
            logger.warning("opa_disabled_skipping_evaluation", run_id=self._run_id)
        else:
            logger.info("no_drift_items_skipping_opa", run_id=self._run_id)

        # Apply static fallback severity to any item OPA did not enrich.
        for item in self._drift_items:
            if not item.get("severity"):
                item["severity"] = classify_drift_severity(
                    str(item.get("type") or ""),
                    item.get("changed_paths") or [],
                    item.get("resource_id"),
                    item.get("provenance"),
                )

        self._drift_summary = {
            "resources_changed": summary.resources_changed,
            "outputs_changed": summary.outputs_changed,
            "resources_by_action": summary.resources_by_action,
            "provider_names": summary.provider_names,
            "filtered_count": len(summary.filtered_items),
        }
        return None, detected

    def _push_defectdojo(self, exit_code: int, detected: bool) -> None:
        if not self._config.defectdojo.enabled:
            return
        error_count_before = len(self._errors)
        try:
            raw = self._config.defectdojo
            dd_cfg = DefectDojoConfig(
                base_url=raw.base_url,
                api_key=raw.api_key,
                engagement_id=int(raw.engagement_id),
                test_title=raw.test_title,
                close_old_findings=raw.close_old_findings,
                deduplication_on_engagement=raw.deduplication_on_engagement,
                minimum_severity=raw.minimum_severity,
            )
            dd = DefectDojoClient(dd_cfg)
            scan_date = _utc_now().date().isoformat()
            findings = drift_items_to_defectdojo_generic_findings(
                self._drift_items, scan_date=scan_date
            )
            response = dd.import_scan_generic_findings(findings, scan_date=scan_date)
            logger.info("defectdojo_import_success", run_id=self._run_id, response=response)
        except Exception as exc:
            self._errors.append({
                "type": "DefectDojoPushError",
                "message": str(exc),
                "remediation": "Verify DefectDojo URL, API key permissions, and engagement id.",
            })
            logger.error("defectdojo_import_failed", run_id=self._run_id, error=str(exc))
        finally:
            if len(self._errors) != error_count_before:
                self._emit_report(
                    finished_at=_utc_now(), exit_code=exit_code, detected=detected
                )

    # ------------------------------------------------------------------
    # Main orchestration
    # ------------------------------------------------------------------

    def run(self) -> int:
        self._tf_version = self._tf_runner.version()

        if (rc := self._validate_working_dir()) is not None:
            return rc

        if self._config.azure.validate_access:
            self._run_azure_validation()

        if (rc := self._run_init()) is not None:
            return rc

        if (rc := self._run_workspace()) is not None:
            return rc

        exit_code, detected = self._run_plan()
        if exit_code is None:
            return 1

        exit_code_override, detected = self._normalize_and_evaluate(detected)
        if exit_code_override is not None:
            exit_code, detected = exit_code_override, False

        # Keep report and process semantics aligned to avoid CI contract mismatch:
        # report.drift.exit_code must reflect the post-normalization detection state.
        exit_code = self._final_exit_code(detected=detected, has_errors=bool(self._errors))

        finished_at = _utc_now()
        self._emit_report(finished_at=finished_at, exit_code=exit_code, detected=detected)
        logger.info(
            "report_written",
            run_id=self._run_id,
            detected=detected,
            output_path=str(self._out_path),
            resources_changed=self._drift_summary.get("resources_changed", 0),
        )

        self._push_defectdojo(exit_code, detected)

        # Re-evaluate after optional DefectDojo push because it can append errors.
        # This keeps process exit code fail-closed and consistent with engine policy.
        return self._final_exit_code(detected=detected, has_errors=bool(self._errors))


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="CloudSentinel Drift Engine (scheduled batch job)"
    )
    parser.add_argument(
        "--config", default=os.getenv("DRIFT_CONFIG_PATH", "config/drift_config.yaml")
    )
    parser.add_argument("--tf-dir", default=None, help="Override Terraform working directory")
    parser.add_argument("--output", default=None, help="Override drift report output path")
    parser.add_argument(
        "--push-dojo", action="store_true", help="Force push findings to DefectDojo"
    )
    args = parser.parse_args(argv)

    configure_logging()
    run_id = str(uuid.uuid4())
    pipeline_correlation_id = (
        os.getenv("CLOUDSENTINEL_PIPELINE_CORRELATION_ID") or ""
    ).strip()
    correlation_id = pipeline_correlation_id or str(uuid.uuid4())
    os.environ["CLOUDSENTINEL_CORRELATION_ID"] = correlation_id
    started_at = _utc_now()

    config_path = Path(args.config).expanduser()
    engine_root = resolve_engine_root(config_path)

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
        _write_minimal_error_report(
            engine_root=engine_root,
            run_id=run_id,
            correlation_id=correlation_id,
            pipeline_correlation_id=pipeline_correlation_id,
            started_at=started_at,
            tf_dir=args.tf_dir,
            output_override=args.output,
            message=str(exc),
            remediation="Validate drift_config.yaml and required environment variables.",
        )
        return 1

    if config.defectdojo.enabled and not (
        config.defectdojo.base_url
        and config.defectdojo.api_key
        and config.defectdojo.engagement_id
    ):
        logger.error("defectdojo_config_missing")
        _write_minimal_error_report(
            engine_root=engine_root,
            run_id=run_id,
            correlation_id=correlation_id,
            pipeline_correlation_id=pipeline_correlation_id,
            started_at=started_at,
            tf_dir=args.tf_dir,
            output_override=args.output,
            message="DefectDojo config incomplete (base_url/api_key/engagement_id).",
            remediation=(
                "Set DEFECTDOJO_URL, DEFECTDOJO_API_KEY, and DOJO_ENGAGEMENT_ID_RIGHT "
                "(or DEFECTDOJO_ENGAGEMENT_ID_RIGHT) in the environment (.env or CI secrets)."
            ),
        )
        return 1

    logger.info(
        "run_started",
        run_id=run_id,
        correlation_id=correlation_id,
        pipeline_correlation_id=pipeline_correlation_id or None,
        engine=config.engine.name,
        version=config.engine.version,
        env=safe_env_snapshot(),
    )

    return DriftEngine(
        config=config,
        run_id=run_id,
        correlation_id=correlation_id,
        started_at=started_at,
        engine_root=engine_root,
    ).run()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
