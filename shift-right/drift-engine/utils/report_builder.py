from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

SCHEMA_VERSION = "1.0.0"

_OCSF_ORDER = ["Info", "Low", "Medium", "High", "Critical"]
_OCSF_ID = {"Info": 1, "Low": 2, "Medium": 3, "High": 4, "Critical": 5}


def build_report_context(
    config: Any,
    run_id: str,
    correlation_id: str,
    started_at: datetime,
    finished_at: datetime,
    exit_code: int,
    detected: bool,
    tf_version: str | None,
    init_result: dict[str, Any],
    plan_result: dict[str, Any],
    drift_summary: dict[str, Any],
    drift_items: list[dict[str, Any]],
    drift_filtered_items: list[dict[str, Any]],
    errors: list[dict[str, Any]],
) -> dict[str, Any]:
    if not detected:
        severity = "Info"
    else:
        severities = [
            item.get("severity")
            for item in drift_items
            if item.get("severity") in _OCSF_ORDER
        ]
        severity = (
            max(severities, key=lambda s: _OCSF_ORDER.index(s))
            if severities
            else "Medium"
        )

    cloudsentinel = {
        "run_id": run_id,
        "correlation_id": correlation_id,
        "engine": config.engine.name,
        "engine_version": config.engine.version,
        "tenant_id": config.azure.tenant_id,
        "subscription_id": config.azure.subscription_id,
        "terraform_workspace": config.terraform.workspace,
        "terraform_working_dir": Path(config.terraform.working_dir).resolve().as_posix(),
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_ms": int((finished_at - started_at).total_seconds() * 1000),
        "run_status": "error" if errors else ("drifted" if detected else "clean"),
    }
    if config.pipeline_correlation_id:
        cloudsentinel["pipeline_correlation_id"] = config.pipeline_correlation_id

    return {
        "schema_version": SCHEMA_VERSION,
        "ocsf": {
            "version": config.engine.ocsf_version,
            "class_uid": 2001,
            "category_uid": 2,
            "type_uid": 200100,
            "time": finished_at.isoformat(),
            "severity_id": _OCSF_ID.get(severity, 3),
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
        },
        "cloudsentinel": cloudsentinel,
        "drift": {
            "detected": detected,
            "exit_code": exit_code,
            "summary": drift_summary,
            "items": drift_items,
            "filtered_items": drift_filtered_items,
        },
        "terraform": {"version": tf_version, "init": init_result, "plan": plan_result},
        "errors": errors,
    }


def render_report(template_path: Path, context: dict[str, Any]) -> dict[str, Any]:
    env = Environment(
        loader=FileSystemLoader(str(template_path.parent)), autoescape=False
    )
    rendered = env.get_template(template_path.name).render(**context)
    return json.loads(rendered)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
