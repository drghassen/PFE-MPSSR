#!/usr/bin/env python3
"""Main orchestration for enterprise exceptions fetch pipeline."""

from __future__ import annotations

import logging
import os
import sys
from typing import Any, Dict, Optional, Set

from .fetch_defectdojo import DefectDojoFetchError, fetch_risk_acceptances
from .fetch_mapping import emit_audit_event, json_payload, map_risk_acceptances, save_outputs
from .fetch_validation import FetchContext


def _parse_bool_env(name: str, default: str = "false") -> bool:
    return os.environ.get(name, default).lower() == "true"


def _parse_set_env(name: str, default_csv: str) -> Set[str]:
    return {
        role.strip().upper()
        for role in os.environ.get(name, default_csv).split(",")
        if role.strip()
    }


def configure_logging() -> logging.Logger:
    logging.basicConfig(
        level=logging.INFO,
        format='{"time":"%(asctime)s","level":"%(levelname)s","component":"fetch-exceptions","message":"%(message)s"}',
        datefmt="%Y-%m-%dT%H:%M:%SZ",
        stream=sys.stderr,
    )
    return logging.getLogger("fetch-exceptions")


def build_context(logger: Optional[logging.Logger] = None) -> FetchContext:
    logger = logger or configure_logging()

    dojo_url = os.environ.get("DOJO_URL", "").rstrip("/")
    dojo_api_key = os.environ.get("DOJO_API_KEY", "")
    repo_root = os.getcwd()

    ci_project_name = os.environ.get("CI_PROJECT_NAME", "unknown")
    ci_project_path = os.environ.get("CI_PROJECT_PATH", ci_project_name)
    ci_commit_ref_name = os.environ.get("CI_COMMIT_REF_NAME", "")
    ci_commit_sha = os.environ.get("CI_COMMIT_SHA", "")

    output_file = os.environ.get(
        "OPA_EXCEPTIONS_FILE", os.path.join(repo_root, ".cloudsentinel", "exceptions.json")
    )
    dropped_file = os.path.join(repo_root, ".cloudsentinel", "dropped_exceptions.json")
    audit_log_file = os.environ.get(
        "CLOUDSENTINEL_AUDIT_LOG", os.path.join(repo_root, ".cloudsentinel", "audit_events.jsonl")
    )

    # Compatibility toggle: legacy schema can coexist with v2 until sunset date.
    legacy_compat = _parse_bool_env("CLOUDSENTINEL_LEGACY_COMPAT", "true")
    legacy_sunset_date = os.environ.get("CLOUDSENTINEL_LEGACY_SUNSET_DATE", "2026-12-31T23:59:59Z")

    allowed_approver_roles = _parse_set_env(
        "CLOUDSENTINEL_ALLOWED_APPROVER_ROLES",
        "APPSEC_L1,APPSEC_L2,APPSEC_L3,APPSEC_MANAGER,SECURITY_MANAGER",
    )
    global_scope_allowed_roles = _parse_set_env(
        "CLOUDSENTINEL_GLOBAL_SCOPE_ALLOWED_ROLES",
        "APPSEC_L3,APPSEC_MANAGER,SECURITY_MANAGER",
    )

    break_glass_max_days = int(os.environ.get("CLOUDSENTINEL_BREAK_GLASS_MAX_DAYS", "7"))

    allowed_scope_types = {"commit", "branch", "repo", "global"}
    severity_enum = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

    role_ranks = {
        "APPSEC_L1": 1,
        "APPSEC_L2": 2,
        "APPSEC_L3": 3,
        "APPSEC_MANAGER": 4,
        "SECURITY_MANAGER": 4,
    }

    schema_version = "2.0.0"

    return FetchContext(
        logger=logger,
        dojo_url=dojo_url,
        dojo_api_key=dojo_api_key,
        repo_root=repo_root,
        ci_project_name=ci_project_name,
        ci_project_path=ci_project_path,
        ci_commit_ref_name=ci_commit_ref_name,
        ci_commit_sha=ci_commit_sha,
        output_file=output_file,
        dropped_file=dropped_file,
        audit_log_file=audit_log_file,
        legacy_compat=legacy_compat,
        legacy_sunset_date=legacy_sunset_date,
        allowed_approver_roles=allowed_approver_roles,
        global_scope_allowed_roles=global_scope_allowed_roles,
        break_glass_max_days=break_glass_max_days,
        allowed_scope_types=allowed_scope_types,
        severity_enum=severity_enum,
        role_ranks=role_ranks,
        schema_version=schema_version,
    )


def emit_empty(ctx: FetchContext, reason: str) -> None:
    ctx.logger.warning(f"No approved active exceptions found: {reason}")
    payload = json_payload(
        ctx,
        [],
        {
            "reason": reason,
            "source": "defectdojo",
            "total_raw": 0,
            "total_mapped": 0,
            "total_dropped": len(ctx.dropped),
        },
    )
    save_outputs(ctx, payload)
    emit_audit_event(
        ctx,
        "exceptions_payload_emitted",
        {
            "reason": reason,
            "total_exceptions": 0,
            "total_dropped": len(ctx.dropped),
        },
    )
    raise SystemExit(0)


def execute(ctx: FetchContext) -> None:
    ctx.logger.info("Starting enterprise exceptions fetch process")

    if not ctx.dojo_url or not ctx.dojo_api_key:
        ctx.logger.error("DefectDojo credentials are not configured")
        raise SystemExit(2)

    try:
        raw_ras = fetch_risk_acceptances(ctx.dojo_url, ctx.dojo_api_key, ctx.logger)
    except DefectDojoFetchError as exc:
        ctx.logger.error(f"DefectDojo fetch failed: {exc}")
        raise SystemExit(2) from exc

    if not raw_ras:
        emit_empty(ctx, "No approved active risk acceptances found")

    mapped, meta = map_risk_acceptances(ctx, raw_ras)
    payload = json_payload(ctx, mapped, meta)

    save_outputs(ctx, payload)
    emit_audit_event(
        ctx,
        "exceptions_payload_emitted",
        {
            "total_exceptions": len(mapped),
            "total_dropped": len(ctx.dropped),
            "legacy_mode": meta.get("legacy_mode", False),
        },
    )

    ctx.logger.info(f"Exceptions payload written: mapped={len(mapped)} dropped={len(ctx.dropped)}")


def run_cli() -> None:
    ctx = build_context()
    try:
        execute(ctx)
    except SystemExit:
        raise
    except Exception as exc:
        ctx.logger.exception(f"Unhandled error in fetch-exceptions: {exc}")
        raise SystemExit(2) from exc
