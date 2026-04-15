#!/usr/bin/env python3
"""Main orchestration for CloudSentinel exception fetch pipeline."""

from __future__ import annotations

import logging
import os
import sys
from typing import Optional

from .fetch_defectdojo import DefectDojoFetchError, fetch_risk_acceptances
from .fetch_mapping import json_payload, map_risk_acceptances, save_outputs
from .fetch_utils import ensure_dir
from .fetch_validation import FetchContext


def _parse_bool_env(name: str, default: str = "false") -> bool:
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


def _parse_set_env(name: str, default_csv: str) -> set[str]:
    return {
        item.strip().lower()
        for item in os.environ.get(name, default_csv).split(",")
        if item.strip()
    }


def _parse_threshold(value: str, fallback: float = 0.85) -> float:
    try:
        parsed = float(value)
    except ValueError:
        return fallback
    if parsed < 0.0 or parsed > 1.0:
        return fallback
    return parsed


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

    repo_root = os.getcwd()
    output_file = os.environ.get(
        "OPA_EXCEPTIONS_FILE", os.path.join(repo_root, ".cloudsentinel", "exceptions.json")
    )
    dropped_file = os.path.join(repo_root, ".cloudsentinel", "dropped_exceptions.json")
    audit_log_file = os.environ.get(
        "CLOUDSENTINEL_AUDIT_LOG", os.path.join(repo_root, ".cloudsentinel", "audit_events.jsonl")
    )

    return FetchContext(
        logger=logger,
        dojo_url=os.environ.get("DOJO_URL", "").rstrip("/"),
        dojo_api_key=os.environ.get("DOJO_API_KEY", ""),
        dojo_engagement_id=os.environ.get("DOJO_ENGAGEMENT_ID", ""),
        repo_root=repo_root,
        output_file=output_file,
        dropped_file=dropped_file,
        audit_log_file=audit_log_file,
        schema_version="2.0.0",
        severity_enum={"CRITICAL", "HIGH", "MEDIUM", "LOW"},
        allowed_tools={"checkov", "trivy", "gitleaks"},
        allowed_decisions={"accept", "mitigate", "fix", "transfer", "avoid"},
        enforce_approver_allowlist=_parse_bool_env("CLOUDSENTINEL_ENFORCE_APPROVER_ALLOWLIST", "false"),
        approver_allowlist=_parse_set_env("CLOUDSENTINEL_APPROVER_ALLOWLIST", "appsecteam,security-team"),
        fuzzy_threshold=_parse_threshold(os.environ.get("CLOUDSENTINEL_FUZZY_MATCH_THRESHOLD", "0.85")),
    )


def execute(ctx: FetchContext) -> None:
    ctx.logger.info("Starting CloudSentinel DefectDojo exception ingestion")

    if not ctx.dojo_url or not ctx.dojo_api_key:
        ctx.logger.error("DefectDojo credentials are not configured")
        raise SystemExit(2)

    ensure_dir(ctx.audit_log_file)
    with open(ctx.audit_log_file, "w", encoding="utf-8"):
        pass

    try:
        raw_ras = fetch_risk_acceptances(ctx.dojo_url, ctx.dojo_api_key, ctx.dojo_engagement_id, ctx.logger)
    except DefectDojoFetchError as exc:
        ctx.logger.error(f"DefectDojo fetch failed: {exc}")
        raise SystemExit(2) from exc

    mapped, meta = map_risk_acceptances(ctx, raw_ras)
    payload = json_payload(ctx, mapped, meta)
    save_outputs(ctx, payload)

    ctx.logger.info(
        "Exceptions payload written: valid=%s dropped=%s",
        len(mapped),
        len(ctx.dropped),
    )


def run_cli() -> None:
    ctx = build_context()
    try:
        execute(ctx)
    except SystemExit:
        raise
    except Exception as exc:
        ctx.logger.exception(f"Unhandled error in fetch-exceptions: {exc}")
        raise SystemExit(2) from exc
