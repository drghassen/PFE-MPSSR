#!/usr/bin/env python3
"""Normalization orchestration, output emission, and audit trail generation."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Tuple

from .fetch_normalization import (
    accepted_findings,
    normalize_finding_candidate,
    risk_acceptance_id,
)
from .fetch_utils import (
    ensure_dir,
    normalize_path,
    now_utc,
    sanitize_text,
    save_json,
    to_rfc3339,
)
from .fetch_validation import (
    FetchContext,
    is_active_accepted,
    parse_approved_at,
    parse_approved_by,
    parse_decision,
    parse_expires_at,
    parse_requested_by,
    parse_status,
    stable_exception_id,
    validate_normalized_exception,
)


def _build_ci_scope() -> dict:
    """
    Injects pipeline execution context into the exception scope.
    These values are NOT sourced from DefectDojo — they come from CI environment variables.
    DefectDojo manages risk lifecycle; the fetch layer binds that risk to a CI context.
    """
    scope: dict = {}

    repo = os.environ.get("CI_PROJECT_PATH", "").strip()
    if repo:
        scope["repos"] = [repo]

    branch = os.environ.get("CI_COMMIT_REF_NAME", "").strip()
    if branch:
        scope["branches"] = [branch]

    env = (
        (os.environ.get("CI_ENVIRONMENT_NAME", "") or os.environ.get("ENVIRONMENT", ""))
        .strip()
        .lower()
    )
    valid_envs = {"dev", "test", "staging", "prod"}
    if env in valid_envs:
        scope["environments"] = [env]

    return scope


def emit_audit_event(
    ctx: FetchContext,
    input_payload: Any,
    output_payload: Optional[Dict[str, Any]],
    status: str,
    reason: Optional[str] = None,
) -> None:
    ensure_dir(ctx.audit_log_file)
    event: Dict[str, Any] = {
        "timestamp": to_rfc3339(now_utc()),
        "scan_id": ctx.scan_id,
        "source": "defectdojo",
        "action": "normalize_exception",
        "input": input_payload,
        "output": output_payload,
        "status": status,
    }
    if reason:
        event["reason"] = reason

    with open(ctx.audit_log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, separators=(",", ":"), sort_keys=True) + "\n")


def json_payload(
    ctx: FetchContext, exceptions: List[Dict[str, Any]], meta: Dict[str, Any]
) -> Dict[str, Any]:
    return {
        "cloudsentinel": {
            "exceptions": {
                "schema_version": ctx.schema_version,
                "generated_at": to_rfc3339(now_utc()),
                "metadata": meta,
                "exceptions": exceptions,
            }
        }
    }


def drop(
    ctx: FetchContext, ra_identifier: str, reason: str, detail: str, input_payload: Any
) -> None:
    record = {
        "risk_acceptance_id": ra_identifier,
        "reason": reason,
        "detail": detail,
        "timestamp": to_rfc3339(now_utc()),
        "input": input_payload,
    }
    ctx.dropped.append(record)


def save_outputs(ctx: FetchContext, payload: Dict[str, Any]) -> None:
    save_json(ctx.output_file, payload)
    save_json(ctx.dropped_file, {"dropped_exceptions": ctx.dropped})


def _draft_exception(
    ctx: FetchContext,
    ra: Dict[str, Any],
    finding_candidate: Dict[str, Any],
    finding_raw: Dict[str, Any],
) -> Dict[str, Any]:
    tool = sanitize_text(finding_candidate.get("tool")).lower()
    rule_id = sanitize_text(finding_candidate.get("rule_id"))
    resource = normalize_path(finding_candidate.get("resource"))
    occurrence_file_path = normalize_path(
        finding_raw.get("file_path")
        or finding_raw.get("path")
        or finding_candidate.get("resource")
    )

    raw_line = finding_raw.get("line")
    if raw_line is None or sanitize_text(raw_line) == "":
        raw_line = finding_raw.get("start_line")
    try:
        occurrence_line = int(raw_line)
    except (TypeError, ValueError):
        occurrence_line = 0

    occurrence_hash = sanitize_text(finding_raw.get("hash_code")).lower()
    finding_id = sanitize_text(finding_raw.get("id"))

    requested_by = parse_requested_by(ra)
    approved_by = parse_approved_by(ra)
    decision = parse_decision(ra)
    approved_at = parse_approved_at(ra)
    expires_at = parse_expires_at(ra)

    occurrence_obj: Dict[str, Any] = {
        "file_path": occurrence_file_path,
        "line": occurrence_line,
        "hash_code": occurrence_hash,
    }
    if finding_id.isdigit():
        occurrence_obj["finding_id"] = int(finding_id)

    return {
        "id": stable_exception_id(
            tool,
            rule_id,
            resource,
            occurrence_file_path,
            occurrence_line,
            occurrence_hash,
        )
        if tool and rule_id and resource
        else "",
        "tool": tool,
        "rule_id": rule_id,
        "resource": resource,
        "severity": sanitize_text(finding_candidate.get("severity")).upper(),
        "requested_by": requested_by,
        "approved_by": approved_by,
        "approved_at": to_rfc3339(approved_at) if approved_at else "",
        "expires_at": to_rfc3339(expires_at) if expires_at else "",
        "decision": decision,
        "source": "defectdojo",
        "status": parse_status(ra) or "",
        "scope": _build_ci_scope(),
        "occurrence": occurrence_obj,
    }


def _deduplicate_exceptions(exceptions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_id: Dict[str, Tuple[str, Dict[str, Any]]] = {}

    for item in exceptions:
        identifier = sanitize_text(item.get("id"))
        if not identifier:
            continue
        canonical = json.dumps(item, separators=(",", ":"), sort_keys=True)
        previous = by_id.get(identifier)
        if previous is None or canonical < previous[0]:
            by_id[identifier] = (canonical, item)

    ordered_ids = sorted(by_id.keys())
    return [by_id[item_id][1] for item_id in ordered_ids]


def map_risk_acceptances(
    ctx: FetchContext, raw_ras: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    accepted: List[Dict[str, Any]] = []

    for ra in raw_ras:
        ra_identifier = risk_acceptance_id(ra)

        # Filter: only process Risk Acceptances that are actively accepted
        # in DefectDojo (active=true AND not rejected/expired).
        if not is_active_accepted(ra):
            reason = "inactive_risk_acceptance"
            detail = "DefectDojo RA is not active+accepted (active=False or status!=accepted)"
            drop(ctx, ra_identifier, reason, detail, ra)
            emit_audit_event(ctx, ra, None, "rejected", reason)
            continue

        findings = accepted_findings(ra)

        if not findings:
            reason = "parsing_error"
            detail = "no accepted findings available"
            drop(ctx, ra_identifier, reason, detail, ra)
            emit_audit_event(ctx, ra, None, "rejected", reason)
            continue

        valid_for_ra = 0
        for finding in findings:
            finding_dict = (
                finding
                if isinstance(finding, dict)
                else {"title": sanitize_text(finding)}
            )
            candidate = normalize_finding_candidate(ctx, ra, finding_dict)
            normalized_exception = _draft_exception(ctx, ra, candidate, finding_dict)

            is_valid, reason, detail = validate_normalized_exception(
                ctx, normalized_exception
            )
            if not is_valid:
                reject_reason = reason or "parsing_error"
                drop(
                    ctx,
                    ra_identifier,
                    reject_reason,
                    detail or "validation failed",
                    finding_dict,
                )
                emit_audit_event(
                    ctx, finding_dict, normalized_exception, "rejected", reject_reason
                )
                continue

            accepted.append(normalized_exception)
            valid_for_ra += 1
            emit_audit_event(ctx, finding_dict, normalized_exception, "accepted")

        if valid_for_ra == 0:
            reason = "parsing_error"
            detail = "no valid findings parsed"
            drop(ctx, ra_identifier, reason, detail, ra)

    deduplicated = _deduplicate_exceptions(accepted)

    meta = {
        "source": "defectdojo",
        "total_raw_risk_acceptances": len(raw_ras),
        "total_valid_exceptions": len(deduplicated),
        "total_dropped": len(ctx.dropped),
    }

    return deduplicated, meta
