#!/usr/bin/env python3
"""Validation rules for CloudSentinel DefectDojo exception ingestion."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from logging import Logger
from typing import Any, Dict, List, Optional, Set, Tuple

from .fetch_utils import (
    cf,
    first_non_empty,
    has_wildcard,
    normalize_decision,
    normalize_severity,
    now_utc,
    parse_datetime,
    sanitize_text,
    sanitize_username,
    sha256_hex,
    to_rfc3339,
)


@dataclass
class FetchContext:
    logger: Logger
    dojo_url: str
    dojo_api_key: str
    dojo_engagement_id: str
    repo_root: str
    output_file: str
    dropped_file: str
    audit_log_file: str
    schema_version: str
    severity_enum: Set[str]
    allowed_tools: Set[str]
    allowed_decisions: Set[str]
    enforce_approver_allowlist: bool
    approver_allowlist: Set[str]
    fuzzy_threshold: float
    dropped: List[Dict[str, Any]] = field(default_factory=list)


def stable_exception_id(tool: str, rule_id: str, resource: str) -> str:
    seed = f"{tool}{rule_id}{resource}"
    return sha256_hex(seed)


def parse_requested_by(ra: Dict[str, Any]) -> str:
    return sanitize_username(cf(ra, "requested_by") or ra.get("owner"))


def parse_approved_by(ra: Dict[str, Any]) -> str:
    return sanitize_username(cf(ra, "approved_by") or ra.get("accepted_by"))


def parse_decision(ra: Dict[str, Any]) -> str:
    raw = first_non_empty(
        cf(ra, "decision", "recommendation"),
        ra.get("decision"),
        ra.get("recommendation"),
    )
    return normalize_decision(raw)


def parse_expires_at(ra: Dict[str, Any]) -> Optional[datetime]:
    raw = cf(ra, "expires_at", "expiration_date") or ra.get("expiration_date")
    return parse_datetime(raw, end_of_day=True)


def parse_approved_at(ra: Dict[str, Any]) -> Optional[datetime]:
    raw = (
        cf(ra, "approved_at", "created")
        or ra.get("created")
        or ra.get("accepted_date")
        or ra.get("updated")
    )
    return parse_datetime(raw)


def parse_status(ra: Dict[str, Any]) -> str:
    raw = sanitize_text(cf(ra, "status") or ra.get("status")).lower()
    aliases = {
        "approved": "approved",
        "approve": "approved",
        "accepted": "approved",
        "accept": "approved",
        "a": "approved",
    }
    normalized = aliases.get(raw, raw)
    if normalized:
        return normalized

    # DefectDojo Risk Acceptance objects may omit explicit status while still
    # carrying accepted_by + decision/recommendation.
    accepted_by = sanitize_text(cf(ra, "approved_by") or ra.get("accepted_by"))
    decision = parse_decision(ra)
    if accepted_by and decision:
        return "approved"

    return ""


def is_active_accepted(ra: Dict[str, Any]) -> bool:
    status = parse_status(ra)
    is_active_raw = cf(ra, "is_active") or ra.get("is_active")
    if is_active_raw is None:
        is_active = True
    else:
        is_active = str(is_active_raw).strip().lower() in {"true", "1", "yes", "on"}
    return is_active and status == "approved"


def validate_normalized_exception(ctx: FetchContext, exception_obj: Dict[str, Any]) -> Tuple[bool, Optional[str], Optional[str]]:
    requested_by = sanitize_username(exception_obj.get("requested_by"))
    approved_by = sanitize_username(exception_obj.get("approved_by"))

    if not requested_by or not approved_by:
        return False, "four_eyes_violation", "requested_by and approved_by are mandatory"
    if requested_by == approved_by:
        return False, "four_eyes_violation", "requested_by equals approved_by"
    if ctx.enforce_approver_allowlist and approved_by not in ctx.approver_allowlist:
        return False, "four_eyes_violation", "approved_by is not in configured approver allowlist"

    severity = normalize_severity(exception_obj.get("severity"), ctx.severity_enum)
    if not severity:
        return False, "invalid_severity", "severity must be one of CRITICAL|HIGH|MEDIUM|LOW"

    missing_fields = [
        key
        for key in ["tool", "rule_id", "resource", "approved_at", "expires_at", "decision"]
        if not sanitize_text(exception_obj.get(key))
    ]
    if missing_fields:
        return False, "missing_fields", f"missing required fields: {','.join(missing_fields)}"

    if sanitize_text(exception_obj.get("tool")).lower() not in ctx.allowed_tools:
        return False, "missing_fields", "tool is invalid"

    if sanitize_text(exception_obj.get("decision")).lower() not in ctx.allowed_decisions:
        return False, "missing_fields", "decision is invalid"

    if sanitize_text(exception_obj.get("status")).lower() != "approved":
        return False, "missing_fields", "status must be approved"

    if sanitize_text(exception_obj.get("source")).lower() != "defectdojo":
        return False, "missing_fields", "source must be defectdojo"

    resource = sanitize_text(exception_obj.get("resource"))
    if has_wildcard(resource):
        return False, "parsing_error", "wildcard resources are forbidden"

    approved_at = parse_datetime(exception_obj.get("approved_at"))
    if not approved_at:
        return False, "missing_fields", "approved_at is invalid"

    expires_at = parse_datetime(exception_obj.get("expires_at"), end_of_day=True)
    if not expires_at:
        return False, "missing_fields", "expires_at is invalid"

    if now_utc() >= expires_at:
        return False, "missing_fields", "expires_at is in the past"

    if approved_at > now_utc():
        return False, "missing_fields", "approved_at cannot be in the future"

    return True, None, None


def build_base_exception(
    ctx: FetchContext,
    tool: str,
    rule_id: str,
    resource: str,
    severity: str,
    requested_by: str,
    approved_by: str,
    approved_at: datetime,
    expires_at: datetime,
    decision: str,
) -> Dict[str, Any]:
    cleaned_tool = sanitize_text(tool).lower()
    cleaned_rule = sanitize_text(rule_id)
    cleaned_resource = sanitize_text(resource)

    return {
        "id": stable_exception_id(cleaned_tool, cleaned_rule, cleaned_resource),
        "tool": cleaned_tool,
        "rule_id": cleaned_rule,
        "resource": cleaned_resource,
        "severity": normalize_severity(severity, ctx.severity_enum),
        "requested_by": sanitize_username(requested_by),
        "approved_by": sanitize_username(approved_by),
        "approved_at": to_rfc3339(approved_at),
        "expires_at": to_rfc3339(expires_at),
        "decision": sanitize_text(decision).lower(),
        "source": "defectdojo",
        "status": "approved",
    }
