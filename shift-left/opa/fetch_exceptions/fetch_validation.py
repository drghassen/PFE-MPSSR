#!/usr/bin/env python3
"""Validation and mapping rules for enterprise exceptions."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from logging import Logger
from typing import Any, Dict, List, Optional, Set, Tuple

from .fetch_utils import (
    cf,
    first_non_empty,
    normalize_path,
    normalize_role,
    normalize_scope,
    normalize_severity,
    parse_bool,
    parse_datetime,
    role_rank,
    safe_str,
    to_rfc3339,
    valid_email,
    now_utc,
)


@dataclass
class FetchContext:
    logger: Logger
    dojo_url: str
    dojo_api_key: str
    repo_root: str
    ci_project_name: str
    ci_project_path: str
    ci_commit_ref_name: str
    ci_commit_sha: str
    output_file: str
    dropped_file: str
    audit_log_file: str
    legacy_compat: bool
    legacy_sunset_date: str
    allowed_approver_roles: Set[str]
    global_scope_allowed_roles: Set[str]
    break_glass_max_days: int
    allowed_scope_types: Set[str]
    severity_enum: Set[str]
    role_ranks: Dict[str, int]
    schema_version: str
    dropped: List[Dict[str, Any]] = field(default_factory=list)


def guess_scanner(rule_id: str, raw_scanner: str) -> str:
    candidate = safe_str(raw_scanner).lower()
    if candidate in {"gitleaks", "checkov", "trivy"}:
        return candidate
    rid = safe_str(rule_id).upper()
    if rid.startswith("CKV"):
        return "checkov"
    if rid.startswith("CVE-"):
        return "trivy"
    return "gitleaks"


def extract_rule_id_hint(*values: Any) -> str:
    pattern = re.compile(r"\b(CKV[0-9A-Z_]+|CVE-\d{4}-\d+)\b", re.IGNORECASE)
    for value in values:
        text = safe_str(value)
        if not text:
            continue
        match = pattern.search(text)
        if match:
            return match.group(1).upper()
    return ""


def looks_like_fingerprint(value: Any) -> bool:
    text = safe_str(value)
    if len(text) < 16:
        return False
    if re.search(r"\s", text):
        return False
    return True


def principal_email(value: Any) -> str:
    if isinstance(value, dict):
        return first_non_empty(value.get("email"), value.get("username"), value.get("user"))
    return safe_str(value)


def choose_email(default_email: str, *candidates: Any) -> str:
    for candidate in candidates:
        email = principal_email(candidate)
        if email and valid_email(email):
            return email
    return default_email


def accepted_finding_details(ra: Dict[str, Any]) -> List[Dict[str, Any]]:
    details = ra.get("accepted_finding_details", [])
    if not isinstance(details, list):
        return []
    return [x for x in details if isinstance(x, dict)]


def accepted_finding_resource_id(ra: Dict[str, Any]) -> str:
    for finding in accepted_finding_details(ra):
        resource = first_non_empty(
            finding.get("component_name"),
            finding.get("unique_id_from_tool"),
            finding.get("file_path"),
            finding.get("vuln_id_from_tool"),
        )
        if resource:
            return resource
    return ""


def accepted_finding_severity(ra: Dict[str, Any]) -> str:
    for finding in accepted_finding_details(ra):
        sev = safe_str(finding.get("severity"))
        if sev:
            return sev
    return ""


def looks_like_proof_path(value: Any) -> bool:
    text = safe_str(value).lower()
    if not text:
        return False
    return "no proof has been supplied" in text or text.startswith("http://") or text.startswith("https://")


def generate_exception_uuid(ctx: FetchContext, ra: Dict[str, Any]) -> str:
    preferred = first_non_empty(
        cf(ra, "exception_id", "uuid"),
        safe_str(ra.get("uuid")),
    )
    if preferred:
        try:
            return str(uuid.UUID(preferred))
        except ValueError:
            pass

    seed = f"{ctx.dojo_url}|RA|{safe_str(ra.get('id'))}|{safe_str(ra.get('name'))}"
    return str(uuid.uuid5(uuid.NAMESPACE_URL, seed))


def parse_expires_at(ra: Dict[str, Any]) -> Optional[datetime]:
    return parse_datetime(
        first_non_empty(
            cf(ra, "expires_at", "expiration_date"),
            ra.get("expiration_date"),
            ra.get("expires_at"),
        )
    )


def parse_created_at(ra: Dict[str, Any]) -> Optional[datetime]:
    return parse_datetime(
        first_non_empty(
            cf(ra, "created_at", "request_date"),
            ra.get("created"),
            ra.get("request_date"),
        )
    )


def parse_approved_at(ra: Dict[str, Any]) -> Optional[datetime]:
    return parse_datetime(
        first_non_empty(
            cf(ra, "approved_at", "acceptance_date"),
            ra.get("accepted_date"),
            ra.get("updated"),
        )
    )


def resolve_break_glass(ra: Dict[str, Any]) -> bool:
    return parse_bool(first_non_empty(cf(ra, "break_glass"), ra.get("break_glass")))


def legacy_window_open(ctx: FetchContext) -> bool:
    sunset = parse_datetime(ctx.legacy_sunset_date)
    if not sunset:
        return False
    return now_utc() <= sunset


def is_active_accepted(ra: Dict[str, Any]) -> bool:
    if not ra.get("is_active", True):
        return False
    status = safe_str(ra.get("status")).lower()
    if not status:
        return True
    # Keep accepted-like statuses only.
    return status in {"accepted", "approve", "approved", "active"}


def extract_v2_exception(ctx: FetchContext, ra: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    ra_id = safe_str(ra.get("id")) or "unknown"

    rule_id = first_non_empty(cf(ra, "rule_id", "rule", "check_id"), ra.get("rule_id"), ra.get("name"))
    inferred_rule_id = extract_rule_id_hint(
        cf(ra, "rule_id", "rule", "check_id"),
        ra.get("rule_id"),
        ra.get("name"),
        ra.get("title"),
        ra.get("description"),
        ra.get("recommendation_details"),
    )
    if inferred_rule_id:
        rule_id = inferred_rule_id
    scanner = guess_scanner(rule_id, first_non_empty(cf(ra, "scanner", "tool"), ra.get("tool")))

    requested_by = choose_email(
        "dev-system@example.com",
        cf(ra, "requested_by", "owner_email"),
        ra.get("requested_by"),
        ra.get("owner_email"),
        ra.get("owner"),
    )
    approved_by = choose_email(
        "appsec-system@example.com",
        cf(ra, "approved_by", "approver_email"),
        ra.get("approved_by"),
        ra.get("approver"),
        ra.get("accepted_by"),
    )
    approved_by_role = normalize_role(
        first_non_empty(
            cf(ra, "approved_by_role", "approver_role"),
            ra.get("approved_by_role"),
            "APPSEC_L1",
        )
    )

    scope_type = normalize_scope(
        first_non_empty(cf(ra, "scope_type"), ra.get("scope_type"), "repo"),
        ctx.allowed_scope_types,
    )
    branch_scope = first_non_empty(cf(ra, "branch_scope"), ra.get("branch_scope"), ctx.ci_commit_ref_name or "*")
    repo = first_non_empty(cf(ra, "repo", "repository"), ra.get("repository"), ctx.ci_project_path)

    resource_id = first_non_empty(
        cf(ra, "resource_id", "resource_name"),
        ra.get("resource_name"),
        accepted_finding_resource_id(ra),
    )
    if not resource_id:
        path_hint = safe_str(ra.get("path"))
        if path_hint and not looks_like_proof_path(path_hint):
            resource_id = path_hint
    resource_id = normalize_path(resource_id)

    fingerprint = first_non_empty(cf(ra, "fingerprint", "resource_hash", "finding_hash"), ra.get("fingerprint"))
    fallback_fingerprint = first_non_empty(
        ra.get("resource_hash"),
        ra.get("finding_hash"),
        ra.get("recommendation_details"),
    )
    if not fingerprint and looks_like_fingerprint(fallback_fingerprint):
        fingerprint = safe_str(fallback_fingerprint)

    resource_hash = first_non_empty(
        cf(ra, "resource_hash", "fingerprint"),
        ra.get("resource_hash"),
        fingerprint,
    )
    if not resource_hash and looks_like_fingerprint(ra.get("recommendation_details")):
        resource_hash = safe_str(ra.get("recommendation_details"))

    severity = normalize_severity(
        first_non_empty(
            cf(ra, "severity", "max_severity"),
            ra.get("severity"),
            accepted_finding_severity(ra),
            "HIGH",
        ),
        ctx.severity_enum,
    )
    break_glass = resolve_break_glass(ra)
    incident_id = first_non_empty(cf(ra, "incident_id"), ra.get("incident_id"))
    justification = first_non_empty(
        cf(ra, "justification", "reason"),
        ra.get("decision_details"),
        ra.get("reason"),
        ra.get("description"),
        ra.get("recommendation"),
    )

    commit_sha = first_non_empty(
        cf(ra, "commit_sha", "commit_hash"),
        ra.get("commit_hash"),
        ctx.ci_commit_sha,
    )
    commit_sha = commit_sha[:40]

    created_at = parse_created_at(ra)
    expires_at = parse_expires_at(ra)
    approved_at = parse_approved_at(ra)

    if not created_at:
        return None, "missing or invalid created_at/request_date"
    if not expires_at:
        return None, "missing or invalid expires_at/expiration_date"
    if expires_at <= now_utc():
        return None, "exception already expired"

    if not justification:
        return None, "missing required justification"
    if not rule_id:
        return None, "missing required rule_id"
    if not resource_id:
        return None, "missing required resource_id"
    if not (fingerprint or resource_hash):
        return None, "missing fingerprint/resource_hash (required for strict matching)"

    if not valid_email(requested_by):
        return None, f"invalid requested_by email: {requested_by}"
    if not valid_email(approved_by):
        return None, f"invalid approved_by email: {approved_by}"
    if requested_by.strip().lower() == approved_by.strip().lower():
        return None, "separation of duties violated: requested_by equals approved_by"

    if approved_by_role not in ctx.allowed_approver_roles:
        return None, f"approved_by_role not allowed: {approved_by_role}"

    if scope_type == "global" and approved_by_role not in ctx.global_scope_allowed_roles:
        return None, "global scope requires elevated AppSec role"

    if break_glass:
        ttl_days = (expires_at - now_utc()).total_seconds() / 86400.0
        if not incident_id:
            return None, "break-glass exception requires incident_id"
        if ttl_days > ctx.break_glass_max_days:
            return None, f"break-glass TTL exceeds {ctx.break_glass_max_days} days"
        if role_rank(approved_by_role, ctx.role_ranks) < role_rank("APPSEC_L3", ctx.role_ranks):
            return None, "break-glass requires approver role APPSEC_L3 or higher"

    ex = {
        "exception_id": generate_exception_uuid(ctx, ra),
        "schema_version": ctx.schema_version,
        "enabled": True,
        "source_system": "defectdojo",
        "source_id": f"RA-{ra_id}",
        "scanner": scanner,
        "rule_id": rule_id,
        "resource_id": resource_id,
        "resource_hash": resource_hash or fingerprint,
        "fingerprint": fingerprint or resource_hash,
        "repo": repo,
        "branch_scope": branch_scope,
        "scope_type": scope_type,
        "severity": severity,
        "break_glass": break_glass,
        "incident_id": incident_id,
        "approved_by_role": approved_by_role,
        "requested_by": requested_by,
        "approved_by": approved_by,
        "justification": justification,
        "created_at": to_rfc3339(created_at),
        "approved_at": to_rfc3339(approved_at) if approved_at else None,
        "expires_at": to_rfc3339(expires_at),
        "commit_sha": commit_sha,
        "accepted_finding_ids": ra.get("accepted_findings", []),
    }

    # Legacy bridge fields consumed by older policy versions.
    ex.update(
        {
            "id": ex["exception_id"],
            "tool": scanner,
            "resource_path": resource_id,
            "resource_name": resource_id,
            "environments": ["dev", "test", "staging", "prod"],
            "max_severity": severity,
            "reason": justification,
            "ticket": f"DOJO-RA-{ra_id}",
            "commit_hash": commit_sha[:8] if commit_sha else "unknown",
            "request_date": ex["created_at"],
        }
    )

    return ex, None
