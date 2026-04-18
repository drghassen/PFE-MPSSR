#!/usr/bin/env python3
"""Normalization layer for DefectDojo risk acceptance findings."""

from __future__ import annotations

from typing import Any, Dict, List

from .fetch_utils import (
    derive_trivy_secret_rule_id,
    derive_rule_id_from_title,
    extract_path_from_text,
    extract_rule_id,
    extract_wildcard_path_from_text,
    find_best_fuzzy_match,
    normalize_path,
    normalize_tool,
    parse_severity_from_text,
    parse_tool_from_text,
    sanitize_text,
)
from .fetch_validation import FetchContext


def risk_acceptance_id(ra: Dict[str, Any]) -> str:
    raw_id = sanitize_text(ra.get("id"))
    return f"RA-{raw_id or 'unknown'}"


def _finding_title(finding: Dict[str, Any]) -> str:
    return sanitize_text(
        finding.get("title")
        or finding.get("name")
        or finding.get("test_title")
        or finding.get("vuln_id_from_tool")
        or finding.get("component_name")
        or finding.get("file_path")
    )


def _finding_texts(ra: Dict[str, Any], finding: Dict[str, Any]) -> List[str]:
    texts: List[str] = []
    for key in [
        "title",
        "name",
        "test_title",
        "vuln_id_from_tool",
        "component_name",
        "file_path",
        "path",
        "description",
        "severity",
        "test_type_name",
        "scanner",
        "tool",
        "finding_title",
    ]:
        text = sanitize_text(finding.get(key))
        if text:
            texts.append(text)

    for key in ["name", "notes", "decision_details"]:
        text = sanitize_text(ra.get(key))
        if text:
            texts.append(text)
    return texts


def _normalize_finding_dict(item: Any) -> Dict[str, Any]:
    if isinstance(item, dict):
        return item
    if isinstance(item, str):
        text = sanitize_text(item)
        return {"title": text, "raw": text}
    if isinstance(item, int):
        return {"id": item, "title": str(item)}
    text = sanitize_text(item)
    return {"title": text, "raw": text}


def accepted_findings(ra: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    details = ra.get("accepted_finding_details", [])
    if isinstance(details, list):
        for item in details:
            if isinstance(item, dict):
                findings.append(item)

    # Prefer enriched finding objects when available. Raw IDs from accepted_findings
    # are not parseable on their own and create false drop noise.
    if findings:
        return findings

    raw_findings = ra.get("accepted_findings", [])
    if isinstance(raw_findings, list):
        for item in raw_findings:
            findings.append(_normalize_finding_dict(item))

    return findings


def _tool_from_finding(ra: Dict[str, Any], finding: Dict[str, Any]) -> str:
    explicit = normalize_tool(finding.get("tool") or finding.get("scanner"))
    if explicit:
        return explicit
    texts = _finding_texts(ra, finding)
    by_text = parse_tool_from_text(*texts)
    if by_text:
        return by_text

    inferred_rule = extract_rule_id(
        finding.get("vuln_id_from_tool"),
        finding.get("title"),
        finding.get("name"),
        finding.get("description"),
        ra.get("name"),
    ).upper()
    if inferred_rule.startswith("CKV"):
        return "checkov"
    if inferred_rule.startswith("CVE-"):
        return "trivy"

    unique_id = sanitize_text(finding.get("unique_id_from_tool"))
    if unique_id.startswith("cloudsentinel-drift"):
        return "cloudsentinel-drift"

    secret_rule = derive_trivy_secret_rule_id(
        finding.get("title"),
        finding.get("description"),
        finding.get("name"),
        ra.get("name"),
    )
    if secret_rule:
        return "gitleaks"

    tags = finding.get("tags", [])
    if isinstance(tags, list):
        normalized_tags = {sanitize_text(tag).lower() for tag in tags}
        if "secret" in normalized_tags or "credential" in normalized_tags:
            return "gitleaks"

    if (
        sanitize_text(finding.get("title")).lower().startswith("secret detected in")
        or "hard coded" in sanitize_text(finding.get("title")).lower()
    ):
        return "gitleaks"

    if "**category:**" in sanitize_text(finding.get("description")).lower():
        return "trivy"
    return ""


def _severity_from_finding(
    ctx: FetchContext, ra: Dict[str, Any], finding: Dict[str, Any]
) -> str:
    texts = _finding_texts(ra, finding)
    return parse_severity_from_text(ctx.severity_enum, finding.get("severity"), *texts)


def _rule_from_finding(ra: Dict[str, Any], finding: Dict[str, Any]) -> str:
    explicit = extract_rule_id(
        finding.get("vuln_id_from_tool"),
        finding.get("title"),
        finding.get("name"),
        finding.get("test_title"),
        finding.get("description"),
        ra.get("name"),
    )
    if explicit:
        return explicit

    trivy_secret_rule = derive_trivy_secret_rule_id(
        finding.get("title"),
        finding.get("description"),
        finding.get("name"),
        ra.get("name"),
    )
    if trivy_secret_rule:
        return trivy_secret_rule

    title = _finding_title(finding) or sanitize_text(ra.get("name"))
    return derive_rule_id_from_title(title)


def _resource_from_finding(ra: Dict[str, Any], finding: Dict[str, Any]) -> str:
    # Priority: component_name (logical resource address used by OPA finding_resource_id)
    # then file_path (fallback for tools that don't expose a logical resource name)
    explicit = normalize_path(
        finding.get("component_name")
        or finding.get("unique_id_from_tool")
        or finding.get("file_path")
        or finding.get("path")
    )
    if explicit:
        return explicit

    path_from_text = extract_path_from_text(*_finding_texts(ra, finding))
    if path_from_text:
        return path_from_text

    wildcard_path = extract_wildcard_path_from_text(*_finding_texts(ra, finding))
    if wildcard_path:
        return wildcard_path

    return "unknown"


def _is_deterministic(candidate: Dict[str, Any]) -> bool:
    return bool(
        candidate.get("tool")
        and candidate.get("rule_id")
        and candidate.get("resource")
        and candidate.get("resource") != "unknown"
        and candidate.get("severity")
    )


def normalize_finding_candidate(
    ctx: FetchContext, ra: Dict[str, Any], finding: Dict[str, Any]
) -> Dict[str, Any]:
    candidate = {
        "title": _finding_title(finding) or sanitize_text(ra.get("name")),
        "tool": _tool_from_finding(ra, finding),
        "rule_id": _rule_from_finding(ra, finding),
        "resource": _resource_from_finding(ra, finding),
        "severity": _severity_from_finding(ctx, ra, finding),
    }

    if _is_deterministic(candidate):
        return candidate

    detail_candidates = [
        item
        for item in accepted_findings(ra)
        if isinstance(item, dict)
        and sanitize_text(item.get("title") or item.get("name"))
    ]
    fuzzy_reference = candidate["title"] or sanitize_text(ra.get("name"))
    best = find_best_fuzzy_match(
        fuzzy_reference, detail_candidates, ctx.fuzzy_threshold
    )
    if not best:
        return candidate

    if not candidate["tool"]:
        candidate["tool"] = _tool_from_finding(ra, best)
    if not candidate["rule_id"]:
        candidate["rule_id"] = _rule_from_finding(ra, best)
    if not candidate["resource"] or candidate["resource"] == "unknown":
        candidate["resource"] = _resource_from_finding(ra, best)
    if not candidate["severity"]:
        candidate["severity"] = _severity_from_finding(ctx, ra, best)

    return candidate
