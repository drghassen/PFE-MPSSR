#!/usr/bin/env python3
"""Utility helpers shared by fetch-exceptions modules."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from difflib import SequenceMatcher
from typing import Any, Dict, Iterable, List, Optional


RULE_ID_PATTERN = re.compile(r"\b(CKV[0-9A-Z_]+|CVE-\d{4}-\d+)\b", re.IGNORECASE)
PATH_PATTERN = re.compile(r"(?:[A-Za-z]:[\\/]|[./~])?[A-Za-z0-9._-]+(?:[\\/][A-Za-z0-9._-]+)+")
WILDCARD_PATH_PATTERN = re.compile(r"[A-Za-z0-9._/-]*[\*\?][A-Za-z0-9._/*?-]*")


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def to_rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_datetime(value: Any, *, end_of_day: bool = False) -> Optional[datetime]:
    raw = sanitize_text(value)
    if not raw:
        return None

    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
        try:
            dt = datetime.strptime(raw, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            if end_of_day:
                dt = dt.replace(hour=23, minute=59, second=59)
            return dt
        except ValueError:
            return None

    normalized = raw.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def ensure_dir(path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)


def save_json(path: str, doc: Dict[str, Any]) -> None:
    ensure_dir(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, sort_keys=True)


def sanitize_text(value: Any) -> str:
    if value is None:
        return ""
    text = str(value)
    text = re.sub(r"[\x00-\x1f\x7f]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def sanitize_username(value: Any) -> str:
    return sanitize_text(value).lower()


def safe_str(value: Any) -> str:
    return sanitize_text(value)


def first_non_empty(*values: Any) -> str:
    for value in values:
        text = sanitize_text(value)
        if text:
            return text
    return ""


def get_custom_fields(ra: Dict[str, Any]) -> Dict[str, Any]:
    custom_fields = ra.get("custom_fields", {})
    return custom_fields if isinstance(custom_fields, dict) else {}


def cf(ra: Dict[str, Any], *keys: str) -> str:
    custom_fields = get_custom_fields(ra)
    for key in keys:
        value = custom_fields.get(key)
        text = sanitize_text(value)
        if text:
            return text
    return ""


def normalize_path(path: Any) -> str:
    raw = sanitize_text(path)
    if not raw:
        return ""
    normalized = raw.replace("\\", "/").replace("/./", "/")
    while "//" in normalized:
        normalized = normalized.replace("//", "/")
    if normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized.strip("/")


def has_wildcard(value: str) -> bool:
    return "*" in value or "?" in value


def slugify(value: Any) -> str:
    text = sanitize_text(value).lower()
    if not text:
        return ""
    slug = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    return slug


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_decision(value: Any) -> str:
    raw = sanitize_text(value).lower()
    if not raw:
        return ""
    aliases = {
        "accept": "accept",
        "accepted": "accept",
        "mitigate": "mitigate",
        "mitigation": "mitigate",
        "fix": "fix",
        "fixed": "fix",
        "remediate": "fix",
        "remediation": "fix",
        "transfer": "transfer",
        "avoid": "avoid",
    }
    return aliases.get(raw, "")


def normalize_tool(value: Any) -> str:
    raw = sanitize_text(value).lower()
    aliases = {
        "checkov": "checkov",
        "checkov scan": "checkov",
        "trivy": "trivy",
        "trivy scan": "trivy",
        "gitleaks": "gitleaks",
        "gitleaks scan": "gitleaks",
    }
    return aliases.get(raw, "")


def parse_tool_from_text(*values: Any) -> str:
    for value in values:
        text = sanitize_text(value)
        if not text:
            continue
        lowered = text.lower()
        if "(checkov scan)" in lowered or "checkov" in lowered:
            return "checkov"
        if "(trivy scan)" in lowered or "trivy" in lowered:
            return "trivy"
        if "(gitleaks scan)" in lowered or "gitleaks" in lowered:
            return "gitleaks"
    return ""


def normalize_severity(value: Any, severity_enum: Iterable[str]) -> str:
    allowed = set(severity_enum)
    raw = sanitize_text(value).upper()
    aliases = {
        "CRITICAL": "CRITICAL",
        "CRIT": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "MODERATE": "MEDIUM",
        "LOW": "LOW",
    }
    normalized = aliases.get(raw, "")
    return normalized if normalized in allowed else ""


def parse_severity_from_text(severity_enum: Iterable[str], *values: Any) -> str:
    for value in values:
        direct = normalize_severity(value, severity_enum)
        if direct:
            return direct

        text = sanitize_text(value)
        if not text:
            continue
        upper_text = text.upper()
        for candidate in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if re.search(rf"\b{candidate}\b", upper_text):
                return candidate
    return ""


def extract_rule_id(*values: Any) -> str:
    for value in values:
        text = sanitize_text(value)
        if not text:
            continue
        match = RULE_ID_PATTERN.search(text)
        if match:
            return match.group(1).upper()
    return ""


def derive_rule_id_from_title(title: Any) -> str:
    normalized = slugify(title)
    if normalized:
        return normalized
    fallback = sanitize_text(title)
    return f"rule-{sha256_hex(fallback)[:12]}" if fallback else ""


def extract_path_from_text(*values: Any) -> str:
    for value in values:
        text = sanitize_text(value)
        if not text:
            continue
        match = PATH_PATTERN.search(text)
        if match:
            candidate = normalize_path(match.group(0))
            if candidate:
                return candidate
    return ""


def extract_wildcard_path_from_text(*values: Any) -> str:
    for value in values:
        text = sanitize_text(value)
        if not text:
            continue
        match = WILDCARD_PATH_PATTERN.search(text)
        if match:
            candidate = normalize_path(match.group(0))
            if candidate:
                return candidate
    return ""


def parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    txt = sanitize_text(value).lower()
    return txt in {"1", "true", "yes", "y", "on"}


def similarity(left: Any, right: Any) -> float:
    a = sanitize_text(left).lower()
    b = sanitize_text(right).lower()
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()


def find_best_fuzzy_match(reference: str, candidates: List[Dict[str, Any]], threshold: float) -> Optional[Dict[str, Any]]:
    best: Optional[Dict[str, Any]] = None
    best_score = 0.0
    best_richness = -1

    def _richness(candidate: Dict[str, Any]) -> int:
        keys = ["severity", "file_path", "path", "component_name", "tool", "scanner", "vuln_id_from_tool"]
        return sum(1 for key in keys if sanitize_text(candidate.get(key)))

    for candidate in candidates:
        title = sanitize_text(candidate.get("title"))
        score = similarity(reference, title)
        richness = _richness(candidate)
        if score > best_score or (score == best_score and richness > best_richness):
            best_score = score
            best = candidate
            best_richness = richness

    if best and best_score >= threshold:
        return best
    return None
