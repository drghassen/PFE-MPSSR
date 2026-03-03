#!/usr/bin/env python3
"""Utility helpers shared by fetch-exceptions modules."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def to_rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_datetime(value: str) -> Optional[datetime]:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()

    # DefectDojo often returns date-only for expiration_date.
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
        try:
            return datetime.strptime(raw, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    normalized = raw.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def ensure_dir(path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)


def save_json(path: str, doc: Dict[str, Any]) -> None:
    ensure_dir(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)


def valid_email(value: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", str(value).strip().lower()))


def normalize_path(path: str) -> str:
    if not path:
        return ""
    p = str(path).replace("\\", "/").replace("/./", "/")
    while "//" in p:
        p = p.replace("//", "/")
    if p.startswith("./"):
        p = p[2:]
    return p.strip("/")


def normalize_severity(value: str, severity_enum: Iterable[str]) -> str:
    raw = (value or "").strip().upper()
    aliases = {
        "CRIT": "CRITICAL",
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "MODERATE": "MEDIUM",
        "LOW": "LOW",
        "INFO": "INFO",
        "INFORMATIONAL": "INFO",
        "UNKNOWN": "INFO",
    }
    normalized = aliases.get(raw, "")
    return normalized if normalized in set(severity_enum) else "MEDIUM"


def normalize_scope(scope_type: str, allowed_scope_types: Iterable[str]) -> str:
    scope = (scope_type or "repo").strip().lower()
    allowed = set(allowed_scope_types)
    return scope if scope in allowed else "repo"


def normalize_role(role: str) -> str:
    return (role or "").strip().upper()


def role_rank(role: str, role_ranks: Dict[str, int]) -> int:
    return role_ranks.get(normalize_role(role), 0)


def safe_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def first_non_empty(*values: Any) -> str:
    for value in values:
        text = safe_str(value)
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
        if value is None:
            continue
        text = safe_str(value)
        if text:
            return text
    return ""


def parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    txt = safe_str(value).lower()
    return txt in {"1", "true", "yes", "y", "on"}
