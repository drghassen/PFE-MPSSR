#!/usr/bin/env python3
# ==============================================================================
# CloudSentinel Risk Acceptance Fetcher (DefectDojo Compatibility Engine)
# Backward-compatible wrapper around modular implementation.
# ==============================================================================

from __future__ import annotations

import pathlib
import sys
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from fetch_exceptions.fetch_defectdojo import fetch_risk_acceptances as _fetch_risk_acceptances
from fetch_exceptions.fetch_mapping import (
    drop as _drop,
    emit_audit_event as _emit_audit_event,
    json_payload as _json_payload,
    map_risk_acceptances as _map_risk_acceptances,
    save_outputs as _save_outputs,
)
from fetch_exceptions.fetch_normalization import accepted_findings, normalize_finding_candidate
from fetch_exceptions.fetch_utils import (
    cf,
    ensure_dir,
    first_non_empty,
    get_custom_fields,
    normalize_path,
    normalize_severity as _normalize_severity,
    now_utc,
    parse_bool,
    parse_datetime,
    safe_str,
    sanitize_text,
    sanitize_username,
    save_json,
    to_rfc3339,
)
from fetch_exceptions.fetch_validation import (
    parse_approved_at,
    parse_approved_by,
    parse_decision,
    parse_expires_at,
    parse_requested_by,
    parse_status,
    stable_exception_id,
    validate_normalized_exception,
    is_active_accepted,
)
from fetch_exceptions.main import build_context, execute

CTX = build_context()

logger = CTX.logger
DOJO_URL = CTX.dojo_url
DOJO_API_KEY = CTX.dojo_api_key
REPO_ROOT = CTX.repo_root
OUTPUT_FILE = CTX.output_file
DROPPED_FILE = CTX.dropped_file
AUDIT_LOG_FILE = CTX.audit_log_file
SEVERITY_ENUM = CTX.severity_enum
DROPPED = CTX.dropped


def normalize_severity(value: str) -> str:
    return _normalize_severity(value, SEVERITY_ENUM)


def emit_audit_event(input_payload: Any, output_payload: Optional[Dict[str, Any]], status: str, reason: Optional[str] = None) -> None:
    _emit_audit_event(CTX, input_payload, output_payload, status, reason)


def json_payload(exceptions: List[Dict[str, Any]], meta: Dict[str, Any]) -> Dict[str, Any]:
    return _json_payload(CTX, exceptions, meta)


def drop(ra_identifier: str, reason: str, detail: str, input_payload: Any) -> None:
    _drop(CTX, ra_identifier, reason, detail, input_payload)


def save_outputs(payload: Dict[str, Any]) -> None:
    _save_outputs(CTX, payload)


def fetch_risk_acceptances() -> List[Dict[str, Any]]:
    return _fetch_risk_acceptances(DOJO_URL, DOJO_API_KEY, logger)


def _draft_exception(ra: Dict[str, Any], finding_candidate: Dict[str, Any]) -> Dict[str, Any]:
    tool = sanitize_text(finding_candidate.get("tool")).lower()
    rule_id = sanitize_text(finding_candidate.get("rule_id"))
    resource = sanitize_text(finding_candidate.get("resource"))

    approved_at = parse_approved_at(ra)
    expires_at = parse_expires_at(ra)

    return {
        "id": stable_exception_id(tool, rule_id, resource) if tool and rule_id and resource else "",
        "tool": tool,
        "rule_id": rule_id,
        "resource": resource,
        "severity": sanitize_text(finding_candidate.get("severity")).upper(),
        "requested_by": parse_requested_by(ra),
        "approved_by": parse_approved_by(ra),
        "approved_at": to_rfc3339(approved_at) if approved_at else "",
        "expires_at": to_rfc3339(expires_at) if expires_at else "",
        "decision": parse_decision(ra),
        "source": "defectdojo",
        "status": parse_status(ra) or "",
    }


def extract_v2_exception(ra: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    findings = accepted_findings(ra)
    if not findings:
        return None, "no accepted findings available"

    def _finding_richness(item: Any) -> int:
        if not isinstance(item, dict):
            return 0
        keys = ["title", "name", "description", "severity", "file_path", "path", "component_name"]
        return sum(1 for key in keys if sanitize_text(item.get(key)))

    best_finding = max(
        [item if isinstance(item, dict) else {"title": sanitize_text(item)} for item in findings],
        key=_finding_richness,
    )
    candidate = normalize_finding_candidate(CTX, ra, best_finding)
    normalized = _draft_exception(ra, candidate)

    is_valid, reason, detail = validate_normalized_exception(CTX, normalized)
    if not is_valid:
        return None, f"{reason}: {detail}"

    return normalized, None


def map_risk_acceptances(raw_ras: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    return _map_risk_acceptances(CTX, raw_ras)


def main() -> None:
    execute(CTX)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        logger.exception(f"Unhandled error in fetch-exceptions: {exc}")
        raise SystemExit(2) from exc
