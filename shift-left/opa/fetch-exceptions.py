#!/usr/bin/env python3
# ==============================================================================
# CloudSentinel Risk Acceptance Fetcher (Enterprise Engine)
# Compatibility wrapper for legacy entrypoint path.
# Modular implementation is now located under shift-left/opa/fetch_exceptions/.
# ==============================================================================

from __future__ import annotations

import pathlib
import sys
from typing import Any, Dict, List, Optional, Tuple

# Ensure `shift-left/opa` is importable even when this file is loaded dynamically
# by tests via importlib.util.spec_from_file_location.
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
from fetch_exceptions.fetch_utils import (
    cf,
    ensure_dir,
    first_non_empty,
    get_custom_fields,
    normalize_path,
    normalize_role,
    normalize_scope as _normalize_scope,
    normalize_severity as _normalize_severity,
    now_utc,
    parse_bool,
    parse_datetime,
    role_rank as _role_rank,
    safe_str,
    save_json,
    to_rfc3339,
    valid_email,
)
from fetch_exceptions.fetch_validation import (
    extract_v2_exception as _extract_v2_exception,
    generate_exception_uuid as _generate_exception_uuid,
    guess_scanner,
    is_active_accepted,
    legacy_window_open as _legacy_window_open,
    parse_approved_at,
    parse_created_at,
    parse_expires_at,
    resolve_break_glass,
)
from fetch_exceptions.main import build_context, emit_empty as _emit_empty, execute

CTX = build_context()

# Preserve legacy module-level symbols for backward compatibility.
logger = CTX.logger
DOJO_URL = CTX.dojo_url
DOJO_API_KEY = CTX.dojo_api_key
REPO_ROOT = CTX.repo_root
CI_PROJECT_NAME = CTX.ci_project_name
CI_PROJECT_PATH = CTX.ci_project_path
CI_COMMIT_REF_NAME = CTX.ci_commit_ref_name
CI_COMMIT_SHA = CTX.ci_commit_sha
OUTPUT_FILE = CTX.output_file
DROPPED_FILE = CTX.dropped_file
AUDIT_LOG_FILE = CTX.audit_log_file
LEGACY_COMPAT = CTX.legacy_compat
LEGACY_SUNSET_DATE = CTX.legacy_sunset_date
ALLOWED_APPROVER_ROLES = CTX.allowed_approver_roles
GLOBAL_SCOPE_ALLOWED_ROLES = CTX.global_scope_allowed_roles
BREAK_GLASS_MAX_DAYS = CTX.break_glass_max_days
ALLOWED_SCOPE_TYPES = CTX.allowed_scope_types
SEVERITY_ENUM = CTX.severity_enum
ROLE_RANK = CTX.role_ranks
SCHEMA_VERSION = CTX.schema_version
DROPPED = CTX.dropped


def normalize_severity(value: str) -> str:
    return _normalize_severity(value, SEVERITY_ENUM)


def normalize_scope(scope_type: str) -> str:
    return _normalize_scope(scope_type, ALLOWED_SCOPE_TYPES)


def role_rank(role: str) -> int:
    return _role_rank(role, ROLE_RANK)


def emit_audit_event(event_type: str, payload: Dict[str, Any]) -> None:
    _emit_audit_event(CTX, event_type, payload)


def generate_exception_uuid(ra: Dict[str, Any]) -> str:
    return _generate_exception_uuid(CTX, ra)


def json_payload(exceptions: List[Dict[str, Any]], meta: Dict[str, Any]) -> Dict[str, Any]:
    return _json_payload(CTX, exceptions, meta)


def drop(ra: Dict[str, Any], reason: str) -> None:
    _drop(CTX, ra, reason)


def save_outputs(payload: Dict[str, Any]) -> None:
    _save_outputs(CTX, payload)


def emit_empty(reason: str) -> None:
    _emit_empty(CTX, reason)


def fetch_risk_acceptances() -> List[Dict[str, Any]]:
    return _fetch_risk_acceptances(DOJO_URL, DOJO_API_KEY, logger)


def legacy_window_open() -> bool:
    return _legacy_window_open(CTX)


def extract_v2_exception(ra: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    return _extract_v2_exception(CTX, ra)


def map_risk_acceptances(raw_ras: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    return _map_risk_acceptances(CTX, raw_ras)


def main() -> None:
    execute(CTX)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        logger.exception(f"Unhandled error in fetch-exceptions: {exc}")
        emit_empty(f"Unhandled exception: {exc}")

