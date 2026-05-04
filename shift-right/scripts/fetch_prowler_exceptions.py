#!/usr/bin/env python3
"""
fetch_prowler_exceptions.py — Fetch Prowler exceptions from DefectDojo Risk Acceptances.

Builds .cloudsentinel/prowler_exceptions.json consumed by OPA package
cloudsentinel.shiftright.prowler.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any

try:
    import requests
except ImportError:
    print(
        "ERROR: 'requests' library not installed. Run: pip install requests",
        file=sys.stderr,
    )
    sys.exit(1)


class _StructuredLogger:
    """
    Stdlib-only fallback that emits one JSON line per event to stderr.
    API mirrors structlog's bound-logger so the same call pattern works
    whether or not structlog is installed.
    """

    def __init__(self, name: str) -> None:
        self._name = name

    def _emit(self, level: str, event: str, **fields: Any) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        record: dict[str, Any] = {
            "timestamp": ts,
            "logger": self._name,
            "level": level,
            "event": event,
        }
        if fields:
            record["details"] = fields
        try:
            line = json.dumps(record, default=str)
        except Exception:
            # Fields contained an unserializable value (e.g. circular reference).
            # Emit a safe envelope so the logger never crashes the caller.
            line = json.dumps({
                "timestamp": ts,
                "logger": self._name,
                "level": level,
                "event": event,
                "details": {"_serialization_error": True},
            })
        print(line, file=sys.stderr, flush=True)

    def info(self, event: str, **fields: Any) -> None:
        self._emit("INFO", event, **fields)

    def warning(self, event: str, **fields: Any) -> None:
        self._emit("WARNING", event, **fields)

    def error(self, event: str, **fields: Any) -> None:
        self._emit("ERROR", event, **fields)

    def debug(self, event: str, **fields: Any) -> None:
        self._emit("DEBUG", event, **fields)


try:
    import structlog

    logger = structlog.get_logger(__name__)
except ImportError:
    logger = _StructuredLogger(__name__)  # type: ignore[assignment]


PROWLER_EXCEPTION_SCHEMA_VERSION = "2.0.0"
_DESCRIPTION_FIELD_RE = re.compile(
    r"(?im)^\s*-\s*([A-Za-z][A-Za-z _-]+?)\s*:\s*(.+?)\s*$"
)


# ---------------------------------------------------------------------------
# Validation helpers  (mirrors shift-left fetch_validation.py)
# ---------------------------------------------------------------------------


def _has_wildcard(text: str) -> bool:
    return "*" in text or "?" in text


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_datetime_strict(value: Any) -> "datetime | None":
    """Parse RFC3339 / ISO-8601 datetime. Returns None on any failure."""
    if not value:
        return None
    text = str(value).strip()
    if not text or text == "None":
        return None
    if len(text) == 10:
        text = f"{text}T00:00:00+00:00"
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, AttributeError):
        return None


def _stable_exception_id(finding: dict[str, Any]) -> str:
    key = (
        f"{finding.get('id', '')}:"
        f"{finding.get('title', finding.get('name', ''))}:"
        f"{finding.get('created', '')}"
    )
    return hashlib.sha256(key.encode()).hexdigest()


def _clean_text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _parse_description_fields(description: Any) -> dict[str, str]:
    text = _clean_text(description)
    if not text:
        return {}

    out: dict[str, str] = {}
    for match in _DESCRIPTION_FIELD_RE.finditer(text):
        key = _clean_text(match.group(1)).lower().replace(" ", "_")
        val = _clean_text(match.group(2))
        if key and val:
            out[key] = val
    return out


def _build_scope(environment: str) -> dict[str, Any]:
    repo = _clean_text(os.getenv("CI_PROJECT_PATH", ""))
    branch = _clean_text(os.getenv("CI_COMMIT_REF_NAME", ""))
    return {
        "repos": [repo] if repo else [],
        "branches": [branch] if branch else [],
        "environments": [_clean_text(environment)] if _clean_text(environment) else [],
    }


def _normalize_dojo_base_url(base_url: str) -> str:
    normalized = _clean_text(base_url).rstrip("/")
    if normalized.endswith("/api/v2"):
        normalized = normalized[: -len("/api/v2")]
    return normalized


def _extract_engagement_id(finding: dict[str, Any]) -> str:
    explicit = _clean_text(finding.get("engagement_id"))
    if explicit:
        return explicit

    raw = finding.get("engagement")
    if isinstance(raw, dict):
        return _clean_text(raw.get("id"))
    if raw is not None:
        return _clean_text(raw)

    test_obj = finding.get("test")
    if isinstance(test_obj, dict):
        nested = test_obj.get("engagement")
        if isinstance(nested, dict):
            return _clean_text(nested.get("id"))
        return _clean_text(nested)

    return ""


def _matches_engagement(finding: dict[str, Any], engagement: str) -> bool:
    if not engagement:
        return True
    return _extract_engagement_id(finding) == _clean_text(engagement)


def _extract_check_id(
    finding: dict[str, Any], description_fields: dict[str, str]
) -> str:
    explicit = _clean_text(finding.get("check_id"))
    if explicit:
        return explicit

    vuln_id = _clean_text(finding.get("vuln_id_from_tool"))
    if vuln_id.startswith("prowler_check:"):
        return _clean_text(vuln_id.split(":", 1)[1])

    unique_id = _clean_text(finding.get("unique_id_from_tool"))
    if unique_id.startswith("cloudsentinel-prowler:"):
        parts = unique_id.split(":", 2)
        if len(parts) == 3:
            return _clean_text(parts[1])

    return _clean_text(description_fields.get("check_id"))


def _extract_resource_id(
    finding: dict[str, Any], description_fields: dict[str, str]
) -> str:
    resource_obj = finding.get("resource")
    if isinstance(resource_obj, dict):
        for key in ("id", "uid", "address"):
            nested = _clean_text(resource_obj.get(key))
            if nested:
                return nested

    component_name = _clean_text(finding.get("component_name"))
    if component_name:
        return component_name

    unique_id = _clean_text(finding.get("unique_id_from_tool"))
    if unique_id.startswith("cloudsentinel-prowler:"):
        parts = unique_id.split(":", 2)
        if len(parts) == 3:
            return _clean_text(parts[2])

    return _clean_text(description_fields.get("resource_id"))


def _extract_resource_type(
    finding: dict[str, Any], description_fields: dict[str, str]
) -> str:
    resource_obj = finding.get("resource")
    if isinstance(resource_obj, dict):
        for key in ("type", "resource_type"):
            nested = _clean_text(resource_obj.get(key))
            if nested:
                return nested

    explicit_type = _clean_text(finding.get("resource_type"))
    if explicit_type:
        return explicit_type

    return _clean_text(description_fields.get("resource_type"))


def _parse_ra_to_exception(
    finding: dict[str, Any], scope: dict[str, Any]
) -> dict[str, Any] | None:
    if not finding.get("risk_accepted"):
        return None

    description_fields = _parse_description_fields(finding.get("description"))
    check_id = _extract_check_id(finding, description_fields)
    resource_id = _extract_resource_id(finding, description_fields)
    resource_type = _extract_resource_type(finding, description_fields)

    if not check_id or not resource_id or not resource_type:
        logger.warning(
            "prowler_exception_rejected_missing_context",
            finding_id=finding.get("id"),
            check_id=check_id,
            resource_id=resource_id,
            resource_type=resource_type,
        )
        return None

    accepted_risks = finding.get("accepted_risks", [])
    if not isinstance(accepted_risks, list) or len(accepted_risks) == 0:
        return None

    ra = accepted_risks[0]

    owner_dict = ra.get("owner")
    if isinstance(owner_dict, dict):
        requested_by = str(owner_dict.get("username", "unknown"))
        requested_by_details = {"id": owner_dict.get("id"), "username": requested_by}
    else:
        requested_by = str(owner_dict) if owner_dict else "unknown"
        requested_by_details = {
            "id": int(owner_dict) if str(owner_dict).isdigit() else None,
            "username": requested_by,
        }

    approved_by = str(
        ra.get("accepted_by", {}).get("username", "unknown")
        if isinstance(ra.get("accepted_by"), dict)
        else ra.get("accepted_by", "unknown")
    )

    approved_at = str(ra.get("created", ""))
    expires_at = str(ra.get("expiration_date", ""))

    if not (approved_at and requested_by and approved_by):
        return None

    if len(approved_at) == 10:
        approved_at = f"{approved_at}T00:00:00Z"
    if expires_at and len(expires_at) == 10:
        expires_at = f"{expires_at}T23:59:59Z"

    return {
        "id": _stable_exception_id(finding),
        "source": "defectdojo",
        "status": "approved",
        "check_id": check_id,
        "resource_id": resource_id,
        "resource_type": resource_type,
        "requested_by": requested_by,
        "requested_by_details": requested_by_details,
        "approved_by": approved_by,
        "approved_at": approved_at,
        "expires_at": expires_at or None,
        "environments": scope.get("environments", []),
        "repos": scope.get("repos", []),
        "branches": scope.get("branches", []),
        "defectdojo_ra_id": ra.get("id"),
    }


# ---------------------------------------------------------------------------
# Post-parse validation  (mirrors shift-left validate_normalized_exception)
# ---------------------------------------------------------------------------


def _validate_prowler_exception(
    ex: "dict[str, Any]",
    approver_allowlist: "set[str] | None" = None,
    enforce_approver_allowlist: bool = False,
) -> "tuple[bool, str, str]":
    """
    Validate a normalised prowler exception against 11+ governance criteria.
    Returns (is_valid, reason_code, detail_message).
    Mirrors shift-left validate_normalized_exception() from fetch_validation.py.
    """
    requested_by = _clean_text(ex.get("requested_by"))
    approved_by = _clean_text(ex.get("approved_by"))

    if not requested_by or not approved_by:
        return False, "four_eyes_violation", "requested_by and approved_by are mandatory"
    if requested_by == approved_by:
        return False, "four_eyes_violation", "requested_by equals approved_by"
    if enforce_approver_allowlist and approver_allowlist:
        if approved_by not in approver_allowlist:
            return False, "four_eyes_violation", "approved_by is not in approver allowlist"

    if _clean_text(ex.get("source")) != "defectdojo":
        return False, "invalid_source", "source must be defectdojo"

    if _clean_text(ex.get("status")) != "approved":
        return False, "invalid_status", "status must be approved"

    check_id = _clean_text(ex.get("check_id"))
    if not check_id:
        return False, "missing_fields", "check_id is required"
    if _has_wildcard(check_id):
        return False, "wildcard_forbidden", "wildcards in check_id are forbidden"

    resource_id = _clean_text(ex.get("resource_id"))
    if not resource_id:
        return False, "missing_fields", "resource_id is required"
    if _has_wildcard(resource_id):
        return False, "wildcard_forbidden", "wildcards in resource_id are forbidden"

    resource_type = _clean_text(ex.get("resource_type"))
    if not resource_type:
        return False, "missing_fields", "resource_type is required"
    if _has_wildcard(resource_type):
        return False, "wildcard_forbidden", "wildcards in resource_type are forbidden"

    approved_at_str = _clean_text(ex.get("approved_at"))
    if not approved_at_str:
        return False, "missing_fields", "approved_at is required"
    approved_at = _parse_datetime_strict(approved_at_str)
    if not approved_at:
        return False, "invalid_timestamp", "approved_at is not a valid RFC3339 datetime"
    if approved_at > _now_utc():
        return False, "invalid_timestamp", "approved_at cannot be in the future"

    expires_at_raw = ex.get("expires_at")
    if not expires_at_raw:
        return False, "missing_fields", "expires_at is required for all shift-right exceptions"
    expires_at_str = _clean_text(expires_at_raw)
    if not expires_at_str:
        return False, "missing_fields", "expires_at must not be empty"
    expires_at = _parse_datetime_strict(expires_at_str)
    if not expires_at:
        return False, "invalid_timestamp", "expires_at is not a valid RFC3339 datetime"
    if _now_utc() >= expires_at:
        return False, "expired", "exception has already expired"
    if approved_at >= expires_at:
        return False, "invalid_timestamp", "approved_at must be strictly before expires_at"

    environments = ex.get("environments", [])
    if not isinstance(environments, list) or len(environments) == 0:
        return False, "missing_scope", "environments scope is required"

    return True, "", ""


def _emit_prowler_audit_event(
    audit_file: str,
    finding_id: Any,
    exception: "dict[str, Any] | None",
    status: str,
    reason: "str | None" = None,
) -> None:
    """Append one JSONL event to the audit log (mirrors shift-left emit_audit_event)."""
    if not audit_file:
        return
    import pathlib
    pathlib.Path(audit_file).parent.mkdir(parents=True, exist_ok=True)
    event: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "defectdojo",
        "action": "normalize_prowler_exception",
        "finding_id": str(finding_id) if finding_id is not None else "",
        "output": exception,
        "status": status,
    }
    if reason:
        event["reason"] = reason
    try:
        line = json.dumps(event, separators=(",", ":"), sort_keys=True)
    except (TypeError, ValueError):
        line = json.dumps({
            "timestamp": event["timestamp"],
            "source": "defectdojo",
            "action": "normalize_prowler_exception",
            "finding_id": event["finding_id"],
            "status": status,
            "reason": reason or "",
            "_serialization_error": True,
        }, separators=(",", ":"))
    with open(audit_file, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def _deduplicate_prowler_exceptions(
    exceptions: "list[dict[str, Any]]",
) -> "list[dict[str, Any]]":
    """Deduplicate by stable SHA-256 ID, keeping first occurrence (mirrors shift-left)."""
    by_id: "dict[str, dict[str, Any]]" = {}
    for ex in exceptions:
        ex_id = _clean_text(ex.get("id"))
        if not ex_id:
            continue
        if ex_id not in by_id:
            by_id[ex_id] = ex
    return [by_id[k] for k in sorted(by_id.keys())]


# ---------------------------------------------------------------------------
# DefectDojo fetch
# ---------------------------------------------------------------------------


def fetch_risk_acceptances(
    base_url: str, api_key: str, engagement: str
) -> list[dict[str, Any]]:
    headers = {
        "Authorization": f"Token {api_key}",
        "Content-Type": "application/json",
    }
    endpoint = f"{_normalize_dojo_base_url(base_url)}/api/v2/findings/"

    def _paginate(params: dict[str, Any]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        url: str | None = endpoint
        next_params: dict[str, Any] = params
        while url:
            resp = requests.get(url, headers=headers, params=next_params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            results.extend(data.get("results", []))
            url = data.get("next")
            next_params = {}
        return results

    base_params: dict[str, Any] = {"limit": 200, "offset": 0, "risk_accepted": "true"}
    attempts: list[tuple[str, dict[str, Any]]] = []
    if engagement:
        p = dict(base_params)
        p["engagement"] = engagement
        attempts.append(("engagement_only", p))
    attempts.append(("risk_accepted_only", dict(base_params)))

    last_http_error: requests.exceptions.HTTPError | None = None
    tried_signatures: set[tuple[tuple[str, str], ...]] = set()
    results: list[dict[str, Any]] = []
    selected_mode = ""

    for label, params in attempts:
        signature = tuple(sorted((str(k), str(v)) for k, v in params.items()))
        if signature in tried_signatures:
            continue
        tried_signatures.add(signature)

        try:
            results = _paginate(params)
            selected_mode = label
            if label != "engagement_only":
                logger.warning("fetch_prowler_exceptions_fallback_mode", mode=label)
            break
        except requests.exceptions.HTTPError as exc:
            last_http_error = exc
            status = exc.response.status_code if exc.response is not None else None
            if status in (400, 403):
                logger.warning(
                    "fetch_prowler_exceptions_query_rejected",
                    mode=label,
                    status=status,
                )
                continue
            raise
    else:
        if last_http_error is not None:
            raise last_http_error
        return []

    accepted = [f for f in results if f.get("risk_accepted")]
    if not engagement:
        return accepted

    if selected_mode == "engagement_only":
        filtered: list[dict[str, Any]] = []
        dropped_mismatched = 0
        missing_engagement_field = 0
        engagement_clean = _clean_text(engagement)
        for finding in accepted:
            finding_engagement = _extract_engagement_id(finding)
            if finding_engagement:
                if finding_engagement == engagement_clean:
                    filtered.append(finding)
                else:
                    dropped_mismatched += 1
                continue
            missing_engagement_field += 1
            filtered.append(finding)

        if missing_engagement_field > 0:
            logger.warning(
                "fetch_prowler_exceptions_engagement_field_missing",
                trusting_server_filter=True,
                missing=missing_engagement_field,
                total=len(accepted),
            )
        if dropped_mismatched > 0:
            logger.warning(
                "fetch_prowler_exceptions_engagement_mismatch_dropped",
                count=dropped_mismatched,
                expected_engagement=engagement_clean,
            )
        return filtered

    return [f for f in accepted if _matches_engagement(f, engagement)]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Fetch Prowler exceptions from DefectDojo for OPA shift-right evaluation"
    )
    parser.add_argument(
        "--output",
        default=os.getenv("PROWLER_EXCEPTIONS_PATH", ".cloudsentinel/prowler_exceptions.json"),
    )
    parser.add_argument(
        "--base-url", default=os.getenv("DOJO_URL", os.getenv("DEFECTDOJO_URL", ""))
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv(
            "DOJO_API_KEY",
            os.getenv("DEFECTDOJO_API_KEY", os.getenv("DEFECTDOJO_API_TOKEN", "")),
        ),
    )
    parser.add_argument(
        "--engagement",
        default=os.getenv(
            "DOJO_ENGAGEMENT_ID_RIGHT",
            os.getenv("DEFECTDOJO_ENGAGEMENT_ID_RIGHT", ""),
        ),
    )
    parser.add_argument(
        "--environment",
        default=os.getenv(
            "PROWLER_ENVIRONMENT", os.getenv("CI_ENVIRONMENT_NAME", "production")
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print exceptions without writing to disk",
    )
    parser.add_argument(
        "--audit-log",
        default=os.getenv(
            "PROWLER_EXCEPTIONS_AUDIT_LOG",
            ".cloudsentinel/03_core_artifacts/prowler_exceptions_audit.jsonl",
        ),
        help="Path for per-exception JSONL audit trail",
    )
    parser.add_argument(
        "--dropped-output",
        default=os.getenv(
            "PROWLER_DROPPED_EXCEPTIONS_PATH",
            ".cloudsentinel/prowler_dropped_exceptions.json",
        ),
        help="Path for dropped/rejected exceptions report",
    )
    parser.add_argument(
        "--enforce-approver-allowlist",
        action="store_true",
        default=os.getenv("PROWLER_ENFORCE_APPROVER_ALLOWLIST", "").lower() in ("1", "true", "yes"),
        help="Reject exceptions whose approver is not in the allowlist",
    )
    parser.add_argument(
        "--approver-allowlist",
        default=os.getenv("PROWLER_APPROVER_ALLOWLIST", ""),
        help="Comma-separated list of allowed approver usernames",
    )
    args = parser.parse_args(argv)

    if not args.base_url:
        print("ERROR: DOJO_URL/DEFECTDOJO_URL not set", file=sys.stderr)
        return 1
    if not args.api_key:
        print("ERROR: DOJO_API_KEY/DEFECTDOJO_API_KEY not set", file=sys.stderr)
        return 1
    if not args.engagement:
        print(
            "ERROR: DOJO_ENGAGEMENT_ID_RIGHT/DEFECTDOJO_ENGAGEMENT_ID_RIGHT not set",
            file=sys.stderr,
        )
        return 1

    logger.info(
        "fetch_prowler_exceptions_start",
        environment=args.environment,
        output=args.output,
    )

    try:
        raw_ras = fetch_risk_acceptances(
            args.base_url,
            args.api_key,
            engagement=args.engagement,
        )
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else None
        print(
            f"ERROR: Failed to fetch Prowler exceptions from DefectDojo (HTTP {status}): {exc}",
            file=sys.stderr,
        )
        return 1
    except Exception as exc:
        print(
            f"ERROR: Failed to fetch Prowler exceptions from DefectDojo: {exc}",
            file=sys.stderr,
        )
        return 1

    logger.info("prowler_risk_acceptances_fetched", count=len(raw_ras))

    approver_allowlist: set[str] | None = None
    if args.enforce_approver_allowlist and args.approver_allowlist:
        approver_allowlist = {
            u.strip() for u in args.approver_allowlist.split(",") if u.strip()
        }

    import pathlib

    audit_log_path = pathlib.Path(args.audit_log)
    audit_log_path.parent.mkdir(parents=True, exist_ok=True)

    scope = _build_scope(args.environment)
    exceptions: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    skipped = 0

    for ra in raw_ras:
        ex = _parse_ra_to_exception(ra, scope)
        if ex is None:
            skipped += 1
            continue

        finding_id = ex.get("finding_id") or ra.get("id", "unknown")
        ok, reason, detail = _validate_prowler_exception(
            ex,
            approver_allowlist=approver_allowlist,
            enforce_approver_allowlist=args.enforce_approver_allowlist,
        )

        if not ok:
            _emit_prowler_audit_event(
                str(audit_log_path), finding_id, ex, "dropped", reason=reason
            )
            dropped.append(
                {
                    "finding_id": finding_id,
                    "reason": reason,
                    "detail": detail,
                    "exception": ex,
                }
            )
            logger.warning(
                "prowler_exception_dropped",
                finding_id=finding_id,
                reason=reason,
                detail=detail,
            )
            continue

        _emit_prowler_audit_event(str(audit_log_path), finding_id, ex, "accepted")
        exceptions.append(ex)

    exceptions = _deduplicate_prowler_exceptions(exceptions)

    logger.info(
        "prowler_exceptions_built",
        total=len(exceptions),
        skipped=skipped,
        dropped=len(dropped),
    )

    output_doc = {
        "cloudsentinel": {
            "prowler_exceptions": {
                "schema_version": PROWLER_EXCEPTION_SCHEMA_VERSION,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "environment": args.environment,
                "source": "defectdojo",
                "meta": {
                    "engagement_scope": "shift-right",
                    "raw_risk_acceptances": len(raw_ras),
                    "valid_exceptions": len(exceptions),
                    "skipped_findings": skipped,
                    "dropped_count": len(dropped),
                },
                "exceptions": exceptions,
            }
        }
    }

    if args.dry_run:
        print(json.dumps(output_doc, indent=2))
        return 0

    out_path = pathlib.Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(output_doc, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    logger.info("prowler_exceptions_written", path=str(out_path))

    dropped_path = pathlib.Path(args.dropped_output)
    dropped_path.parent.mkdir(parents=True, exist_ok=True)
    dropped_doc = {
        "cloudsentinel": {
            "prowler_dropped_exceptions": {
                "schema_version": PROWLER_EXCEPTION_SCHEMA_VERSION,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "environment": args.environment,
                "total_dropped": len(dropped),
                "entries": dropped,
            }
        }
    }
    dropped_path.write_text(
        json.dumps(dropped_doc, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    logger.info("prowler_dropped_exceptions_written", path=str(dropped_path), count=len(dropped))

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
