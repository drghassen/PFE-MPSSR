#!/usr/bin/env python3
"""
fetch_drift_exceptions.py — Fetch drift exceptions from DefectDojo for shift-right OPA evaluation.

Analogous to shift-left/normalizer/fetch_exceptions/fetch_exceptions.py but scoped to
the drift engine (shift-right). Fetches Risk Acceptances from DefectDojo and transforms
them into the drift_exceptions.json format consumed by policies/opa/drift (cloudsentinel.shiftright.drift).

Usage:
    python shift-right/scripts/fetch_drift_exceptions.py \
        --output .cloudsentinel/drift_exceptions.json

Environment variables required:
    DOJO_URL / DEFECTDOJO_URL                      Base URL of DefectDojo instance
    DOJO_API_KEY / DEFECTDOJO_API_KEY              DefectDojo API key
    DOJO_ENGAGEMENT_ID_RIGHT / DEFECTDOJO_ENGAGEMENT_ID_RIGHT
    DRIFT_ENVIRONMENT   Current environment (default: production)
    CI_PROJECT_PATH     GitLab project path (used for scope binding)
    CI_COMMIT_REF_NAME  Current branch (used for scope binding)
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

try:
    import structlog

    logger = structlog.get_logger(__name__)
except ImportError:
    import logging

    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DRIFT_EXCEPTION_SCHEMA_VERSION = "1.0.0"
_DESCRIPTION_FIELD_RE = re.compile(
    r"(?im)^\s*-\s*([A-Za-z][A-Za-z _-]+?)\s*:\s*(.+?)\s*$"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _stable_exception_id(ra: dict[str, Any]) -> str:
    """
    Deterministic SHA-256 ID for a DefectDojo Risk Acceptance.
    Stable across runs so OPA can correlate the same exception between pipeline runs.
    """
    key = f"{ra.get('id', '')}:{ra.get('title', ra.get('name', ''))}:{ra.get('created', '')}"
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


def _extract_structured_resource_type(
    finding: dict[str, Any], description_fields: dict[str, str]
) -> str:
    resource_obj = finding.get("resource")
    if isinstance(resource_obj, dict):
        nested_type = _clean_text(resource_obj.get("type"))
        if nested_type:
            return nested_type

    explicit_type = _clean_text(finding.get("resource_type"))
    if explicit_type:
        return explicit_type

    vuln_id = _clean_text(finding.get("vuln_id_from_tool"))
    if vuln_id.startswith("drift_type:"):
        return _clean_text(vuln_id.split(":", 1)[1])

    return _clean_text(description_fields.get("resource_type"))


def _extract_structured_resource_address(
    finding: dict[str, Any], description_fields: dict[str, str]
) -> str:
    resource_obj = finding.get("resource")
    if isinstance(resource_obj, dict):
        nested_address = _clean_text(resource_obj.get("address"))
        if nested_address:
            return nested_address

    component_name = _clean_text(finding.get("component_name"))
    if component_name:
        return component_name

    unique_id = _clean_text(finding.get("unique_id_from_tool"))
    if unique_id.startswith("cloudsentinel-drift:"):
        parts = unique_id.split(":", 2)
        if len(parts) == 3:
            return _clean_text(parts[2])

    return _clean_text(description_fields.get("address"))


def _build_scope(environment: str) -> dict[str, Any]:
    """Build CI scope for exception binding."""
    repo = _clean_text(os.getenv("CI_PROJECT_PATH", ""))
    branch = _clean_text(os.getenv("CI_COMMIT_REF_NAME", ""))
    return {
        "repos": [repo] if repo else [],
        "branches": [branch] if branch else [],
        "environments": [_clean_text(environment)] if _clean_text(environment) else [],
    }


def _parse_ra_to_exception(
    finding: dict[str, Any], scope: dict[str, Any]
) -> dict[str, Any] | None:
    """
    Transform a DefectDojo Finding into a drift exception entry.

    Returns None if the Finding lacks mandatory fields.
    """
    if not finding.get("risk_accepted"):
        return None

    description_fields = _parse_description_fields(finding.get("description"))
    resource_type = _extract_structured_resource_type(finding, description_fields)
    resource_address = _extract_structured_resource_address(finding, description_fields)

    if not resource_type or not resource_address:
        logger.warning(
            "resource_parsing_rejected",
            finding_id=finding.get("id"),
            title=finding.get("title", finding.get("name", "")),
            reason="missing_structured_resource_context",
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

    # Ensure RFC3339 format (DefectDojo may return date-only strings)
    if len(approved_at) == 10:
        approved_at = f"{approved_at}T00:00:00Z"
    if expires_at and len(expires_at) == 10:
        expires_at = f"{expires_at}T23:59:59Z"

    notes_raw = finding.get("notes", [])
    if isinstance(notes_raw, list):
        notes_str = "\n".join(
            n.get("text", "") for n in notes_raw if isinstance(n, dict)
        )
    else:
        notes_str = str(notes_raw)
        notes_raw = []

    return {
        "id": _stable_exception_id(finding),
        "source": "defectdojo",
        "status": "approved",
        "resource_type": resource_type,
        "resource_id": resource_address,
        "resource": {
            "type": resource_type,
            "address": resource_address,
        },
        "requested_by": requested_by,
        "requested_by_details": requested_by_details,
        "approved_by": approved_by,
        "approved_at": approved_at,
        "expires_at": expires_at or None,
        "environments": scope.get("environments", []),
        "repos": scope.get("repos", []),
        "branches": scope.get("branches", []),
        "defectdojo_ra_id": ra.get("id"),
        "notes": notes_str,
        "notes_structured": notes_raw,
    }


# ---------------------------------------------------------------------------
# DefectDojo fetch
# ---------------------------------------------------------------------------


def fetch_risk_acceptances(
    base_url: str, api_key: str, engagement: str
) -> list[dict[str, Any]]:
    """Fetch all accepted findings from DefectDojo for the given engagement."""
    headers = {
        "Authorization": f"Token {api_key}",
        "Content-Type": "application/json",
    }
    url = f"{base_url.rstrip('/')}/api/v2/findings/"
    params: dict[str, Any] = {"limit": 200, "offset": 0, "risk_accepted": "true"}
    if engagement:
        params["engagement"] = engagement

    results: list[dict[str, Any]] = []
    while url:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        results.extend(data.get("results", []))
        url = data.get("next")  # type: ignore[assignment]
        params = {}  # next URL already has params embedded

    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Fetch drift exceptions from DefectDojo for OPA shift-right evaluation"
    )
    parser.add_argument(
        "--output",
        default=os.getenv(
            "DRIFT_EXCEPTIONS_PATH", ".cloudsentinel/drift_exceptions.json"
        ),
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
            "DOJO_ENGAGEMENT_ID_RIGHT", os.getenv("DEFECTDOJO_ENGAGEMENT_ID_RIGHT", "")
        ),
    )
    parser.add_argument(
        "--environment",
        default=os.getenv(
            "DRIFT_ENVIRONMENT", os.getenv("CI_ENVIRONMENT_NAME", "production")
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print exceptions without writing to disk",
    )
    args = parser.parse_args(argv)

    if not args.base_url:
        print("ERROR: DOJO_URL/DEFECTDOJO_URL not set", file=sys.stderr)
        return 1
    if not args.api_key:
        print("ERROR: DOJO_API_KEY/DEFECTDOJO_API_KEY not set", file=sys.stderr)
        return 1

    logger.info(
        "fetch_drift_exceptions_start", environment=args.environment, output=args.output
    )

    def write_output(doc: dict[str, Any]) -> None:
        if args.dry_run:
            print(json.dumps(doc, indent=2))
            return
        import pathlib

        out_path = pathlib.Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        logger.info("drift_exceptions_written", path=str(out_path))

    if not args.engagement:
        logger.warning("DOJO_ENGAGEMENT_ID_RIGHT is missing. Entering DEGRADED mode.")
        write_output(
            {
                "cloudsentinel": {
                    "drift_exceptions": {
                        "schema_version": DRIFT_EXCEPTION_SCHEMA_VERSION,
                        "generated_at": datetime.now(timezone.utc).isoformat(),
                        "environment": args.environment,
                        "source": "defectdojo",
                        "meta": {"mode": "DEGRADED", "reason": "missing_engagement"},
                        "exceptions": [],
                    }
                }
            }
        )
        return 0

    try:
        raw_ras = fetch_risk_acceptances(
            args.base_url, args.api_key, engagement=args.engagement
        )
    except Exception as exc:
        print(
            f"ERROR: Failed to fetch Risk Acceptances from DefectDojo: {exc}",
            file=sys.stderr,
        )
        logger.warning("Network failure to DefectDojo. Entering DEGRADED mode.")
        write_output(
            {
                "cloudsentinel": {
                    "drift_exceptions": {
                        "schema_version": DRIFT_EXCEPTION_SCHEMA_VERSION,
                        "generated_at": datetime.now(timezone.utc).isoformat(),
                        "environment": args.environment,
                        "source": "defectdojo",
                        "meta": {
                            "mode": "DEGRADED",
                            "reason": "defectdojo_unreachable",
                        },
                        "exceptions": [],
                    }
                }
            }
        )
        return 0

    logger.info("risk_acceptances_fetched", count=len(raw_ras))

    scope = _build_scope(args.environment)
    exceptions: list[dict[str, Any]] = []
    skipped = 0

    for ra in raw_ras:
        ex = _parse_ra_to_exception(ra, scope)
        if ex is None:
            skipped += 1
            continue
        exceptions.append(ex)

    logger.info(
        "drift_exceptions_built",
        total=len(exceptions),
        skipped=skipped,
    )

    output_doc = {
        "cloudsentinel": {
            "drift_exceptions": {
                "schema_version": DRIFT_EXCEPTION_SCHEMA_VERSION,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "environment": args.environment,
                "source": "defectdojo",
                "exceptions": exceptions,
            }
        }
    }

    write_output(output_doc)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
