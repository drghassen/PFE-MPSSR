#!/usr/bin/env python3
"""
fetch_drift_exceptions.py — Fetch drift exceptions from DefectDojo for shift-right OPA evaluation.

Analogous to shift-left/normalizer/fetch_exceptions/fetch_exceptions.py but scoped to
the drift engine (shift-right). Fetches Risk Acceptances from DefectDojo and transforms
them into the drift_exceptions.json format consumed by drift_decision.rego.

Usage:
    python shift-right/scripts/fetch_drift_exceptions.py \
        --output .cloudsentinel/drift_exceptions.json

Environment variables required:
    DEFECTDOJO_URL      Base URL of DefectDojo instance (e.g. http://localhost:8080)
    DEFECTDOJO_API_KEY  DefectDojo API key (masked CI variable)
    DRIFT_ENVIRONMENT   Current environment (default: production)
    CI_PROJECT_PATH     GitLab project path (used for scope binding)
    CI_COMMIT_REF_NAME  Current branch (used for scope binding)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any

try:
    import requests
except ImportError:
    print("ERROR: 'requests' library not installed. Run: pip install requests", file=sys.stderr)
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _stable_exception_id(ra: dict[str, Any]) -> str:
    """
    Deterministic SHA-256 ID for a DefectDojo Risk Acceptance.
    Stable across runs so OPA can correlate the same exception between pipeline runs.
    """
    key = f"{ra.get('id', '')}:{ra.get('name', '')}:{ra.get('created', '')}"
    return hashlib.sha256(key.encode()).hexdigest()


def _build_scope(environment: str) -> dict[str, Any]:
    """Build CI scope for exception binding."""
    return {
        "repos": [os.getenv("CI_PROJECT_PATH", "")],
        "branches": [os.getenv("CI_COMMIT_REF_NAME", "")],
        "environments": [environment] if environment else [],
    }


def _parse_ra_to_exception(finding: dict[str, Any], scope: dict[str, Any]) -> dict[str, Any] | None:
    """
    Transform a DefectDojo Finding into a drift exception entry.

    Returns None if the Finding lacks mandatory fields.
    """
    if not finding.get("risk_accepted"):
        return None

    resource_type = str(finding.get("severity", ""))
    resource_id = str(finding.get("id", ""))

    if not resource_type:
        return None

    accepted_risks = finding.get("accepted_risks", [])
    if not isinstance(accepted_risks, list) or len(accepted_risks) == 0:
        return None

    ra = accepted_risks[0]

    requested_by = str(ra.get("owner", {}).get("username", "unknown") if isinstance(ra.get("owner"), dict) else ra.get("owner", "unknown"))
    approved_by = str(ra.get("accepted_by", {}).get("username", "unknown") if isinstance(ra.get("accepted_by"), dict) else ra.get("accepted_by", "unknown"))

    approved_at = str(ra.get("created", ""))
    expires_at = str(ra.get("expiration_date", ""))

    if not (approved_at and expires_at and requested_by and approved_by):
        return None

    # Ensure RFC3339 format (DefectDojo may return date-only strings)
    if len(approved_at) == 10:
        approved_at = f"{approved_at}T00:00:00Z"
    if len(expires_at) == 10:
        expires_at = f"{expires_at}T23:59:59Z"

    return {
        "id": _stable_exception_id(finding),
        "source": "defectdojo",
        "status": "approved",
        "resource_type": resource_type,
        "resource_id": resource_id,
        "requested_by": requested_by,
        "approved_by": approved_by,
        "approved_at": approved_at,
        "expires_at": expires_at,
        "environments": scope.get("environments", []),
        "repos": scope.get("repos", []),
        "branches": scope.get("branches", []),
        "defectdojo_ra_id": ra.get("id"),
        "notes": finding.get("notes", ""),
    }


# ---------------------------------------------------------------------------
# DefectDojo fetch
# ---------------------------------------------------------------------------

def fetch_risk_acceptances(base_url: str, api_key: str, engagement: str) -> list[dict[str, Any]]:
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
    parser = argparse.ArgumentParser(description="Fetch drift exceptions from DefectDojo for OPA shift-right evaluation")
    parser.add_argument("--output", default=os.getenv("DRIFT_EXCEPTIONS_PATH", ".cloudsentinel/drift_exceptions.json"))
    parser.add_argument("--base-url", default=os.getenv("DEFECTDOJO_URL", ""))
    parser.add_argument("--api-key", default=os.getenv("DOJO_API_KEY", ""))
    parser.add_argument("--engagement", default=os.getenv("DOJO_ENGAGEMENT_ID_RIGHT", ""))
    parser.add_argument("--environment", default=os.getenv("DRIFT_ENVIRONMENT", os.getenv("CI_ENVIRONMENT_NAME", "production")))
    parser.add_argument("--dry-run", action="store_true", help="Print exceptions without writing to disk")
    args = parser.parse_args(argv)

    if not args.base_url:
        print("ERROR: DEFECTDOJO_URL not set", file=sys.stderr)
        return 1
    if not args.api_key:
        print("ERROR: DOJO_API_KEY not set", file=sys.stderr)
        return 1

    logger.info("fetch_drift_exceptions_start", environment=args.environment, output=args.output)

    try:
        raw_ras = fetch_risk_acceptances(args.base_url, args.api_key, engagement=args.engagement)
    except Exception as exc:
        print(f"ERROR: Failed to fetch Risk Acceptances from DefectDojo: {exc}", file=sys.stderr)
        return 1

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

    if args.dry_run:
        print(json.dumps(output_doc, indent=2))
        return 0

    import pathlib
    out_path = pathlib.Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output_doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    logger.info("drift_exceptions_written", path=str(out_path), count=len(exceptions))

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
