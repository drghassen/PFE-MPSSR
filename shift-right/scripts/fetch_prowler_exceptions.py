#!/usr/bin/env python3
"""
fetch_prowler_exceptions.py — Fetch Prowler exception data from DefectDojo.

Reads risk-accepted findings whose vuln_id_from_tool starts with "prowler:"
and generates two artefacts consumed by the CI pipeline:

  1. prowler_exceptions.json  — OPA-compatible exception store for the
                                opa-prowler-decision.sh gate (Gap #1).
     Format:
       {"cloudsentinel": {"prowler_exceptions": {"exceptions": [...]}}}

  2. mutelist-azure.yaml      — Prowler native mutelist for pre-scan filtering.
     Findings in this file are suppressed before Prowler even generates them,
     reducing DefectDojo noise for formally risk-accepted checks.
     Format:
       Accounts:
         "*":
           Checks:
             <check_id>:
               Regions: ["*"]
               Resources: ["<resource>" | "*"]

Both outputs are derived from the same DefectDojo risk acceptances so the
pre-scan filter (mutelist) and the OPA gate (exceptions) stay in sync.

Usage:
    python shift-right/scripts/fetch_prowler_exceptions.py \\
        --output-exceptions .cloudsentinel/prowler_exceptions.json \\
        --output-mutelist   shift-right/prowler/mutelist-azure.yaml

Environment variables:
    DOJO_URL / DEFECTDOJO_URL
    DOJO_API_KEY / DEFECTDOJO_API_KEY / DEFECTDOJO_API_TOKEN
    DOJO_ENGAGEMENT_ID_RIGHT / DEFECTDOJO_ENGAGEMENT_ID_RIGHT
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import sys
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

try:
    import requests
except ImportError:
    print("ERROR: 'requests' library not installed.", file=sys.stderr)
    sys.exit(1)


_PROWLER_PREFIX = "prowler:"


def _clean(v: Any) -> str:
    return str(v).strip() if v is not None else ""


def _stable_id(finding: dict[str, Any]) -> str:
    key = f"{finding.get('id','')}:{finding.get('title','')}:{finding.get('date','')}"
    return hashlib.sha256(key.encode()).hexdigest()


def _extract_check_id(vuln_id: str) -> str:
    """Strip the 'prowler:' prefix to get the raw Prowler check name."""
    if vuln_id.startswith(_PROWLER_PREFIX):
        return vuln_id[len(_PROWLER_PREFIX):]
    return vuln_id


def _extract_resource(finding: dict[str, Any]) -> str:
    """Best-effort resource extraction from a DefectDojo finding."""
    resource = _clean(finding.get("component_name"))
    if resource:
        return resource
    unique_id = _clean(finding.get("unique_id_from_tool"))
    # unique_id format: prowler:{check_id}:{resource_uid}
    parts = unique_id.split(":", 2)
    if len(parts) == 3:
        return _clean(parts[2])
    return "*"


def _parse_ra_dates(finding: dict[str, Any]) -> tuple[str, str | None]:
    """Return (approved_at, expires_at) in RFC3339 format."""
    accepted_risks = finding.get("accepted_risks", [])
    if not isinstance(accepted_risks, list) or not accepted_risks:
        return ("", None)
    ra = accepted_risks[0]
    approved_at = _clean(ra.get("created", ""))
    expires_at = _clean(ra.get("expiration_date", "")) or None
    if approved_at and len(approved_at) == 10:
        approved_at = f"{approved_at}T00:00:00Z"
    if expires_at and len(expires_at) == 10:
        expires_at = f"{expires_at}T23:59:59Z"
    return approved_at, expires_at


def fetch_accepted_prowler_findings(
    base_url: str, api_key: str, engagement: str
) -> list[dict[str, Any]]:
    # DEFECTDOJO_VERIFY_SSL=false disables TLS verification for local/dev
    # instances whose cert hostname does not match (e.g. host.docker.internal
    # with a cert issued for 'localhost'). Never set this in production.
    _verify: bool | str = os.environ.get("DEFECTDOJO_VERIFY_SSL", "true").lower() != "false"
    if not _verify:
        import urllib3  # noqa: PLC0415
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    headers = {"Authorization": f"Token {api_key}", "Content-Type": "application/json"}
    url = f"{base_url.rstrip('/')}/api/v2/findings/"
    params: dict[str, Any] = {
        "limit": 200,
        "offset": 0,
        "risk_accepted": "true",
        "vuln_id_from_tool__startswith": _PROWLER_PREFIX,
    }
    if engagement:
        params["engagement"] = engagement

    results: list[dict[str, Any]] = []
    while url:
        resp = requests.get(url, headers=headers, params=params, timeout=30, verify=_verify)
        resp.raise_for_status()
        data = resp.json()
        results.extend(data.get("results", []))
        url = data.get("next")
        params = {}

    # Fallback: some DefectDojo versions don't support vuln_id__startswith filter.
    # Re-filter client-side to be safe.
    return [f for f in results if _clean(f.get("vuln_id_from_tool", "")).startswith(_PROWLER_PREFIX)]


def build_opa_exceptions(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    exceptions = []
    for f in findings:
        if not f.get("risk_accepted"):
            continue
        vuln_id = _clean(f.get("vuln_id_from_tool", ""))
        if not vuln_id.startswith(_PROWLER_PREFIX):
            continue
        resource = _extract_resource(f)
        approved_at, expires_at = _parse_ra_dates(f)
        accepted_risks = f.get("accepted_risks", [{}])
        ra = accepted_risks[0] if accepted_risks else {}
        approved_by = _clean(
            ra.get("accepted_by", {}).get("username", "unknown")
            if isinstance(ra.get("accepted_by"), dict)
            else ra.get("accepted_by", "unknown")
        )
        exceptions.append({
            "id":          _stable_id(f),
            "check_id":    vuln_id,        # full "prowler:{check_name}" matches vuln_id_from_tool
            "resource":    resource or "*",
            "approved_by": approved_by,
            "approved_at": approved_at,
            "expires_at":  expires_at,
            "source":      "defectdojo",
            "defectdojo_finding_id": f.get("id"),
        })
    return exceptions


def build_mutelist_yaml(findings: list[dict[str, Any]]) -> str:
    """
    Generate Prowler-native mutelist YAML from risk-accepted findings.

    Groups resources by check_id so the YAML is minimal and readable.
    Resource is set to "*" when no specific resource could be extracted.
    """
    by_check: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        if not f.get("risk_accepted"):
            continue
        vuln_id = _clean(f.get("vuln_id_from_tool", ""))
        if not vuln_id.startswith(_PROWLER_PREFIX):
            continue
        check_id = _extract_check_id(vuln_id)
        resource = _extract_resource(f) or "*"
        by_check[check_id].add(resource)

    if not by_check:
        return "# No Prowler exceptions active — mutelist empty.\nAccounts: {}\n"

    lines = ["Accounts:", '  "*":', "    Checks:"]
    for check_id in sorted(by_check):
        resources = sorted(by_check[check_id])
        lines.append(f"      {check_id}:")
        lines.append("        Regions:")
        lines.append('          - "*"')
        lines.append("        Resources:")
        for r in resources:
            # Quote resource strings that contain special YAML characters.
            safe_r = r.replace('"', '\\"')
            lines.append(f'          - "{safe_r}"')
    return "\n".join(lines) + "\n"


def _write_degraded(output_exceptions: str, reason: str) -> None:
    doc = {
        "cloudsentinel": {
            "prowler_exceptions": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "source": "defectdojo",
                "meta": {"mode": "DEGRADED", "reason": reason},
                "exceptions": [],
            }
        }
    }
    pathlib.Path(output_exceptions).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(output_exceptions).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Fetch Prowler exceptions from DefectDojo for OPA gate and mutelist generation"
    )
    parser.add_argument(
        "--output-exceptions",
        default=os.getenv("PROWLER_EXCEPTIONS_PATH", ".cloudsentinel/prowler_exceptions.json"),
    )
    parser.add_argument(
        "--output-mutelist",
        default=os.getenv("PROWLER_MUTELIST_PATH", "shift-right/prowler/mutelist-azure.yaml"),
    )
    parser.add_argument("--base-url", default=os.getenv("DOJO_URL", os.getenv("DEFECTDOJO_URL", "")))
    parser.add_argument(
        "--api-key",
        default=os.getenv("DOJO_API_KEY", os.getenv("DEFECTDOJO_API_KEY", os.getenv("DEFECTDOJO_API_TOKEN", ""))),
    )
    parser.add_argument(
        "--engagement",
        default=os.getenv("DOJO_ENGAGEMENT_ID_RIGHT", os.getenv("DEFECTDOJO_ENGAGEMENT_ID_RIGHT", "")),
    )
    parser.add_argument("--dry-run", action="store_true", help="Print outputs without writing files")
    args = parser.parse_args(argv)

    if not args.base_url or not args.api_key:
        print("[fetch-prowler-exc][WARN] DOJO_URL or DOJO_API_KEY not set — writing empty exception set.", file=sys.stderr)
        _write_degraded(args.output_exceptions, "missing_defectdojo_credentials")
        return 0

    try:
        findings = fetch_accepted_prowler_findings(args.base_url, args.api_key, args.engagement)
    except Exception as exc:
        print(f"[fetch-prowler-exc][WARN] DefectDojo unreachable: {exc} — writing empty exception set.", file=sys.stderr)
        _write_degraded(args.output_exceptions, "defectdojo_unreachable")
        return 0

    exceptions = build_opa_exceptions(findings)
    mutelist_yaml = build_mutelist_yaml(findings)

    opa_doc = {
        "cloudsentinel": {
            "prowler_exceptions": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "source": "defectdojo",
                "exceptions": exceptions,
            }
        }
    }

    if args.dry_run:
        print("=== OPA exceptions ===")
        print(json.dumps(opa_doc, indent=2))
        print("=== Mutelist YAML ===")
        print(mutelist_yaml)
        return 0

    exc_path = pathlib.Path(args.output_exceptions)
    exc_path.parent.mkdir(parents=True, exist_ok=True)
    exc_path.write_text(json.dumps(opa_doc, indent=2) + "\n", encoding="utf-8")
    print(f"[fetch-prowler-exc] Written {len(exceptions)} exception(s) → {exc_path}")

    ml_path = pathlib.Path(args.output_mutelist)
    ml_path.parent.mkdir(parents=True, exist_ok=True)
    ml_path.write_text(mutelist_yaml, encoding="utf-8")
    print(f"[fetch-prowler-exc] Written mutelist ({len(findings)} check(s)) → {ml_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
