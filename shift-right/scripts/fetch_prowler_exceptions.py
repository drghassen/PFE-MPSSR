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
_SCHEMA_VERSION = "1.0.0"


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


def _normalize_dojo_base_url(base_url: str) -> str:
    """
    Normalize DefectDojo base URL so callers can pass either:
      - https://dojo.example.local
      - https://dojo.example.local/api/v2
    """
    normalized = base_url.rstrip("/")
    if normalized.endswith("/api/v2"):
        normalized = normalized[: -len("/api/v2")]
    return normalized


def _extract_engagement_id(finding: dict[str, Any]) -> str:
    raw = finding.get("engagement")
    if isinstance(raw, dict):
        return _clean(raw.get("id"))
    return _clean(raw)


def _matches_engagement(finding: dict[str, Any], engagement: str) -> bool:
    if not engagement:
        return True
    return _extract_engagement_id(finding) == _clean(engagement)


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
    headers = {"Authorization": f"Token {api_key}", "Content-Type": "application/json"}
    base_endpoint = f"{_normalize_dojo_base_url(base_url)}/api/v2/findings/"

    def _paginate(params: dict[str, Any]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        url: str | None = base_endpoint
        next_params: dict[str, Any] = params
        while url:
            resp = requests.get(url, headers=headers, params=next_params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            results.extend(data.get("results", []))
            url = data.get("next")
            next_params = {}
        return results

    # Preferred: server-side filter by vuln_id prefix + engagement.
    # Fallback chain: progressively remove API-side filters that may be blocked
    # by some DefectDojo versions or RBAC profiles, then apply filtering
    # client-side to preserve exact scope.
    base_params: dict[str, Any] = {"limit": 200, "offset": 0, "risk_accepted": "true"}
    attempts: list[tuple[str, dict[str, Any]]] = []

    p = dict(base_params)
    p["vuln_id_from_tool__startswith"] = _PROWLER_PREFIX
    if engagement:
        p["engagement"] = engagement
    attempts.append(("vuln_prefix+engagement", p))

    if engagement:
        p = dict(base_params)
        p["engagement"] = engagement
        attempts.append(("engagement_only", p))

    attempts.append(("risk_accepted_only", dict(base_params)))

    results: list[dict[str, Any]] = []
    last_http_error: requests.exceptions.HTTPError | None = None
    tried_signatures: set[tuple[tuple[str, str], ...]] = set()

    for label, params in attempts:
        signature = tuple(sorted((str(k), str(v)) for k, v in params.items()))
        if signature in tried_signatures:
            continue
        tried_signatures.add(signature)

        try:
            results = _paginate(params)
            if label != "vuln_prefix+engagement":
                print(
                    f"[fetch-prowler-exc][WARN] Using fallback query mode '{label}' "
                    f"(client-side filtering active).",
                    file=sys.stderr,
                )
            break
        except requests.exceptions.HTTPError as exc:
            last_http_error = exc
            status = exc.response.status_code if exc.response is not None else None
            if status in (400, 403):
                print(
                    f"[fetch-prowler-exc][WARN] Query mode '{label}' rejected with HTTP {status} "
                    f"— trying next fallback.",
                    file=sys.stderr,
                )
                continue
            raise
    else:
        if last_http_error is not None:
            raise last_http_error
        return []

    return [
        f
        for f in results
        if f.get("risk_accepted")
        and _clean(f.get("vuln_id_from_tool", "")).startswith(_PROWLER_PREFIX)
        and _matches_engagement(f, engagement)
    ]


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

def _write_outputs(
    output_exceptions: str,
    output_mutelist: str,
    findings: list[dict[str, Any]],
    exceptions: list[dict[str, Any]],
) -> None:
    opa_doc = {
        "cloudsentinel": {
            "prowler_exceptions": {
                "schema_version": _SCHEMA_VERSION,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "source": "defectdojo",
                "meta": {
                    "engagement_scope": "shift-right",
                    "fetched_findings_count": len(findings),
                    "exception_count": len(exceptions),
                },
                "exceptions": exceptions,
            }
        }
    }

    exc_path = pathlib.Path(output_exceptions)
    exc_path.parent.mkdir(parents=True, exist_ok=True)
    exc_path.write_text(json.dumps(opa_doc, indent=2) + "\n", encoding="utf-8")

    ml_path = pathlib.Path(output_mutelist)
    ml_path.parent.mkdir(parents=True, exist_ok=True)
    ml_path.write_text(build_mutelist_yaml(findings), encoding="utf-8")


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
        default=os.getenv(
            "DOJO_ENGAGEMENT_ID_RIGHT",
            os.getenv(
                "DEFECTDOJO_ENGAGEMENT_ID_RIGHT",
                os.getenv("DOJO_ENGAGEMENT_ID", os.getenv("DEFECTDOJO_ENGAGEMENT_ID_LEFT", "")),
            ),
        ),
    )
    parser.add_argument("--dry-run", action="store_true", help="Print outputs without writing files")
    args = parser.parse_args(argv)

    if not args.base_url:
        print("[fetch-prowler-exc][ERROR] DOJO_URL/DEFECTDOJO_URL is required.", file=sys.stderr)
        return 1
    if not args.api_key:
        print("[fetch-prowler-exc][ERROR] DOJO_API_KEY/DEFECTDOJO_API_KEY is required.", file=sys.stderr)
        return 1
    if not args.engagement:
        print(
            "[fetch-prowler-exc][ERROR] DOJO_ENGAGEMENT_ID_RIGHT/DEFECTDOJO_ENGAGEMENT_ID_RIGHT is required.",
            file=sys.stderr,
        )
        return 1

    try:
        findings = fetch_accepted_prowler_findings(args.base_url, args.api_key, args.engagement)
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else None
        print(
            f"[fetch-prowler-exc][ERROR] DefectDojo HTTP error (status={status}): {exc}",
            file=sys.stderr,
        )
        return 1
    except Exception as exc:
        print(f"[fetch-prowler-exc][ERROR] DefectDojo fetch failed: {exc}", file=sys.stderr)
        return 1

    exceptions = build_opa_exceptions(findings)

    if args.dry_run:
        print("=== OPA exceptions ===")
        print(
            json.dumps(
                {
                    "cloudsentinel": {
                        "prowler_exceptions": {
                            "schema_version": _SCHEMA_VERSION,
                            "generated_at": datetime.now(timezone.utc).isoformat(),
                            "source": "defectdojo",
                            "meta": {
                                "engagement_scope": "shift-right",
                                "fetched_findings_count": len(findings),
                                "exception_count": len(exceptions),
                            },
                            "exceptions": exceptions,
                        }
                    }
                },
                indent=2,
            )
        )
        print("=== Mutelist YAML ===")
        print(build_mutelist_yaml(findings))
        return 0

    _write_outputs(args.output_exceptions, args.output_mutelist, findings, exceptions)
    print(f"[fetch-prowler-exc] Written {len(exceptions)} exception(s) → {args.output_exceptions}")
    print(f"[fetch-prowler-exc] Written mutelist ({len(findings)} accepted finding(s)) → {args.output_mutelist}")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
