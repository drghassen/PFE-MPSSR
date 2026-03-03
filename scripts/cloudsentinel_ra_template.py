#!/usr/bin/env python3
"""Build and optionally POST CloudSentinel-compatible DefectDojo risk acceptances."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

DEFAULT_TEMPLATE_PATH = "defectdojo/risk_acceptance_template.json"
DEFAULT_REPORT_CANDIDATES = (
    ".cloudsentinel/checkov_opa.json",
    ".cloudsentinel/golden_report.json",
)

ALLOWED_SCOPE_TYPES = {"commit", "branch", "repo", "global"}
ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
ALLOWED_APPROVER_ROLES = {
    "APPSEC_L1",
    "APPSEC_L2",
    "APPSEC_L3",
    "APPSEC_MANAGER",
    "SECURITY_MANAGER",
}


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def to_rfc3339(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_datetime(value: str) -> datetime:
    raw = (value or "").strip()
    if not raw:
        raise ValueError("empty datetime")
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
        return datetime.strptime(raw, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    normalized = raw.replace("Z", "+00:00")
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def valid_email(value: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value.strip().lower()))


def safe_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        doc = json.load(f)
    if not isinstance(doc, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return doc


def default_template() -> Dict[str, Any]:
    return {
        "defaults": {
            "rule_id": "CKV2_CS_AZ_021",
            "scanner": "checkov",
            "scope_type": "branch",
            "severity": "CRITICAL",
            "requested_by": "dev-system@example.com",
            "approved_by": "appsec-system@example.com",
            "approved_by_role": "APPSEC_L2",
            "break_glass": False,
            "incident_id": "",
        },
        "defectdojo": {
            "is_active": True,
            "name_prefix": "Accept",
        },
    }


def load_template(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return default_template()
    template = load_json(path)
    defaults = template.get("defaults", {})
    dojo = template.get("defectdojo", {})
    if not isinstance(defaults, dict) or not isinstance(dojo, dict):
        raise ValueError("template must include object fields: defaults and defectdojo")
    merged = default_template()
    merged["defaults"].update(defaults)
    merged["defectdojo"].update(dojo)
    return merged


def deterministic_fingerprint(rule_id: str, resource_id: str) -> str:
    data = f"{rule_id}:{resource_id}".encode("utf-8")
    digest = hashlib.sha256(data).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def finding_iter(report: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    findings = report.get("findings", [])
    if isinstance(findings, list):
        for item in findings:
            if isinstance(item, dict):
                yield item


def finding_rule_id(finding: Dict[str, Any]) -> str:
    direct = safe_str(finding.get("id"))
    if direct:
        return direct
    return safe_str(finding.get("source", {}).get("id"))


def finding_resource_id(finding: Dict[str, Any]) -> str:
    resource = finding.get("resource", {})
    if isinstance(resource, dict):
        value = safe_str(resource.get("name"))
        if value:
            return value
    return safe_str(finding.get("resource_id"))


def finding_fingerprint(finding: Dict[str, Any]) -> str:
    direct = safe_str(finding.get("fingerprint"))
    if direct:
        return direct
    context = finding.get("context", {})
    if isinstance(context, dict):
        dedup = context.get("deduplication", {})
        if isinstance(dedup, dict):
            return safe_str(dedup.get("fingerprint"))
    return ""


def resolve_report_paths(base_dir: Path, cli_report: Optional[str]) -> List[Path]:
    if cli_report:
        return [Path(cli_report).expanduser().resolve()]
    return [(base_dir / p).resolve() for p in DEFAULT_REPORT_CANDIDATES]


def lookup_fingerprint(rule_id: str, resource_id: str, reports: List[Path]) -> Tuple[str, str]:
    target_rule = rule_id.upper()
    for report_path in reports:
        if not report_path.exists():
            continue
        try:
            report = load_json(report_path)
        except Exception:
            continue
        for finding in finding_iter(report):
            rid = finding_rule_id(finding).upper()
            rsrc = finding_resource_id(finding)
            if rid == target_rule and rsrc == resource_id:
                fp = finding_fingerprint(finding)
                if fp:
                    return fp, str(report_path)
    return "", ""


def normalize_csv_ids(raw: str) -> List[int]:
    if not raw:
        return []
    out: List[int] = []
    for part in raw.split(","):
        text = part.strip()
        if not text:
            continue
        out.append(int(text))
    return out


def validate_fields(fields: Dict[str, Any]) -> None:
    if fields["scope_type"] not in ALLOWED_SCOPE_TYPES:
        raise ValueError(f"invalid scope_type: {fields['scope_type']}")
    if fields["severity"] not in ALLOWED_SEVERITIES:
        raise ValueError(f"invalid severity: {fields['severity']}")
    if fields["approved_by_role"] not in ALLOWED_APPROVER_ROLES:
        raise ValueError(f"invalid approved_by_role: {fields['approved_by_role']}")
    if not valid_email(fields["requested_by"]):
        raise ValueError(f"invalid requested_by email: {fields['requested_by']}")
    if not valid_email(fields["approved_by"]):
        raise ValueError(f"invalid approved_by email: {fields['approved_by']}")
    if fields["requested_by"].lower() == fields["approved_by"].lower():
        raise ValueError("requested_by must be different from approved_by")
    if fields["scope_type"] == "branch" and not fields["branch_scope"]:
        raise ValueError("branch_scope is required when scope_type=branch")
    if fields["break_glass"] and not fields["incident_id"]:
        raise ValueError("incident_id is required when break_glass=true")
    if parse_datetime(fields["expires_at"]) <= now_utc():
        raise ValueError("expires_at must be in the future")


def build_fields(args: argparse.Namespace, template: Dict[str, Any], report_paths: List[Path]) -> Tuple[Dict[str, Any], str]:
    defaults = template["defaults"]

    rule_id = safe_str(args.rule_id or defaults.get("rule_id")).upper()
    scanner = safe_str(args.scanner or defaults.get("scanner")).lower() or "checkov"
    scope_type = safe_str(args.scope_type or defaults.get("scope_type")).lower() or "repo"
    severity = safe_str(args.severity or defaults.get("severity")).upper() or "HIGH"

    requested_by = safe_str(args.requested_by or defaults.get("requested_by"))
    approved_by = safe_str(args.approved_by or defaults.get("approved_by"))
    approved_by_role = safe_str(args.approved_by_role or defaults.get("approved_by_role")).upper()

    break_glass = bool(args.break_glass if args.break_glass is not None else defaults.get("break_glass", False))
    incident_id = safe_str(args.incident_id or defaults.get("incident_id", ""))

    expires_at = to_rfc3339(parse_datetime(args.expires_at))
    created_at = to_rfc3339(now_utc())

    fingerprint = safe_str(args.fingerprint)
    source_hint = ""
    if not fingerprint:
        fingerprint, source_hint = lookup_fingerprint(rule_id, args.resource_id, report_paths)
    if not fingerprint:
        fingerprint = deterministic_fingerprint(rule_id, args.resource_id)
        source_hint = "deterministic-fallback"

    fields = {
        "name": rule_id,
        "rule_id": rule_id,
        "check_id": rule_id,
        "scanner": scanner,
        "tool": scanner,
        "resource_id": args.resource_id,
        "resource_name": args.resource_id,
        "fingerprint": fingerprint,
        "resource_hash": fingerprint,
        "scope_type": scope_type,
        "branch_scope": args.branch_scope,
        "repo": args.repo,
        "severity": severity,
        "requested_by": requested_by,
        "approved_by": approved_by,
        "approved_by_role": approved_by_role,
        "justification": args.justification,
        "expires_at": expires_at,
        "break_glass": break_glass,
        "incident_id": incident_id,
        "created_at": created_at,
        "approved_at": None,
    }
    validate_fields(fields)
    return fields, source_hint


def build_defectdojo_payload(fields: Dict[str, Any], template: Dict[str, Any], accepted_findings: List[int], owner_id: Optional[int]) -> Dict[str, Any]:
    dojo_cfg = template["defectdojo"]
    name_prefix = safe_str(dojo_cfg.get("name_prefix"))
    payload_name = f"{name_prefix}: {fields['rule_id']}" if name_prefix else fields["rule_id"]

    custom_fields: Dict[str, Any] = {
        "rule_id": fields["rule_id"],
        "check_id": fields["check_id"],
        "scanner": fields["scanner"],
        "tool": fields["tool"],
        "resource_id": fields["resource_id"],
        "resource_name": fields["resource_name"],
        "fingerprint": fields["fingerprint"],
        "resource_hash": fields["resource_hash"],
        "scope_type": fields["scope_type"],
        "branch_scope": fields["branch_scope"],
        "repo": fields["repo"],
        "severity": fields["severity"],
        "requested_by": fields["requested_by"],
        "approved_by": fields["approved_by"],
        "approved_by_role": fields["approved_by_role"],
        "justification": fields["justification"],
        "expires_at": fields["expires_at"],
        "break_glass": fields["break_glass"],
    }
    if fields["incident_id"]:
        custom_fields["incident_id"] = fields["incident_id"]
    if fields.get("created_at"):
        custom_fields["created_at"] = fields["created_at"]
    if fields.get("approved_at"):
        custom_fields["approved_at"] = fields["approved_at"]

    payload: Dict[str, Any] = {
        "name": payload_name,
        "description": fields["justification"],
        "path": fields["resource_id"],
        "recommendation_details": fields["fingerprint"],
        "expiration_date": fields["expires_at"],
        "is_active": bool(dojo_cfg.get("is_active", True)),
        "custom_fields": custom_fields,
    }
    if accepted_findings:
        payload["accepted_findings"] = accepted_findings
    if owner_id is not None:
        payload["owner"] = owner_id
    return payload


def post_to_defectdojo(dojo_url: str, dojo_api_key: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    endpoint = f"{dojo_url.rstrip('/')}/api/v2/risk_acceptance/"
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Token {dojo_api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        body = response.read().decode("utf-8")
        return json.loads(body)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create CloudSentinel-compatible DefectDojo Risk Acceptance payloads from a reusable template."
    )
    parser.add_argument("--template", default=DEFAULT_TEMPLATE_PATH, help="Template JSON path")
    parser.add_argument("--report", default="", help="Optional report JSON path for fingerprint lookup")

    parser.add_argument("--resource-id", required=True, help="Resource ID/name (CloudSentinel resource_id)")
    parser.add_argument("--repo", required=True, help="Repository path/name")
    parser.add_argument("--branch-scope", required=True, help="Branch scope value (or * for repo/global)")
    parser.add_argument("--justification", required=True, help="Exception justification")
    parser.add_argument("--expires-at", required=True, help="Expiration datetime (YYYY-MM-DD or RFC3339)")

    parser.add_argument("--rule-id", default="", help="Override rule/check id")
    parser.add_argument("--scanner", default="", help="Override scanner/tool")
    parser.add_argument("--scope-type", default="", help="Override scope_type")
    parser.add_argument("--severity", default="", help="Override severity")
    parser.add_argument("--requested-by", default="", help="Override requested_by email")
    parser.add_argument("--approved-by", default="", help="Override approved_by email")
    parser.add_argument("--approved-by-role", default="", help="Override approved_by_role")
    parser.add_argument("--fingerprint", default="", help="Explicit fingerprint/resource_hash")
    parser.add_argument("--incident-id", default="", help="Incident ID for break-glass")

    parser.add_argument("--break-glass", action="store_true", help="Set break_glass=true")
    parser.add_argument("--accepted-findings", default="", help="Comma-separated DefectDojo finding IDs")
    parser.add_argument("--owner-id", type=int, default=None, help="Optional DefectDojo owner user ID")

    parser.add_argument("--post", action="store_true", help="POST payload to DefectDojo")
    parser.add_argument("--output", default="", help="Write payload JSON to file")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    repo_root = Path.cwd()
    template_path = Path(args.template).expanduser().resolve()
    template = load_template(template_path)
    report_paths = resolve_report_paths(repo_root, args.report)

    fields, source_hint = build_fields(args, template, report_paths)
    accepted_findings = normalize_csv_ids(args.accepted_findings)
    payload = build_defectdojo_payload(fields, template, accepted_findings, args.owner_id)

    if args.output:
        out_path = Path(args.output).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(json.dumps(payload, indent=2))

    if source_hint == "deterministic-fallback":
        print(
            "[WARN] Fingerprint not found in scan report; deterministic fallback used "
            "(may not match OPA fingerprint-exact logic).",
            file=sys.stderr,
        )
    elif source_hint:
        print(f"[INFO] Fingerprint sourced from {source_hint}", file=sys.stderr)

    if args.post:
        dojo_url = os.environ.get("DOJO_URL", "").strip()
        dojo_api_key = os.environ.get("DOJO_API_KEY", "").strip()
        if not dojo_url or not dojo_api_key:
            raise SystemExit("DOJO_URL and DOJO_API_KEY are required for --post")
        try:
            response = post_to_defectdojo(dojo_url, dojo_api_key, payload)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise SystemExit(f"DefectDojo POST failed ({exc.code}): {body}") from exc
        except urllib.error.URLError as exc:
            raise SystemExit(f"DefectDojo POST failed: {exc}") from exc
        print(json.dumps({"post_status": "ok", "risk_acceptance": response}, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

