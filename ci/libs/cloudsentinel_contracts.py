#!/usr/bin/env python3
"""Shared CloudSentinel contract utilities for CI and local verification.

This module centralizes duplicated logic used by shell wrappers:
- Trivy sub-scan merge (fs/config/image -> trivy_opa.json)
- JSON schema validation
- Scanner wrapper contract validation
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


SEV_KEYS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "TOTAL", "EXEMPTED", "FAILED", "PASSED"]
BY_TYPE_KEYS = ["vulnerability", "secret", "misconfig"]
BY_CAT_KEYS = ["INFRASTRUCTURE", "APPLICATION", "CONFIGURATION", "SECRET"]


def _empty_stats() -> Dict[str, Any]:
    return {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
        "TOTAL": 0,
        "EXEMPTED": 0,
        "FAILED": 0,
        "PASSED": 0,
        "by_type": {k: 0 for k in BY_TYPE_KEYS},
        "by_category": {k: 0 for k in BY_CAT_KEYS},
    }


def _load_trivy_report(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {"status": "NOT_RUN", "errors": [f"missing_report:{path}"], "findings": [], "stats": {"TOTAL": 0}}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"status": "NOT_RUN", "errors": [f"invalid_json:{path}"], "findings": [], "stats": {"TOTAL": 0}}


def merge_trivy_reports(
    fs_path: Path,
    config_path: Path,
    out_path: Path,
    image_path: Optional[Path] = None,  # optional: image scan removed from pipeline
) -> Dict[str, Any]:
    loaded: Dict[str, Any] = {
        "fs":     _load_trivy_report(fs_path),
        "config": _load_trivy_report(config_path),
    }
    if image_path is not None:
        loaded["image"] = _load_trivy_report(image_path)
    else:
        # Image scan jobs removed from pipeline (monitoring via DefectDojo only).
        # Do not mark as NOT_RUN — only fs and config are required.
        pass

    required_scans = {k: v for k, v in loaded.items() if k in ("fs", "config")}
    any_not_run = any(str(r.get("status", "")).upper() == "NOT_RUN" for r in required_scans.values())
    if any_not_run:
        errors: List[str] = []
        for name, report in loaded.items():
            if str(report.get("status", "")).upper() != "NOT_RUN":
                continue
            errs = report.get("errors", [])
            if isinstance(errs, list):
                errors.extend([f"{name}:{err}" for err in errs])
            else:
                errors.append(f"{name}:not_run")
        merged = {
            "tool": "trivy",
            "version": "multi",
            "status": "NOT_RUN",
            "errors": errors or ["trivy_subscan_not_run"],
            "has_findings": False,
            "stats": _empty_stats(),
            "findings": [],
        }
    else:
        findings: List[Dict[str, Any]] = []
        stats = {k: 0 for k in SEV_KEYS}
        by_type = {k: 0 for k in BY_TYPE_KEYS}
        by_cat = {k: 0 for k in BY_CAT_KEYS}

        for report in loaded.values():
            findings.extend(report.get("findings", []))
            report_stats = report.get("stats", {}) or {}
            for key in SEV_KEYS:
                stats[key] += int(report_stats.get(key, 0) or 0)
            for key in BY_TYPE_KEYS:
                by_type[key] += int(((report_stats.get("by_type", {}) or {}).get(key, 0)) or 0)
            for key in BY_CAT_KEYS:
                by_cat[key] += int(((report_stats.get("by_category", {}) or {}).get(key, 0)) or 0)

        stats["by_type"] = by_type
        stats["by_category"] = by_cat
        merged = {
            "tool": "trivy",
            "version": "multi",
            "status": "OK",
            "errors": [],
            "has_findings": len(findings) > 0,
            "stats": stats,
            "findings": findings,
        }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
    return merged


def validate_schema(document: Path, schema: Path) -> None:
    from jsonschema import Draft7Validator, validate

    doc = json.loads(document.read_text(encoding="utf-8"))
    sch = json.loads(schema.read_text(encoding="utf-8"))
    Draft7Validator.check_schema(sch)
    validate(doc, sch)


def validate_scanner_contract(reports: Iterable[Path]) -> None:
    required = {"tool", "version", "status", "findings", "errors"}
    for report in reports:
        doc = json.loads(report.read_text(encoding="utf-8"))
        missing = sorted(required.difference(doc.keys()))
        if missing:
            raise SystemExit(f"[contract] {report} missing fields: {missing}")
        if doc["status"] not in {"OK", "NOT_RUN"}:
            raise SystemExit(f"[contract] {report} invalid status: {doc['status']}")
        if not isinstance(doc["findings"], list):
            raise SystemExit(f"[contract] {report} findings must be array")
        if not isinstance(doc["errors"], list):
            raise SystemExit(f"[contract] {report} errors must be array")


def _parse_merge_args(sub: argparse.ArgumentParser) -> None:
    sub.add_argument("--fs", required=True, type=Path, help="Path to trivy fs OPA wrapper report")
    sub.add_argument("--config", required=True, type=Path, help="Path to trivy config OPA wrapper report")
    sub.add_argument("--image", required=False, default=None, type=Path, help="Path to trivy image OPA wrapper report (optional: image scan removed from pipeline)")
    sub.add_argument("--output", required=True, type=Path, help="Merged trivy OPA output path")


def _parse_validate_schema_args(sub: argparse.ArgumentParser) -> None:
    sub.add_argument("--document", required=True, type=Path, help="JSON document path")
    sub.add_argument("--schema", required=True, type=Path, help="JSON schema path")
    sub.add_argument(
        "--success-message",
        default="[contract] schema validation passed",
        help="Message printed on successful validation",
    )


def _parse_validate_contract_args(sub: argparse.ArgumentParser) -> None:
    sub.add_argument("--report", action="append", required=True, type=Path, help="OPA wrapper report path")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CloudSentinel shared contract utilities")
    sub = parser.add_subparsers(dest="command", required=True)

    merge_cmd = sub.add_parser("merge-trivy", help="Merge trivy fs/config/image OPA wrapper reports")
    _parse_merge_args(merge_cmd)

    schema_cmd = sub.add_parser("validate-schema", help="Validate a JSON document against a JSON schema")
    _parse_validate_schema_args(schema_cmd)

    contract_cmd = sub.add_parser(
        "validate-scanner-contract",
        help="Validate scanner wrapper reports contract fields and status values",
    )
    _parse_validate_contract_args(contract_cmd)
    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "merge-trivy":
        merged = merge_trivy_reports(args.fs, args.config, args.output, image_path=args.image)
        status = merged.get("status", "unknown")
        total = int((merged.get("stats", {}) or {}).get("TOTAL", 0) or 0)
        print(f"[normalize] merged trivy subscans -> {args.output} (status={status}, total={total})")
        return 0

    if args.command == "validate-schema":
        validate_schema(args.document, args.schema)
        print(args.success_message)
        return 0

    if args.command == "validate-scanner-contract":
        validate_scanner_contract(args.report)
        print("[contract] scanner wrapper contract passed")
        return 0

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
