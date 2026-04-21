#!/usr/bin/env python3
"""Shared CloudSentinel contract utilities for CI and local verification.

This module centralizes duplicated logic used by shell wrappers:
- Trivy sub-scan merge (fs/config/image -> trivy_opa.json)
- JSON schema validation
- Scanner wrapper contract validation
- Artifact contract enforcement (detection/normalization/decision)
- Raw artifact metadata stamping (scan_id/scan_status/executed_targets)
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


SEV_KEYS = [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFO",
    "TOTAL",
    "EXEMPTED",
    "FAILED",
    "PASSED",
]
BY_TYPE_KEYS = ["vulnerability", "secret", "misconfig"]
BY_CAT_KEYS = ["INFRASTRUCTURE", "APPLICATION", "CONFIGURATION", "SECRET"]
SCAN_STATUS_VALUES = {"success", "failure"}


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


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run(cmd: List[str]) -> str:
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return ""


def _resolve_scan_id(explicit: Optional[str] = None) -> str:
    if explicit and explicit.strip():
        return explicit.strip()
    env_scan_id = os.environ.get("CLOUDSENTINEL_SCAN_ID", "").strip()
    if env_scan_id:
        return env_scan_id
    ci_commit = os.environ.get("CI_COMMIT_SHA", "").strip()
    if ci_commit:
        return ci_commit
    git_sha = _run(["git", "rev-parse", "HEAD"])
    if git_sha:
        return git_sha
    return ""


def _is_scan_id_valid(value: str) -> bool:
    if not value:
        return False
    sha_re = re.compile(r"^[0-9a-fA-F]{7,64}$")
    uuid_re = re.compile(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
    )
    return bool(sha_re.fullmatch(value) or uuid_re.fullmatch(value))


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_jsonl(path: Path) -> List[Any]:
    out: List[Any] = []
    with path.open("r", encoding="utf-8") as handle:
        for index, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                out.append(json.loads(stripped))
            except Exception as exc:
                raise ValueError(f"invalid_jsonl_line:{index}:{exc}") from exc
    return out


def _ensure_scan_metadata(
    doc: Dict[str, Any],
    *,
    tool: str,
    scan_id: str,
    findings_count: int,
    executed_targets: List[str],
    scan_status: str,
) -> Dict[str, Any]:
    stamped = dict(doc)
    stamped["scan_id"] = scan_id
    stamped["scan_completed"] = True
    stamped["scan_status"] = scan_status
    stamped["findings_count"] = max(findings_count, 0)
    stamped["executed_targets"] = [t for t in executed_targets if t]

    metadata = stamped.get("scan_metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    metadata.update(
        {
            "tool": tool,
            "scan_id": scan_id,
            "scan_completed": True,
            "scan_status": scan_status,
            "findings_count": max(findings_count, 0),
            "executed_targets": [t for t in executed_targets if t],
            "scanned_at": _now_utc(),
        }
    )
    stamped["scan_metadata"] = metadata
    return stamped


def _count_trivy_findings(doc: Dict[str, Any]) -> int:
    total = 0
    results = doc.get("Results")
    if not isinstance(results, list):
        return 0
    for item in results:
        if not isinstance(item, dict):
            continue
        for key in ("Vulnerabilities", "Misconfigurations", "Secrets"):
            values = item.get(key)
            if isinstance(values, list):
                total += len(values)
    return total


def stamp_artifact_metadata(
    artifact: Path,
    tool: str,
    executed_targets: List[str],
    scan_status: str,
    scan_id: str,
) -> Dict[str, Any]:
    if not artifact.exists():
        raise SystemExit(f"[contract] artifact not found: {artifact}")
    if scan_status not in SCAN_STATUS_VALUES:
        raise SystemExit(
            f"[contract] invalid scan status '{scan_status}', expected one of {sorted(SCAN_STATUS_VALUES)}"
        )

    doc = _load_json(artifact)
    targets = [t.strip() for t in executed_targets if t.strip()]
    if not targets:
        targets = ["."]

    if tool == "gitleaks":
        findings: List[Any]
        base: Dict[str, Any]
        if isinstance(doc, list):
            findings = doc
            base = {}
        elif isinstance(doc, dict):
            base = dict(doc)
            raw_findings = base.get("findings", base.get("leaks", []))
            if not isinstance(raw_findings, list):
                raise SystemExit(
                    "[contract] gitleaks raw artifact must contain 'findings' JSON array"
                )
            findings = raw_findings
        else:
            raise SystemExit("[contract] gitleaks raw artifact must be array/object")

        stamped = _ensure_scan_metadata(
            base,
            tool=tool,
            scan_id=scan_id,
            findings_count=len(findings),
            executed_targets=targets,
            scan_status=scan_status,
        )
        stamped["tool"] = "gitleaks"
        stamped["findings"] = findings

    elif tool == "checkov":
        if not isinstance(doc, dict):
            raise SystemExit("[contract] checkov raw artifact must be JSON object")
        failed_checks = ((doc.get("results") or {}).get("failed_checks", []))
        findings_count = len(failed_checks) if isinstance(failed_checks, list) else 0
        stamped = _ensure_scan_metadata(
            doc,
            tool=tool,
            scan_id=scan_id,
            findings_count=findings_count,
            executed_targets=targets,
            scan_status=scan_status,
        )

    elif tool == "trivy":
        if not isinstance(doc, dict):
            raise SystemExit("[contract] trivy raw artifact must be JSON object")
        # Trivy may emit Results as null for clean/empty target contexts depending on scan mode.
        # Normalize to [] to keep the contract deterministic.
        if doc.get("Results", "__missing__") is None:
            doc["Results"] = []
        elif "Results" not in doc and isinstance(doc.get("results"), list):
            doc["Results"] = doc.get("results")
        stamped = _ensure_scan_metadata(
            doc,
            tool=tool,
            scan_id=scan_id,
            findings_count=_count_trivy_findings(doc),
            executed_targets=targets,
            scan_status=scan_status,
        )

    elif tool == "cloudinit":
        if not isinstance(doc, dict):
            raise SystemExit("[contract] cloudinit raw artifact must be JSON object")
        findings_count = int((doc.get("summary") or {}).get("total_violations", 0) or 0)
        stamped = _ensure_scan_metadata(
            doc,
            tool=tool,
            scan_id=scan_id,
            findings_count=findings_count,
            executed_targets=targets,
            scan_status=scan_status,
        )

    else:
        raise SystemExit(f"[contract] unsupported tool for stamping: {tool}")

    artifact.write_text(json.dumps(stamped, indent=2), encoding="utf-8")
    return stamped


def _load_trivy_report(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {
            "status": "NOT_RUN",
            "errors": [f"missing_report:{path}"],
            "findings": [],
            "stats": {"TOTAL": 0},
        }
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {
            "status": "NOT_RUN",
            "errors": [f"invalid_json:{path}"],
            "findings": [],
            "stats": {"TOTAL": 0},
        }


def merge_trivy_reports(
    fs_path: Path,
    config_path: Path,
    out_path: Path,
    image_path: Optional[Path] = None,  # optional: image scan removed from pipeline
) -> Dict[str, Any]:
    loaded: Dict[str, Any] = {
        "fs": _load_trivy_report(fs_path),
        "config": _load_trivy_report(config_path),
    }
    if image_path is not None:
        loaded["image"] = _load_trivy_report(image_path)

    required_scans = {k: v for k, v in loaded.items() if k in ("fs", "config")}
    any_not_run = any(
        str(r.get("status", "")).upper() == "NOT_RUN" for r in required_scans.values()
    )
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
                by_type[key] += int(
                    ((report_stats.get("by_type", {}) or {}).get(key, 0)) or 0
                )
            for key in BY_CAT_KEYS:
                by_cat[key] += int(
                    ((report_stats.get("by_category", {}) or {}).get(key, 0)) or 0
                )

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


def _build_artifact_result(spec: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": spec.get("id", "unknown"),
        "path": spec.get("path", ""),
        "status": "passed",
        "errors": [],
        "details": {},
    }


def _fail(result: Dict[str, Any], error: str) -> None:
    result["status"] = "failed"
    result["errors"].append(error)


def _extract_scan_id(doc: Any, artifact_id: str) -> str:
    if artifact_id == "golden_report":
        if isinstance(doc, dict):
            top_value = doc.get("scan_id")
            if top_value is not None and str(top_value).strip():
                return str(top_value).strip()
            metadata = doc.get("metadata")
            if isinstance(metadata, dict):
                value = metadata.get("scan_id")
                return str(value).strip() if value is not None else ""
        return ""
    if artifact_id == "opa_decision":
        if isinstance(doc, dict):
            value = doc.get("scan_id")
            return str(value).strip() if value is not None else ""
        return ""
    if isinstance(doc, dict):
        value = doc.get("scan_id")
        return str(value).strip() if value is not None else ""
    return ""


def _validate_scan_context_fields(result: Dict[str, Any], doc: Dict[str, Any]) -> None:
    scan_id = str(doc.get("scan_id", "")).strip()
    scan_completed = doc.get("scan_completed")
    scan_status = str(doc.get("scan_status", "")).strip().lower()
    findings_count = doc.get("findings_count")
    executed_targets = doc.get("executed_targets")

    if not scan_id:
        _fail(result, "missing_scan_id")
    elif not _is_scan_id_valid(scan_id):
        _fail(result, f"invalid_scan_id_format:{scan_id}")

    if scan_completed is not True:
        _fail(result, "scan_completed_must_be_true")

    if scan_status not in SCAN_STATUS_VALUES:
        _fail(result, "invalid_scan_status")

    if not isinstance(findings_count, int) or findings_count < 0:
        _fail(result, "invalid_findings_count")

    if not isinstance(executed_targets, list) or not executed_targets:
        _fail(result, "executed_targets_required")


def _has_scan_context_evidence(doc: Dict[str, Any]) -> bool:
    scan_id = str(doc.get("scan_id", "")).strip()
    scan_status = str(doc.get("scan_status", "")).strip().lower()
    executed_targets = doc.get("executed_targets")
    if not scan_id or not _is_scan_id_valid(scan_id):
        return False
    if scan_status not in SCAN_STATUS_VALUES:
        return False
    if not isinstance(executed_targets, list) or not executed_targets:
        return False
    return True


def _validate_detection_artifact(
    result: Dict[str, Any],
    doc: Any,
) -> None:
    artifact_id = result["id"]

    if artifact_id == "gitleaks_raw":
        if not isinstance(doc, dict):
            _fail(result, "gitleaks_raw_must_be_json_object")
            return
        findings = doc.get("findings")
        if not isinstance(findings, list):
            _fail(result, "gitleaks_raw_findings_must_be_array")
            return
        _validate_scan_context_fields(result, doc)
        _metadata = doc.get("scan_metadata")
        if not isinstance(_metadata, dict) and doc.get("scan_completed") is not True:
            _fail(result, "gitleaks_requires_scan_metadata_or_scan_completed_true")
        findings_count = doc.get("findings_count", -1)
        if isinstance(findings_count, int) and findings_count != len(findings):
            _fail(result, "gitleaks_findings_count_mismatch")
        if len(findings) == 0 and doc.get("scan_status") != "success":
            _fail(result, "gitleaks_empty_findings_requires_success_status")
        result["details"]["findings_count"] = len(findings)
        return

    if artifact_id == "checkov_raw":
        if not isinstance(doc, dict):
            _fail(result, "checkov_raw_must_be_object")
            return
        results = doc.get("results")
        if not isinstance(results, dict):
            _fail(result, "checkov_results_missing")
            return
        _validate_scan_context_fields(result, doc)

        evidence_keys = ["failed_checks", "passed_checks", "skipped_checks", "parsing_errors"]
        has_evidence = any(isinstance(results.get(key), list) for key in evidence_keys)
        if not has_evidence and not _has_scan_context_evidence(doc):
            _fail(result, "checkov_executed_scan_evidence_missing")

        failed_checks = results.get("failed_checks", [])
        failed_count = len(failed_checks) if isinstance(failed_checks, list) else 0
        if doc.get("findings_count") != failed_count:
            _fail(result, "checkov_findings_count_mismatch")
        result["details"]["findings_count"] = failed_count
        return

    if artifact_id in {"trivy_fs_raw", "trivy_config_raw"}:
        if not isinstance(doc, dict):
            _fail(result, "trivy_raw_must_be_object")
            return
        results = doc.get("Results")
        if results is None and _has_scan_context_evidence(doc):
            results = []
            result["details"]["results_coerced_from_null"] = True
        elif "Results" not in doc and isinstance(doc.get("results"), list) and _has_scan_context_evidence(doc):
            results = doc.get("results")
            result["details"]["results_coerced_from_lowercase"] = True
        if not isinstance(results, list):
            _fail(result, "trivy_results_must_be_array")
            return
        _validate_scan_context_fields(result, doc)

        nested_findings = _count_trivy_findings(doc)
        if doc.get("findings_count") != nested_findings:
            _fail(result, "trivy_findings_count_mismatch")
        if len(results) == 0 and doc.get("scan_status") != "success":
            _fail(result, "trivy_empty_results_requires_success_status")
        result["details"]["findings_count"] = nested_findings
        result["details"]["results_count"] = len(results)
        return

    if artifact_id == "cloudinit_analysis":
        if not isinstance(doc, dict):
            _fail(result, "cloudinit_analysis_must_be_object")
            return
        resources = doc.get("resources_analyzed")
        summary = doc.get("summary")
        if not isinstance(resources, list):
            _fail(result, "cloudinit_resources_analyzed_must_be_array")
        if not isinstance(summary, dict):
            _fail(result, "cloudinit_summary_missing")
            return
        _validate_scan_context_fields(result, doc)

        computed = 0
        for resource in resources if isinstance(resources, list) else []:
            if isinstance(resource, dict):
                violations = resource.get("violations", [])
                if isinstance(violations, list):
                    computed += len(violations)
        if doc.get("findings_count") != computed:
            _fail(result, "cloudinit_findings_count_mismatch")
        result["details"]["findings_count"] = computed
        return

    _fail(result, f"unknown_detection_artifact:{artifact_id}")


def _validate_golden_report(
    result: Dict[str, Any],
    doc: Any,
    schema_path: Optional[Path],
    artifact_path: Path,
) -> None:
    if not isinstance(doc, dict):
        _fail(result, "golden_report_must_be_object")
        return

    if schema_path is not None:
        try:
            validate_schema(artifact_path, schema_path)
        except Exception as exc:
            _fail(result, f"golden_report_schema_validation_failed:{exc}")

    metadata = doc.get("metadata")
    if not isinstance(metadata, dict):
        _fail(result, "golden_report_metadata_missing")
        return

    top_scan_id = str(doc.get("scan_id", "")).strip()
    if not top_scan_id:
        _fail(result, "golden_report_top_level_scan_id_missing")
    elif not _is_scan_id_valid(top_scan_id):
        _fail(result, f"golden_report_top_level_scan_id_invalid:{top_scan_id}")

    top_scan_status = str(doc.get("scan_status", "")).strip().lower()
    if top_scan_status not in SCAN_STATUS_VALUES:
        _fail(result, "golden_report_scan_status_invalid")

    scan_id = str(metadata.get("scan_id", "")).strip()
    if not scan_id:
        _fail(result, "golden_report_missing_scan_id")
    elif not _is_scan_id_valid(scan_id):
        _fail(result, f"golden_report_invalid_scan_id_format:{scan_id}")
    elif top_scan_id and top_scan_id != scan_id:
        _fail(result, "golden_report_scan_id_mismatch_top_vs_metadata")

    executed_scanners = metadata.get("executed_scanners")
    if not isinstance(executed_scanners, list) or not executed_scanners:
        _fail(result, "golden_report_executed_scanners_missing")

    findings = doc.get("findings")
    if not isinstance(findings, list):
        _fail(result, "golden_report_findings_must_be_array")
        return

    summary = doc.get("summary")
    if not isinstance(summary, dict):
        _fail(result, "golden_report_summary_missing")
        return

    global_summary = summary.get("global")
    if not isinstance(global_summary, dict):
        _fail(result, "golden_report_summary_global_missing")
        return

    total = global_summary.get("TOTAL")
    if not isinstance(total, int):
        _fail(result, "golden_report_summary_total_invalid")
    elif total != len(findings):
        _fail(result, "golden_report_not_correlated_summary_total_mismatch")

    scanners = doc.get("scanners")
    by_tool = (summary.get("by_tool") or {}) if isinstance(summary, dict) else {}
    if not isinstance(scanners, dict) or not isinstance(by_tool, dict):
        _fail(result, "golden_report_scanners_or_summary_by_tool_missing")
        return

    for tool in ("gitleaks", "checkov", "trivy", "cloudinit"):
        scanner_entry = scanners.get(tool)
        summary_entry = by_tool.get(tool)
        if not isinstance(scanner_entry, dict) or not isinstance(summary_entry, dict):
            _fail(result, f"golden_report_missing_tool_summary:{tool}")
            continue
        scanner_status = scanner_entry.get("status")
        summary_status = summary_entry.get("status")
        if scanner_status != summary_status:
            _fail(result, f"golden_report_status_mismatch:{tool}")


def _validate_exceptions_json(result: Dict[str, Any], doc: Any) -> None:
    if not isinstance(doc, dict):
        _fail(result, "exceptions_must_be_object")
        return
    cs = doc.get("cloudsentinel")
    if not isinstance(cs, dict):
        _fail(result, "exceptions_missing_cloudsentinel")
        return
    exceptions = cs.get("exceptions")
    if not isinstance(exceptions, dict):
        _fail(result, "exceptions_missing_exceptions_object")
        return
    items = exceptions.get("exceptions")
    if not isinstance(items, list):
        _fail(result, "exceptions_items_must_be_array")


def _validate_opa_decision(result: Dict[str, Any], doc: Any) -> None:
    if not isinstance(doc, dict):
        _fail(result, "opa_decision_must_be_object")
        return
    top_scan_id = str(doc.get("scan_id", "")).strip()
    if not top_scan_id:
        _fail(result, "opa_decision_missing_scan_id")
    elif not _is_scan_id_valid(top_scan_id):
        _fail(result, f"opa_decision_invalid_scan_id_format:{top_scan_id}")

    decision = doc.get("result")
    if not isinstance(decision, dict):
        _fail(result, "opa_decision_missing_result")
        return
    allow = decision.get("allow")
    if not isinstance(allow, bool):
        _fail(result, "opa_decision_result_allow_must_be_boolean")
    if not isinstance(decision.get("deny", []), list):
        _fail(result, "opa_decision_result_deny_must_be_array")
    if not isinstance(decision.get("warn", []), list):
        _fail(result, "opa_decision_result_warn_must_be_array")

    gate = decision.get("_gate")
    if not isinstance(gate, dict):
        _fail(result, "opa_decision_missing_gate_metadata")
        return
    if str(gate.get("scan_id", "")).strip() != top_scan_id:
        _fail(result, "opa_decision_gate_scan_id_mismatch")


def _validate_hmac_file(result: Dict[str, Any], path: Path) -> None:
    try:
        content = path.read_text(encoding="ascii").strip()
    except Exception as exc:
        _fail(result, f"hmac_read_error:{exc}")
        return
    if not re.fullmatch(r"[0-9a-fA-F]{64}", content):
        _fail(result, "hmac_invalid_format")


def _validate_jsonl_audit(
    result: Dict[str, Any],
    lines: List[Any],
    *,
    require_event_type: Optional[str] = None,
) -> None:
    if not lines:
        _fail(result, "audit_log_empty")
        return

    matched_required_event = require_event_type is None
    for idx, item in enumerate(lines, start=1):
        if not isinstance(item, dict):
            _fail(result, f"audit_event_not_object:line_{idx}")
            continue
        timestamp = item.get("timestamp")
        if not isinstance(timestamp, str) or not timestamp.strip():
            _fail(result, f"audit_event_missing_timestamp:line_{idx}")
        scan_id = item.get("scan_id")
        if not isinstance(scan_id, str) or not scan_id.strip():
            _fail(result, f"audit_event_missing_scan_id:line_{idx}")
        elif not _is_scan_id_valid(scan_id.strip()):
            _fail(result, f"audit_event_invalid_scan_id_format:line_{idx}")
        if require_event_type and item.get("event_type") == require_event_type:
            matched_required_event = True

    if not matched_required_event and require_event_type:
        _fail(result, f"audit_log_missing_required_event_type:{require_event_type}")


def _validate_hmac_sidecar(artifact: Path) -> Tuple[bool, str]:
    secret = os.environ.get("CLOUDSENTINEL_HMAC_SECRET", "")
    in_ci = bool(os.environ.get("CI"))

    if not secret:
        if in_ci:
            return False, "missing_hmac_secret_in_ci"
        return True, "hmac_secret_not_set_non_ci_skip"

    sidecar = Path(str(artifact) + ".hmac")
    if not sidecar.is_file():
        return False, f"missing_hmac_sidecar:{sidecar}"

    expected = hmac.new(secret.encode("utf-8"), artifact.read_bytes(), hashlib.sha256).hexdigest()
    actual = sidecar.read_text(encoding="ascii").strip()
    if not hmac.compare_digest(expected, actual):
        return False, "hmac_mismatch"
    return True, "hmac_verified"


def _validate_artifact(
    spec: Dict[str, Any],
    repo_root: Path,
    *,
    schema_path: Optional[Path],
) -> Tuple[Dict[str, Any], Optional[Any], str]:
    result = _build_artifact_result(spec)
    artifact_id = result["id"]
    path = repo_root / result["path"]

    if not path.exists():
        _fail(result, "missing_file")
        return result, None, ""
    if not path.is_file():
        _fail(result, "not_a_file")
        return result, None, ""
    if path.stat().st_size == 0:
        _fail(result, "empty_file")
        return result, None, ""

    payload: Any
    payload_scan_id = ""

    if artifact_id == "golden_report_hmac":
        _validate_hmac_file(result, path)
        return result, None, ""

    if artifact_id in {"audit_events", "decision_audit_events"}:
        try:
            payload = _load_jsonl(path)
        except Exception as exc:
            _fail(result, f"invalid_jsonl:{exc}")
            return result, None, ""

        if artifact_id == "decision_audit_events":
            _validate_jsonl_audit(
                result,
                payload,
                require_event_type="decision_evaluated",
            )
        else:
            _validate_jsonl_audit(result, payload)

        if payload:
            first = payload[0]
            if isinstance(first, dict):
                payload_scan_id = str(first.get("scan_id", "")).strip()
        return result, payload, payload_scan_id

    try:
        payload = _load_json(path)
    except Exception as exc:
        _fail(result, f"invalid_json:{exc}")
        return result, None, ""

    if artifact_id in {
        "gitleaks_raw",
        "checkov_raw",
        "trivy_fs_raw",
        "trivy_config_raw",
        "cloudinit_analysis",
    }:
        _validate_detection_artifact(result, payload)
    elif artifact_id == "golden_report":
        _validate_golden_report(result, payload, schema_path, path)
    elif artifact_id == "exceptions":
        _validate_exceptions_json(result, payload)
    elif artifact_id == "opa_decision":
        _validate_opa_decision(result, payload)
    else:
        _fail(result, f"unknown_artifact:{artifact_id}")

    payload_scan_id = _extract_scan_id(payload, artifact_id)
    return result, payload, payload_scan_id


def validate_artifact_contract(
    contract_path: Path,
    report_path: Path,
    stages: List[str],
    expected_scan_id: Optional[str],
    schema_path: Optional[Path],
) -> Dict[str, Any]:
    repo_root = Path.cwd()
    contract = _load_json(contract_path)
    stage_map = contract.get("stages", {})
    if not isinstance(stage_map, dict) or not stage_map:
        raise SystemExit("[contract] invalid contract file: missing 'stages' object")

    selected_stages = stages or list(stage_map.keys())
    unknown = [stage for stage in selected_stages if stage not in stage_map]
    if unknown:
        raise SystemExit(f"[contract] unknown stages requested: {unknown}")

    reference_scan_id = _resolve_scan_id(expected_scan_id)
    report: Dict[str, Any] = {
        "generated_at": _now_utc(),
        "contract_file": str(contract_path),
        "selected_stages": selected_stages,
        "expected_scan_id": reference_scan_id,
        "status": "passed",
        "summary": {
            "stages": len(selected_stages),
            "artifacts_checked": 0,
            "failed_artifacts": 0,
        },
        "stages": [],
    }

    discovered_scan_ids: List[Tuple[str, str]] = []
    collected_payloads: Dict[str, Any] = {}

    for stage in selected_stages:
        stage_spec = stage_map.get(stage, {})
        artifacts = stage_spec.get("required_artifacts", [])
        if not isinstance(artifacts, list):
            raise SystemExit(
                f"[contract] invalid contract file: stage '{stage}' missing required_artifacts list"
            )

        stage_result = {
            "name": stage,
            "status": "passed",
            "artifacts": [],
        }

        for spec in artifacts:
            if not isinstance(spec, dict):
                stage_result["status"] = "failed"
                report["status"] = "failed"
                report["summary"]["failed_artifacts"] += 1
                continue

            item_result, payload, scan_id = _validate_artifact(
                spec,
                repo_root,
                schema_path=schema_path,
            )
            report["summary"]["artifacts_checked"] += 1
            if item_result["status"] != "passed":
                stage_result["status"] = "failed"
                report["status"] = "failed"
                report["summary"]["failed_artifacts"] += 1

            stage_result["artifacts"].append(item_result)
            artifact_id = item_result["id"]
            if payload is not None:
                collected_payloads[artifact_id] = payload
            if scan_id:
                discovered_scan_ids.append((artifact_id, scan_id))

        report["stages"].append(stage_result)

    if not reference_scan_id and discovered_scan_ids:
        reference_scan_id = discovered_scan_ids[0][1]
        report["expected_scan_id"] = reference_scan_id

    if not reference_scan_id:
        report["status"] = "failed"
        report.setdefault("errors", []).append("unable_to_resolve_reference_scan_id")

    for artifact_id, scan_id in discovered_scan_ids:
        if reference_scan_id and scan_id != reference_scan_id:
            report["status"] = "failed"
            report.setdefault("errors", []).append(
                f"scan_id_mismatch:{artifact_id}:{scan_id}!={reference_scan_id}"
            )

    golden_doc = collected_payloads.get("golden_report")
    decision_doc = collected_payloads.get("opa_decision")
    if isinstance(golden_doc, dict) and isinstance(decision_doc, dict):
        golden_scan_id = str(((golden_doc.get("metadata") or {}).get("scan_id") or "")).strip()
        decision_scan_id = str(decision_doc.get("scan_id", "")).strip()
        if golden_scan_id and decision_scan_id and golden_scan_id != decision_scan_id:
            report["status"] = "failed"
            report.setdefault("errors", []).append("golden_decision_scan_id_mismatch")

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def _parse_merge_args(sub: argparse.ArgumentParser) -> None:
    sub.add_argument(
        "--fs", required=True, type=Path, help="Path to trivy fs OPA wrapper report"
    )
    sub.add_argument(
        "--config",
        required=True,
        type=Path,
        help="Path to trivy config OPA wrapper report",
    )
    sub.add_argument(
        "--image",
        required=False,
        default=None,
        type=Path,
        help="Path to trivy image OPA wrapper report (optional: image scan removed from pipeline)",
    )
    sub.add_argument(
        "--output", required=True, type=Path, help="Merged trivy OPA output path"
    )


def _parse_validate_schema_args(sub: argparse.ArgumentParser) -> None:
    sub.add_argument("--document", required=True, type=Path, help="JSON document path")
    sub.add_argument("--schema", required=True, type=Path, help="JSON schema path")
    sub.add_argument(
        "--success-message",
        default="[contract] schema validation passed",
        help="Message printed on successful validation",
    )


def _parse_validate_contract_args(sub: argparse.ArgumentParser) -> None:
    sub.add_argument(
        "--report",
        action="append",
        required=True,
        type=Path,
        help="OPA wrapper report path",
    )


def _parse_stamp_artifact_args(sub: argparse.ArgumentParser) -> None:
    sub.add_argument("--artifact", required=True, type=Path, help="Raw artifact JSON path")
    sub.add_argument(
        "--tool",
        required=True,
        choices=["gitleaks", "checkov", "trivy", "cloudinit"],
        help="Scanner tool name",
    )
    sub.add_argument(
        "--executed-target",
        action="append",
        default=[],
        help="Executed target for the scan (can be repeated)",
    )
    sub.add_argument(
        "--scan-status",
        default="success",
        choices=["success", "failure"],
        help="Explicit scan status",
    )
    sub.add_argument(
        "--scan-id",
        default="",
        help="Correlation scan_id (defaults to CLOUDSENTINEL_SCAN_ID/CI_COMMIT_SHA/git HEAD)",
    )


def _parse_validate_artifact_contract_args(sub: argparse.ArgumentParser) -> None:
    sub.add_argument(
        "--contract",
        required=True,
        type=Path,
        help="Artifact contract definition JSON file",
    )
    sub.add_argument(
        "--report-output",
        required=True,
        type=Path,
        help="artifact_contract_report.json output path",
    )
    sub.add_argument(
        "--stage",
        action="append",
        default=[],
        help="Stage to validate (repeat for multiple). Defaults to all stages in contract.",
    )
    sub.add_argument(
        "--expected-scan-id",
        default="",
        help="Expected scan_id (defaults to CLOUDSENTINEL_SCAN_ID/CI_COMMIT_SHA/git HEAD)",
    )
    sub.add_argument(
        "--golden-schema",
        default="",
        help="Path to golden_report JSON schema",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="CloudSentinel shared contract utilities"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    merge_cmd = sub.add_parser(
        "merge-trivy", help="Merge trivy fs/config/image OPA wrapper reports"
    )
    _parse_merge_args(merge_cmd)

    schema_cmd = sub.add_parser(
        "validate-schema", help="Validate a JSON document against a JSON schema"
    )
    _parse_validate_schema_args(schema_cmd)

    contract_cmd = sub.add_parser(
        "validate-scanner-contract",
        help="Validate scanner wrapper reports contract fields and status values",
    )
    _parse_validate_contract_args(contract_cmd)

    stamp_cmd = sub.add_parser(
        "stamp-artifact-metadata",
        help="Stamp raw scanner artifact with scan_id/scan_status/executed_targets/findings_count",
    )
    _parse_stamp_artifact_args(stamp_cmd)

    artifact_contract_cmd = sub.add_parser(
        "validate-artifact-contract",
        help="Validate stage artifact contract and produce artifact_contract_report.json",
    )
    _parse_validate_artifact_contract_args(artifact_contract_cmd)

    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "merge-trivy":
        merged = merge_trivy_reports(
            args.fs, args.config, args.output, image_path=args.image
        )
        status = merged.get("status", "unknown")
        total = int((merged.get("stats", {}) or {}).get("TOTAL", 0) or 0)
        print(
            f"[normalize] merged trivy subscans -> {args.output} (status={status}, total={total})"
        )
        return 0

    if args.command == "validate-schema":
        validate_schema(args.document, args.schema)
        print(args.success_message)
        return 0

    if args.command == "validate-scanner-contract":
        validate_scanner_contract(args.report)
        print("[contract] scanner wrapper contract passed")
        return 0

    if args.command == "stamp-artifact-metadata":
        scan_id = _resolve_scan_id(args.scan_id)
        if not scan_id:
            raise SystemExit("[contract] scan_id is empty; set CLOUDSENTINEL_SCAN_ID or CI_COMMIT_SHA")
        if not _is_scan_id_valid(scan_id):
            raise SystemExit(f"[contract] invalid scan_id format: {scan_id}")

        stamped = stamp_artifact_metadata(
            args.artifact,
            args.tool,
            executed_targets=args.executed_target,
            scan_status=args.scan_status,
            scan_id=scan_id,
        )
        print(
            "[contract] stamped artifact {path} tool={tool} scan_id={scan_id} findings_count={count}".format(
                path=args.artifact,
                tool=args.tool,
                scan_id=scan_id,
                count=stamped.get("findings_count", "?"),
            )
        )
        return 0

    if args.command == "validate-artifact-contract":
        schema_path = Path(args.golden_schema) if args.golden_schema else None
        report = validate_artifact_contract(
            args.contract,
            args.report_output,
            stages=args.stage,
            expected_scan_id=args.expected_scan_id,
            schema_path=schema_path,
        )
        print(
            "[contract] artifact contract status={status} checked={checked} failed={failed} report={report_path}".format(
                status=report.get("status", "unknown"),
                checked=((report.get("summary") or {}).get("artifacts_checked", 0)),
                failed=((report.get("summary") or {}).get("failed_artifacts", 0)),
                report_path=args.report_output,
            )
        )
        if report.get("status") != "passed":
            raise SystemExit(1)
        return 0

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
