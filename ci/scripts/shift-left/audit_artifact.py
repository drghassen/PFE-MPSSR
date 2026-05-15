#!/usr/bin/env python3
"""Emit detailed CloudSentinel CI job audit files.

The audit file is intentionally separate from scanner raw outputs. It gives
reviewers a stable, low-volume manifest of what the job produced and whether the
artifacts are structurally usable before downstream contract/OPA stages consume
them.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


HMAC_RE = re.compile(r"^[0-9a-fA-F]{64}$")


SAFE_ENV_KEYS = (
    "CI_PIPELINE_ID",
    "CI_PIPELINE_IID",
    "CI_PIPELINE_SOURCE",
    "CI_PIPELINE_URL",
    "CI_PROJECT_ID",
    "CI_PROJECT_PATH",
    "CI_PROJECT_URL",
    "CI_JOB_ID",
    "CI_JOB_NAME",
    "CI_JOB_STAGE",
    "CI_JOB_URL",
    "CI_COMMIT_SHA",
    "CI_COMMIT_SHORT_SHA",
    "CI_COMMIT_REF_NAME",
    "CI_COMMIT_REF_SLUG",
    "CI_COMMIT_BRANCH",
    "CI_COMMIT_TAG",
    "CI_COMMIT_TIMESTAMP",
    "GITLAB_USER_LOGIN",
    "GITLAB_USER_EMAIL",
    "CI_RUNNER_ID",
    "CI_RUNNER_DESCRIPTION",
    "CI_RUNNER_TAGS",
    "CLOUDSENTINEL_SCAN_ID",
    "CLOUDSENTINEL_EXECUTION_MODE",
    "CLOUDSENTINEL_SCHEMA_STRICT",
    "CI_ENVIRONMENT_NAME",
    "ENVIRONMENT",
    "GITLEAKS_VERSION",
    "CHECKOV_VERSION",
    "TRIVY_VERSION",
    "OPA_VERSION",
    "TOFU_VERSION",
    "TRIVY_IMAGE_TARGETS",
    "CHECKOV_SCAN_TARGET",
    "TRIVY_FS_TARGET",
    "TRIVY_TARGET",
    "SCAN_TARGET",
)


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_kv(values: Iterable[str]) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    for item in values:
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        key = key.strip()
        if key:
            parsed[key] = value.strip()
    return parsed


def load_json(path: Path) -> Tuple[Any, str]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), ""
    except Exception as exc:
        return None, str(exc)


def load_jsonl(path: Path) -> Tuple[List[Any], str]:
    events: List[Any] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_no, raw in enumerate(handle, start=1):
                line = raw.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except Exception as exc:
                    return events, f"line {line_no}: {exc}"
    except Exception as exc:
        return events, str(exc)
    return events, ""


def count_trivy_results(doc: Dict[str, Any]) -> Dict[str, int]:
    counts = {
        "results": 0,
        "vulnerabilities": 0,
        "misconfigurations": 0,
        "secrets": 0,
    }
    results = doc.get("Results")
    if not isinstance(results, list):
        return counts
    counts["results"] = len(results)
    for item in results:
        if not isinstance(item, dict):
            continue
        for source_key, count_key in (
            ("Vulnerabilities", "vulnerabilities"),
            ("Misconfigurations", "misconfigurations"),
            ("Secrets", "secrets"),
        ):
            values = item.get(source_key)
            if isinstance(values, list):
                counts[count_key] += len(values)
    return counts


def summarize_json(path: Path, doc: Any) -> Dict[str, Any]:
    summary: Dict[str, Any] = {}
    if not isinstance(doc, dict):
        if isinstance(doc, list):
            summary["array_items"] = len(doc)
        return summary

    scan_id = (
        doc.get("scan_id")
        or (doc.get("metadata") or {}).get("scan_id")
        or (doc.get("scan_metadata") or {}).get("scan_id")
    )
    if scan_id:
        summary["scan_id"] = str(scan_id)

    for key in ("scan_status", "tool", "findings_count"):
        if key in doc:
            summary[key] = doc[key]

    if isinstance(doc.get("findings"), list):
        summary["findings"] = len(doc["findings"])
    if isinstance(doc.get("leaks"), list):
        summary["leaks"] = len(doc["leaks"])

    results = doc.get("results")
    if isinstance(results, dict):
        for source_key, target_key in (
            ("failed_checks", "checkov_failed_checks"),
            ("passed_checks", "checkov_passed_checks"),
            ("skipped_checks", "checkov_skipped_checks"),
        ):
            values = results.get(source_key)
            if isinstance(values, list):
                summary[target_key] = len(values)

    if isinstance(doc.get("Results"), list):
        summary["trivy"] = count_trivy_results(doc)

    if isinstance(doc.get("resources_analyzed"), list):
        summary["cloudinit_resources_analyzed"] = len(doc["resources_analyzed"])

    if isinstance(doc.get("summary"), dict):
        summary["summary"] = doc["summary"]
    if isinstance(doc.get("quality_gate"), dict):
        summary["quality_gate"] = doc["quality_gate"]

    exceptions = (doc.get("cloudsentinel") or {}).get("exceptions")
    if isinstance(exceptions, dict):
        metadata = exceptions.get("metadata")
        if isinstance(metadata, dict):
            summary["exceptions_metadata"] = metadata
        items = exceptions.get("exceptions")
        if isinstance(items, list):
            summary["exceptions"] = len(items)

    decision = doc.get("result")
    if isinstance(decision, dict):
        summary["opa_decision"] = {
            "allow": decision.get("allow"),
            "deny_count": len(decision.get("deny") or []),
            "warn_count": len(decision.get("warn") or []),
            "metrics": decision.get("metrics") if isinstance(decision.get("metrics"), dict) else {},
        }

    return summary


def summarize_jsonl(events: List[Any]) -> Dict[str, Any]:
    event_types: Dict[str, int] = {}
    actions: Dict[str, int] = {}
    scan_ids: List[str] = []
    for item in events:
        if not isinstance(item, dict):
            continue
        event_type = str(item.get("event_type") or "")
        action = str(item.get("action") or "")
        scan_id = str(item.get("scan_id") or "")
        if event_type:
            event_types[event_type] = event_types.get(event_type, 0) + 1
        if action:
            actions[action] = actions.get(action, 0) + 1
        if scan_id and scan_id not in scan_ids:
            scan_ids.append(scan_id)
    return {
        "events": len(events),
        "event_types": event_types,
        "actions": actions,
        "scan_ids": scan_ids,
    }


def hmac_status(path: Path) -> Dict[str, Any]:
    sidecar = Path(str(path) + ".hmac")
    status: Dict[str, Any] = {
        "sidecar": str(sidecar),
        "present": sidecar.is_file(),
        "format_valid": False,
        "verified": "not_checked",
    }
    if not sidecar.is_file():
        return status
    try:
        actual = sidecar.read_text(encoding="ascii").strip()
    except Exception as exc:
        status["read_error"] = str(exc)
        return status
    status["format_valid"] = bool(HMAC_RE.fullmatch(actual))
    secret = os.environ.get("CLOUDSENTINEL_HMAC_SECRET", "")
    if not secret:
        status["verified"] = "skipped_secret_not_available"
        return status
    try:
        expected = hmac.new(secret.encode("utf-8"), path.read_bytes(), hashlib.sha256).hexdigest()
    except Exception as exc:
        status["verified"] = "failed"
        status["verify_error"] = str(exc)
        return status
    status["verified"] = "passed" if hmac.compare_digest(expected, actual) else "failed"
    return status


def iter_artifact_paths(raw_paths: Iterable[str]) -> List[Path]:
    paths: List[Path] = []
    seen: set[str] = set()
    for raw in raw_paths:
        path = Path(raw)
        expanded: List[Path]
        if path.is_dir():
            expanded = sorted(p for p in path.rglob("*") if p.is_file())
        else:
            expanded = [path]
        for item in expanded:
            key = str(item)
            if key not in seen:
                seen.add(key)
                paths.append(item)
    return paths


def inspect_artifact(path: Path) -> Dict[str, Any]:
    entry: Dict[str, Any] = {
        "path": str(path),
        "exists": path.exists(),
        "is_file": path.is_file(),
    }
    if not path.exists() or not path.is_file():
        return entry

    stat = path.stat()
    entry["bytes"] = stat.st_size
    entry["sha256"] = sha256_file(path)
    entry["modified_at_epoch"] = int(stat.st_mtime)

    suffixes = "".join(path.suffixes)
    if suffixes.endswith(".jsonl"):
        events, error = load_jsonl(path)
        entry["jsonl_valid"] = not error
        if error:
            entry["jsonl_error"] = error
        entry["content_summary"] = summarize_jsonl(events)
    elif path.suffix == ".json":
        doc, error = load_json(path)
        entry["json_valid"] = not error
        if error:
            entry["json_error"] = error
        else:
            entry["content_summary"] = summarize_json(path, doc)
    elif path.suffix == ".hmac":
        try:
            content = path.read_text(encoding="ascii").strip()
            entry["hmac_format_valid"] = bool(HMAC_RE.fullmatch(content))
        except Exception as exc:
            entry["hmac_read_error"] = str(exc)
    else:
        entry["content_summary"] = {"format": "opaque"}

    if path.suffix != ".hmac":
        entry["hmac"] = hmac_status(path)
    return entry


def build_audit(args: argparse.Namespace) -> Dict[str, Any]:
    env = {key: os.environ[key] for key in SAFE_ENV_KEYS if key in os.environ}
    artifacts = [inspect_artifact(path) for path in iter_artifact_paths(args.artifact)]
    missing_artifacts = [
        item["path"]
        for item in artifacts
        if not item.get("exists")
    ]
    invalid_artifacts = [
        item["path"]
        for item in artifacts
        if item.get("json_valid") is False or item.get("jsonl_valid") is False
    ]

    return {
        "schema_version": "1.0.0",
        "generated_at": now_utc(),
        "job": {
            "name": args.job,
            "stage": args.stage,
            "component": args.component,
            "status": args.status,
            "exit_code": args.exit_code,
        },
        "execution_context": env,
        "metrics": parse_kv(args.metric),
        "artifacts": artifacts,
        "summary": {
            "artifact_count": len(artifacts),
            "missing_artifact_count": len(missing_artifacts),
            "missing_artifacts": missing_artifacts,
            "invalid_artifact_count": len(invalid_artifacts),
            "invalid_artifacts": invalid_artifacts,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job", required=True)
    parser.add_argument("--stage", required=True)
    parser.add_argument("--component", required=True)
    parser.add_argument("--status", required=True, choices=["success", "failure", "canceled", "skipped", "unknown"])
    parser.add_argument("--exit-code", type=int, default=0)
    parser.add_argument("--output", default="")
    parser.add_argument("--artifact", action="append", default=[])
    parser.add_argument("--metric", action="append", default=[])
    args = parser.parse_args()

    output = Path(args.output or f".cloudsentinel/audit/{args.job}_audit.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    audit = build_audit(args)
    output.write_text(json.dumps(audit, indent=2, sort_keys=True), encoding="utf-8")
    print(f"[audit] wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
