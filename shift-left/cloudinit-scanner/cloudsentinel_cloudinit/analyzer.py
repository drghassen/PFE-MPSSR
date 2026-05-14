"""Cloud-init intent analysis over parsed Terraform VM resources."""

from __future__ import annotations

import os
import re
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from .hcl import (
    extract_cloud_init,
    extract_environment,
    extract_locals,
    extract_resources,
    extract_role_tag,
    extract_tags,
    extract_yaml_packages,
    iter_tf_files,
    load_hcl_file,
)
from .patterns import (
    detect_pattern_ids,
    load_pattern_db,
    pattern_entry_by_id,
    pattern_metadata,
)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def resolve_scan_id() -> str:
    explicit = os.environ.get("CLOUDSENTINEL_SCAN_ID", "").strip()
    if explicit:
        return explicit
    ci_sha = os.environ.get("CI_COMMIT_SHA", "").strip()
    if ci_sha:
        return ci_sha
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        return str(uuid.uuid4())


def as_lower_str(value: Any) -> str:
    return str(value).strip().lower()


def detect_db_packages(cloud_init_text: str, pattern_db: Dict[str, Any]) -> list[str]:
    lower_text = cloud_init_text.lower()
    db_keywords = pattern_db.get("workload_keywords", {}).get("database", [])
    detected = {
        kw for kw in db_keywords if re.search(rf"\b{re.escape(str(kw))}\b", lower_text)
    }

    for package_name in extract_yaml_packages(cloud_init_text):
        for kw in db_keywords:
            kw_str = str(kw)
            if kw_str in package_name:
                detected.add(kw_str)
    return sorted(detected)


def build_violation(rule: str, severity: str, message: str, block: bool) -> Dict[str, Any]:
    return {
        "rule": rule,
        "severity": severity,
        "message": message,
        "non_waivable_in_prod": True,
        "block": block,
    }


def analyze_resource(
    resource_type: str,
    resource_name: str,
    resource_body: Dict[str, Any],
    tf_file: Path,
    repo_root: Path,
    default_env: str,
    local_values: Dict[str, Any],
    pattern_db: Dict[str, Any],
) -> Dict[str, Any]:
    tags = extract_tags(resource_body)
    role_tag = extract_role_tag(tags)
    env = extract_environment(tags, default_env)

    cloud_init_field, cloud_init_text, cloud_init_unresolvable = extract_cloud_init(
        resource_body=resource_body,
        local_values=local_values,
        module_dir=tf_file.parent,
        repo_root=repo_root,
    )
    db_packages = detect_db_packages(cloud_init_text, pattern_db)
    remote_exec_patterns = detect_pattern_ids(
        cloud_init_text, pattern_db, "remote_exec_patterns"
    )
    security_bypass_patterns = detect_pattern_ids(
        cloud_init_text, pattern_db, "security_bypass_patterns"
    )

    role_spoofing_candidate = (
        as_lower_str(role_tag) not in {"", "db-server"} and bool(db_packages)
    )
    role_tag_missing = role_tag == ""
    remote_exec_detected = bool(remote_exec_patterns)
    security_bypass_detected = bool(security_bypass_patterns)
    blocking_env = env != "dev"

    violations: list[Dict[str, Any]] = []
    if role_tag_missing:
        violations.append(
            build_violation(
                "CS-CLOUDINIT-ROLE-TAG-MISSING",
                "HIGH",
                "Missing mandatory VM tag cs:role",
                block=blocking_env,
            )
        )

    if role_spoofing_candidate:
        violations.append(
            build_violation(
                "CS-MULTI-SIGNAL-ROLE-SPOOFING-V2",
                "CRITICAL",
                "Role web-server conflicts with cloud-init database packages",
                block=blocking_env,
            )
        )

    if remote_exec_detected:
        remote_meta = pattern_entry_by_id(
            pattern_db, "remote_exec_patterns", remote_exec_patterns[0]
        )
        violations.append(
            build_violation(
                str(remote_meta.get("rule_id", "CS-CLOUDINIT-REMOTE-EXEC")),
                str(remote_meta.get("severity", "CRITICAL")),
                str(
                    remote_meta.get(
                        "message", "Remote execution pattern detected in cloud-init"
                    )
                ),
                block=blocking_env,
            )
        )

    for bypass in security_bypass_patterns:
        bypass_meta = pattern_entry_by_id(
            pattern_db, "security_bypass_patterns", bypass
        )
        violations.append(
            build_violation(
                str(bypass_meta.get("rule_id", "CS-CLOUDINIT-SECURITY-BYPASS")),
                str(bypass_meta.get("severity", "CRITICAL")),
                str(
                    bypass_meta.get(
                        "message",
                        f"Security bypass pattern detected in cloud-init: {bypass}",
                    )
                ),
                block=blocking_env,
            )
        )

    try:
        rel_file = str(tf_file.resolve().relative_to(repo_root.resolve()))
    except Exception:
        rel_file = str(tf_file)

    return {
        "resource_address": f"{resource_type}.{resource_name}",
        "resource_type": resource_type,
        "resource_name": resource_name,
        "file": rel_file,
        "line": int(resource_body.get("__start_line__", 0) or 0),
        "environment": env,
        "role_tag": role_tag or None,
        "cloud_init_field": cloud_init_field or None,
        "signals": {
            "role_tag_missing": role_tag_missing,
            "role_spoofing_candidate": role_spoofing_candidate,
            "remote_exec_detected": remote_exec_detected,
            "security_bypass_detected": security_bypass_detected,
            "db_packages_detected": db_packages,
            "remote_exec_patterns": remote_exec_patterns,
            "security_bypass_patterns": security_bypass_patterns,
            "cloud_init_unresolvable": cloud_init_unresolvable,
        },
        "violations": violations,
    }


def analyze_terraform(
    terraform_dir: Path,
    repo_root: Path,
    default_env: str,
    pattern_db_path: Optional[Path] = None,
) -> Dict[str, Any]:
    resources: list[Dict[str, Any]] = []
    parse_errors: list[str] = []
    pattern_db = load_pattern_db(pattern_db_path)

    for tf_file in iter_tf_files(terraform_dir):
        try:
            doc = load_hcl_file(tf_file)
        except Exception as exc:
            parse_errors.append(f"{tf_file}: {exc}")
            continue

        local_values = extract_locals(doc)
        for resource_type, resource_name, body in extract_resources(doc):
            resources.append(
                analyze_resource(
                    resource_type=resource_type,
                    resource_name=resource_name,
                    resource_body=body,
                    tf_file=tf_file,
                    repo_root=repo_root,
                    default_env=default_env,
                    local_values=local_values,
                    pattern_db=pattern_db,
                )
            )

    total_violations = sum(len(r.get("violations", [])) for r in resources)
    blocking_violations = sum(
        1
        for resource in resources
        for violation in resource.get("violations", [])
        if bool(violation.get("block", False))
    )

    by_rule: Dict[str, int] = {}
    for resource in resources:
        for violation in resource.get("violations", []):
            rule = str(violation.get("rule", "")).strip()
            if rule:
                by_rule[rule] = by_rule.get(rule, 0) + 1

    scan_id = resolve_scan_id()
    executed_target = str(terraform_dir)
    return {
        "schema_version": "1.0.0",
        "generated_at": utc_now(),
        "scanner": "cloudinit-scanner",
        "scan_id": scan_id,
        "scan_completed": True,
        "scan_status": "success",
        "findings_count": total_violations,
        "executed_targets": [executed_target],
        "scan_metadata": {
            "tool": "cloudinit",
            "scan_id": scan_id,
            "scan_completed": True,
            "scan_status": "success",
            "findings_count": total_violations,
            "executed_targets": [executed_target],
            "scanned_at": utc_now(),
        },
        "resources_analyzed": resources,
        "summary": {
            "total_resources": len(resources),
            "total_violations": total_violations,
            "blocking_violations": blocking_violations,
            "violations_by_rule": by_rule,
            "parse_errors": parse_errors,
            "pattern_db": pattern_metadata(pattern_db),
        },
    }
