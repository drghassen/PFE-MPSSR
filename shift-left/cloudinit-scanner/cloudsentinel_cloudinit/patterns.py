"""Local pattern database loading and matching for cloud-init scans."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Optional

SCANNER_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PATTERN_DB_PATH = SCANNER_ROOT / "rules" / "cloudinit_malicious_patterns.json"

FALLBACK_PATTERN_DB: Dict[str, Any] = {
    "schema_version": "fallback-1.0.0",
    "description": "Built-in fallback patterns used only when the local JSON rule database is unavailable.",
    "workload_keywords": {
        "database": [
            "postgresql",
            "postgres",
            "mysql",
            "mariadb",
            "mongodb",
            "mongod",
            "redis",
            "redis-server",
            "couchdb",
            "elasticsearch",
        ]
    },
    "remote_exec_patterns": [
        {
            "id": "curl_pipe_shell",
            "rule_id": "CS-CLOUDINIT-REMOTE-EXEC",
            "severity": "CRITICAL",
            "message": "Remote execution pattern detected in cloud-init",
            "regex": r"curl\s+[^\n|;]+\|\s*(?:sudo\s+)?(?:bash|sh)\b",
        },
        {
            "id": "wget_pipe_shell",
            "rule_id": "CS-CLOUDINIT-REMOTE-EXEC",
            "severity": "CRITICAL",
            "message": "Remote execution pattern detected in cloud-init",
            "regex": r"wget\s+[^\n|;]+\|\s*(?:bash|sh)\b",
        },
    ],
    "security_bypass_patterns": [
        {
            "id": "ssh_key_injection",
            "rule_id": "CS-CLOUDINIT-SSH-KEY-INJECTION",
            "severity": "CRITICAL",
            "message": "SSH authorized_keys injection detected in cloud-init",
            "regex": r"(?:echo\s+[\"']?ssh-(?:rsa|ed25519|ecdsa)[^\n]+>>\s*[^\n]*authorized_keys|ssh_authorized_keys\s*:)",
        },
        {
            "id": "firewall_disable",
            "rule_id": "CS-CLOUDINIT-FIREWALL-DISABLE",
            "severity": "CRITICAL",
            "message": "Firewall or host security daemon disabled via cloud-init",
            "regex": r"\b(?:ufw\s+disable|iptables\s+-F|systemctl\s+(?:stop|disable)\s+(?:firewalld|ufw|iptables)|setenforce\s+0)\b",
        },
        {
            "id": "hardcoded_credentials",
            "rule_id": "CS-CLOUDINIT-HARDCODED-CREDENTIALS",
            "severity": "CRITICAL",
            "message": "Hardcoded credentials detected in cloud-init",
            "regex": r"(?:password|passwd|secret|token|api_key)\s*=\s*(?:[\"'][^\"']{6,}[\"']|[^\s\"']{6,})",
        },
    ],
}


def validate_pattern_entry(entry: Any, group: str) -> Dict[str, str]:
    if not isinstance(entry, dict):
        raise ValueError(f"{group}: pattern entry must be an object")

    pattern_id = str(entry.get("id", "")).strip()
    regex = str(entry.get("regex", "")).strip()
    if not pattern_id:
        raise ValueError(f"{group}: pattern id is required")
    if not regex:
        raise ValueError(f"{group}.{pattern_id}: regex is required")

    try:
        re.compile(regex, re.IGNORECASE)
    except re.error as exc:
        raise ValueError(f"{group}.{pattern_id}: invalid regex: {exc}") from exc

    return {
        "id": pattern_id,
        "rule_id": str(entry.get("rule_id", "")).strip()
        or "CS-CLOUDINIT-SECURITY-BYPASS",
        "severity": str(entry.get("severity", "CRITICAL")).strip().upper(),
        "message": str(
            entry.get("message", "Cloud-init suspicious pattern detected")
        ).strip(),
        "regex": regex,
    }


def compile_pattern_db(raw_db: Dict[str, Any], source: str) -> Dict[str, Any]:
    if not isinstance(raw_db, dict):
        raise ValueError("pattern database root must be an object")

    compiled: Dict[str, Any] = {
        "schema_version": str(raw_db.get("schema_version", "unknown")),
        "source": source,
        "workload_keywords": {"database": []},
        "remote_exec_patterns": [],
        "security_bypass_patterns": [],
    }

    workload_keywords = raw_db.get("workload_keywords", {})
    if isinstance(workload_keywords, dict):
        database_keywords = workload_keywords.get("database", [])
        if isinstance(database_keywords, list):
            compiled["workload_keywords"]["database"] = sorted(
                {
                    str(keyword).strip().lower()
                    for keyword in database_keywords
                    if str(keyword).strip()
                }
            )

    for group in ("remote_exec_patterns", "security_bypass_patterns"):
        entries = raw_db.get(group, [])
        if not isinstance(entries, list):
            raise ValueError(f"{group}: expected array")

        seen: set[str] = set()
        for entry in entries:
            clean = validate_pattern_entry(entry, group)
            if clean["id"] in seen:
                raise ValueError(f"{group}.{clean['id']}: duplicate pattern id")
            seen.add(clean["id"])
            clean["compiled_regex"] = re.compile(clean["regex"], re.IGNORECASE)
            compiled[group].append(clean)

    return compiled


def load_pattern_db(pattern_db_path: Optional[Path] = None) -> Dict[str, Any]:
    configured_path = pattern_db_path
    if configured_path is None:
        env_path = os.environ.get("CLOUDINIT_PATTERN_DB", "").strip()
        configured_path = Path(env_path) if env_path else DEFAULT_PATTERN_DB_PATH

    try:
        with configured_path.open("r", encoding="utf-8") as handle:
            raw_db = json.load(handle)
        return compile_pattern_db(raw_db, str(configured_path))
    except Exception as exc:
        fallback = compile_pattern_db(FALLBACK_PATTERN_DB, "built-in-fallback")
        fallback["load_error"] = f"{configured_path}: {exc}"
        return fallback


def pattern_metadata(pattern_db: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "source": pattern_db.get("source", "unknown"),
        "schema_version": pattern_db.get("schema_version", "unknown"),
        "load_error": pattern_db.get("load_error"),
        "remote_exec_patterns": len(pattern_db.get("remote_exec_patterns", [])),
        "security_bypass_patterns": len(
            pattern_db.get("security_bypass_patterns", [])
        ),
        "database_keywords": len(
            pattern_db.get("workload_keywords", {}).get("database", [])
        ),
    }


def detect_pattern_ids(cloud_init_text: str, pattern_db: Dict[str, Any], group: str) -> list[str]:
    matches: list[str] = []
    for entry in pattern_db.get(group, []):
        pattern = entry.get("compiled_regex")
        if pattern.search(cloud_init_text):
            matches.append(str(entry.get("id", "")))
    return matches


def pattern_entry_by_id(
    pattern_db: Dict[str, Any], group: str, pattern_id: str
) -> Dict[str, str]:
    for entry in pattern_db.get(group, []):
        if str(entry.get("id", "")) == pattern_id:
            return entry
    return {
        "id": pattern_id,
        "rule_id": "CS-CLOUDINIT-SECURITY-BYPASS",
        "severity": "CRITICAL",
        "message": f"Security bypass pattern detected in cloud-init: {pattern_id}",
    }
