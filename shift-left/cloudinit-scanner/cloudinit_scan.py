#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import hcl2
import yaml

VM_RESOURCE_TYPES = {
    "azurerm_linux_virtual_machine",
    "azurerm_windows_virtual_machine",
    "aws_instance",
    "google_compute_instance",
}

CLOUD_INIT_FIELDS = (
    "custom_data",
    "custom_data_base64",
    "user_data",
    "user_data_base64",
    "metadata_startup_script",
)

DB_KEYWORDS = {
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
}

REMOTE_EXEC_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    (
        "curl_pipe_shell",
        re.compile(r"curl\s+[^\n|;]+\|\s*(?:sudo\s+)?(?:bash|sh)\b", re.IGNORECASE),
    ),
    (
        "wget_pipe_shell",
        re.compile(r"wget\s+[^\n|;]+\|\s*(?:bash|sh)\b", re.IGNORECASE),
    ),
    (
        "subshell_curl_shell",
        re.compile(r"(?:bash|sh)\s+-c\s+[\"']?\$\(\s*curl", re.IGNORECASE),
    ),
    (
        "eval_remote_exec",
        re.compile(r'\beval\s+["\']?\$\(', re.IGNORECASE),
    ),
    (
        "process_substitution_remote",
        re.compile(r"(?:bash|sh)\s+<\s*\(\s*(?:curl|wget)", re.IGNORECASE),
    ),
    (
        "curl_download_exec",
        re.compile(r"curl\s+[^\n]+\s+-o\s+[^\n]+&&\s*(?:bash|sh|chmod)", re.IGNORECASE),
    ),
    (
        "wget_unverified_binary",
        re.compile(r"wget\s+(?:--no-check-certificate|--no-verify)\s+[^\n]+", re.IGNORECASE),
    ),
    (
        "python_remote_exec",
        re.compile(r"python[23]?\s+-c\s+[\"'].*(?:urllib|requests|http).*exec", re.IGNORECASE),
    ),
)

SECURITY_BYPASS_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    (
        "ssh_key_injection",
        re.compile(
            r"(?:"
            r"echo\s+[\"']?ssh-(?:rsa|ed25519|ecdsa)[^\n]+>>\s*[^\n]*authorized_keys"
            r"|ssh_authorized_keys\s*:"
            r")",
            re.IGNORECASE,
        ),
    ),
    (
        "firewall_disable",
        re.compile(r"\b(?:ufw\s+disable|iptables\s+-F|systemctl\s+(?:stop|disable)\s+(?:firewalld|ufw|iptables))\b", re.IGNORECASE),
    ),
    (
        "chmod_critical_path",
        re.compile(r"chmod\s+(?:777|a\+[rwx]+)\s+(?:/etc|/usr|/bin|/sbin|/lib|/root)", re.IGNORECASE),
    ),
    (
        "hardcoded_credentials",
        re.compile(r"(?:password|passwd|secret|token|api_key)\s*=\s*(?:[\"'][^\"']{6,}[\"']|[^\s\"']{6,})", re.IGNORECASE),
    ),
    (
        "crontab_injection",
        re.compile(r"(?:crontab\s+-[lu]|echo\s+[\"'][^\"']*\*[^\"']*[\"']\s*>+\s*/etc/cron)", re.IGNORECASE),
    ),
)


def _strip_hcl_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def _strip_hcl_heredoc(value: str) -> str:
    value = value.strip()
    heredoc_re = re.match(r"^<<[-~]?\w+\n(.*?)\n\w+$", value, re.DOTALL)
    if heredoc_re:
        return heredoc_re.group(1)
    return value


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _iter_tf_files(terraform_dir: Path) -> Iterable[Path]:
    for path in sorted(terraform_dir.rglob("*.tf")):
        if path.is_file():
            yield path


def _load_hcl_file(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return hcl2.load(handle)


def _extract_resources(
    doc: Dict[str, Any],
) -> Iterable[Tuple[str, str, Dict[str, Any]]]:
    for resource_block in doc.get("resource", []):
        if not isinstance(resource_block, dict):
            continue
        for resource_type, entries in resource_block.items():
            if _strip_hcl_quotes(resource_type) not in VM_RESOURCE_TYPES:
                continue
            if not isinstance(entries, dict):
                continue
            for resource_name, resource_body in entries.items():
                if isinstance(resource_body, dict):
                    yield _strip_hcl_quotes(resource_type), _strip_hcl_quotes(resource_name), resource_body


def _as_lower_str(value: Any) -> str:
    return str(value).strip().lower()


def _unwrap_hcl_value(value: Any) -> Any:
    if isinstance(value, list) and len(value) == 1:
        return value[0]
    return value


def _extract_tags(resource_body: Dict[str, Any]) -> Dict[str, str]:
    tags = _unwrap_hcl_value(resource_body.get("tags"))
    if isinstance(tags, str):
        extracted_from_expr = _extract_tags_from_expression(tags)
        if extracted_from_expr:
            return extracted_from_expr
        return {}
    if not isinstance(tags, dict):
        return {}

    result: Dict[str, str] = {}
    for key, value in tags.items():
        if not isinstance(key, str):
            continue
        result[_strip_hcl_quotes(key)] = _strip_hcl_quotes(str(value))
    return result


def _extract_tags_from_expression(expression: str) -> Dict[str, str]:
    # python-hcl2 often serializes HCL expressions as strings, e.g.:
    # "${merge(var.tags,{'cs:role': 'web-server'})}"
    # We only extract explicit literal entries from inline map fragments.
    map_matches = re.findall(r"\{[^{}]*\}", expression)
    if not map_matches:
        return {}

    extracted: Dict[str, str] = {}
    for fragment in map_matches:
        for key, value in re.findall(r"[\"']([^\"']+)[\"']\s*:\s*[\"']([^\"']*)[\"']", fragment):
            extracted[key.strip()] = value.strip()
    return extracted


def _extract_role_tag(tags: Dict[str, str]) -> str:
    for key, value in tags.items():
        if key.lower() in {"cs:role", "cs_role", "cs-role"} and value.strip():
            return value.strip()
    return ""


def _extract_environment(tags: Dict[str, str], default_env: str) -> str:
    for key, value in tags.items():
        if key.lower() in {"environment", "env"} and value.strip():
            return value.strip().lower()
    return default_env.strip().lower() or "dev"


def _looks_base64(value: str) -> bool:
    if not value or len(value) < 16 or len(value) % 4 != 0:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/=]+", value))


def _decode_if_base64(field_name: str, raw: str) -> str:
    raw_stripped = raw.strip()
    if "${" in raw_stripped:
        return raw
    if not (field_name.endswith("_base64") or _looks_base64(raw_stripped)):
        return raw

    try:
        decoded = base64.b64decode(raw_stripped, validate=True).decode(
            "utf-8", errors="ignore"
        )
    except Exception:
        return raw

    if decoded.strip():
        return decoded
    return raw


def _extract_cloud_init(resource_body: Dict[str, Any]) -> Tuple[str, str, bool]:
    for field in CLOUD_INIT_FIELDS:
        raw_value = _unwrap_hcl_value(resource_body.get(field))
        if isinstance(raw_value, str) and raw_value.strip():
            cleaned = _strip_hcl_heredoc(raw_value)
            unresolvable = "${" in cleaned.strip()
            return field, _decode_if_base64(field, cleaned), unresolvable
    return "", "", False


def _extract_yaml_packages(cloud_init_text: str) -> List[str]:
    text = cloud_init_text.strip()
    if not text:
        return []

    if text.startswith("#cloud-config"):
        text = "\n".join(text.splitlines()[1:])

    try:
        payload = yaml.safe_load(text)
    except Exception:
        return []

    if not isinstance(payload, dict):
        return []

    packages = payload.get("packages")
    if not isinstance(packages, list):
        return []

    out: List[str] = []
    for item in packages:
        if isinstance(item, str) and item.strip():
            out.append(item.strip().lower())
    return out


def _detect_db_packages(cloud_init_text: str) -> List[str]:
    lower_text = cloud_init_text.lower()
    detected = {
        kw for kw in DB_KEYWORDS if re.search(rf"\b{re.escape(kw)}\b", lower_text)
    }

    for package_name in _extract_yaml_packages(cloud_init_text):
        for kw in DB_KEYWORDS:
            if kw in package_name:
                detected.add(kw)

    return sorted(detected)


def _detect_remote_exec_patterns(cloud_init_text: str) -> List[str]:
    matches: List[str] = []
    for code, pattern in REMOTE_EXEC_PATTERNS:
        if pattern.search(cloud_init_text):
            matches.append(code)
    return matches


def _detect_security_bypass_patterns(cloud_init_text: str) -> List[str]:
    matches: List[str] = []
    for code, pattern in SECURITY_BYPASS_PATTERNS:
        if pattern.search(cloud_init_text):
            matches.append(code)
    return matches


def _build_violation(
    rule: str, severity: str, message: str, block: bool
) -> Dict[str, Any]:
    return {
        "rule": rule,
        "severity": severity,
        "message": message,
        "non_waivable_in_prod": True,
        "block": block,
    }


def _analyze_resource(
    resource_type: str,
    resource_name: str,
    resource_body: Dict[str, Any],
    tf_file: Path,
    repo_root: Path,
    default_env: str,
) -> Dict[str, Any]:
    tags = _extract_tags(resource_body)
    role_tag = _extract_role_tag(tags)
    env = _extract_environment(tags, default_env)

    cloud_init_field, cloud_init_text, cloud_init_unresolvable = _extract_cloud_init(resource_body)
    db_packages = _detect_db_packages(cloud_init_text)
    remote_exec_patterns = _detect_remote_exec_patterns(cloud_init_text)
    security_bypass_patterns = _detect_security_bypass_patterns(cloud_init_text)

    role_spoofing_candidate = (
        _as_lower_str(role_tag) not in {"", "db-server"}
        and bool(db_packages)
    )
    role_tag_missing = role_tag == ""
    remote_exec_detected = bool(remote_exec_patterns)
    security_bypass_detected = bool(security_bypass_patterns)
    blocking_env = env != "dev"

    violations: List[Dict[str, Any]] = []
    if role_tag_missing:
        violations.append(
            _build_violation(
                "CS-CLOUDINIT-ROLE-TAG-MISSING",
                "HIGH",
                "Missing mandatory VM tag cs:role",
                block=blocking_env,
            )
        )

    if role_spoofing_candidate:
        violations.append(
            _build_violation(
                "CS-MULTI-SIGNAL-ROLE-SPOOFING-V2",
                "CRITICAL",
                "Role web-server conflicts with cloud-init database packages",
                block=blocking_env,
            )
        )

    if remote_exec_detected:
        violations.append(
            _build_violation(
                "CS-CLOUDINIT-REMOTE-EXEC",
                "CRITICAL",
                "Remote execution pattern detected in cloud-init",
                block=blocking_env,
            )
        )

    _BYPASS_RULE_IDS = {
        "ssh_key_injection": "CS-CLOUDINIT-SSH-KEY-INJECTION",
        "firewall_disable": "CS-CLOUDINIT-FIREWALL-DISABLE",
        "hardcoded_credentials": "CS-CLOUDINIT-HARDCODED-CREDENTIALS",
    }
    for bp in security_bypass_patterns:
        violations.append(
            _build_violation(
                _BYPASS_RULE_IDS.get(bp, "CS-CLOUDINIT-SECURITY-BYPASS"),
                "CRITICAL",
                f"Security bypass pattern detected in cloud-init: {bp}",
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
    terraform_dir: Path, repo_root: Path, default_env: str
) -> Dict[str, Any]:
    resources: List[Dict[str, Any]] = []
    parse_errors: List[str] = []

    for tf_file in _iter_tf_files(terraform_dir):
        try:
            doc = _load_hcl_file(tf_file)
        except Exception as exc:
            parse_errors.append(f"{tf_file}: {exc}")
            continue

        for resource_type, resource_name, body in _extract_resources(doc):
            resources.append(
                _analyze_resource(
                    resource_type=resource_type,
                    resource_name=resource_name,
                    resource_body=body,
                    tf_file=tf_file,
                    repo_root=repo_root,
                    default_env=default_env,
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
            if not rule:
                continue
            by_rule[rule] = by_rule.get(rule, 0) + 1

    return {
        "schema_version": "1.0.0",
        "generated_at": _utc_now(),
        "scanner": "cloudinit-scanner",
        "resources_analyzed": resources,
        "summary": {
            "total_resources": len(resources),
            "total_violations": total_violations,
            "blocking_violations": blocking_violations,
            "violations_by_rule": by_rule,
            "parse_errors": parse_errors,
        },
    }


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CloudSentinel cloud-init scanner")
    parser.add_argument(
        "--terraform-dir",
        default=".",
        help="Terraform root directory to analyze",
    )
    parser.add_argument(
        "--output",
        default=".cloudsentinel/cloudinit_analysis.json",
        help="Output JSON path",
    )
    parser.add_argument(
        "--default-env",
        default="dev",
        help="Fallback environment when tags do not include Environment/env",
    )
    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    repo_root = Path.cwd()
    terraform_dir = (repo_root / args.terraform_dir).resolve()
    output_path = (repo_root / args.output).resolve()

    if not terraform_dir.exists() or not terraform_dir.is_dir():
        print(
            f"[cloudinit-scan][ERROR] terraform dir not found: {terraform_dir}",
            file=sys.stderr,
        )
        return 2

    analysis = analyze_terraform(
        terraform_dir=terraform_dir, repo_root=repo_root, default_env=args.default_env
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(analysis, handle, indent=2)

    summary = analysis.get("summary", {})
    print(
        "[cloudinit-scan] resources={resources} violations={violations} blocking={blocking}".format(
            resources=summary.get("total_resources", 0),
            violations=summary.get("total_violations", 0),
            blocking=summary.get("blocking_violations", 0),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
