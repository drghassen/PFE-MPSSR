"""Terraform HCL parsing and cloud-init expression resolution."""

from __future__ import annotations

import ast
import base64
import re
from pathlib import Path
from typing import Any, Dict, Iterable, Tuple

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


def strip_hcl_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def strip_hcl_heredoc(value: str) -> str:
    value = value.strip()
    heredoc_re = re.match(r"^<<[-~]?\w+\n(.*?)\n\w+$", value, re.DOTALL)
    if heredoc_re:
        return heredoc_re.group(1)
    return value


def iter_tf_files(terraform_dir: Path) -> Iterable[Path]:
    for path in sorted(terraform_dir.rglob("*.tf")):
        if path.is_file():
            yield path


def load_hcl_file(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return hcl2.load(handle)


def extract_resources(
    doc: Dict[str, Any],
) -> Iterable[Tuple[str, str, Dict[str, Any]]]:
    for resource_block in doc.get("resource", []):
        if not isinstance(resource_block, dict):
            continue
        for resource_type, entries in resource_block.items():
            if strip_hcl_quotes(resource_type) not in VM_RESOURCE_TYPES:
                continue
            if not isinstance(entries, dict):
                continue
            for resource_name, resource_body in entries.items():
                if isinstance(resource_body, dict):
                    yield (
                        strip_hcl_quotes(resource_type),
                        strip_hcl_quotes(resource_name),
                        resource_body,
                    )


def unwrap_hcl_value(value: Any) -> Any:
    if isinstance(value, list) and len(value) == 1:
        return value[0]
    return value


def extract_locals(doc: Dict[str, Any]) -> Dict[str, Any]:
    values: Dict[str, Any] = {}
    for block in doc.get("locals", []):
        if not isinstance(block, dict):
            continue
        for key, value in block.items():
            if str(key).startswith("__"):
                continue
            values[str(key)] = unwrap_hcl_value(value)
    return values


def extract_tags(resource_body: Dict[str, Any]) -> Dict[str, str]:
    tags = unwrap_hcl_value(resource_body.get("tags"))
    if isinstance(tags, str):
        return extract_tags_from_expression(tags)
    if not isinstance(tags, dict):
        return {}

    result: Dict[str, str] = {}
    for key, value in tags.items():
        if isinstance(key, str):
            result[strip_hcl_quotes(key)] = strip_hcl_quotes(str(value))
    return result


def extract_tags_from_expression(expression: str) -> Dict[str, str]:
    map_matches = re.findall(r"\{[^{}]*\}", expression)
    extracted: Dict[str, str] = {}
    for fragment in map_matches:
        for key, value in re.findall(
            r"[\"']([^\"']+)[\"']\s*:\s*[\"']([^\"']*)[\"']", fragment
        ):
            extracted[key.strip()] = value.strip()
    return extracted


def extract_role_tag(tags: Dict[str, str]) -> str:
    for key, value in tags.items():
        if key.lower() in {"cs:role", "cs_role", "cs-role"} and value.strip():
            return value.strip()
    return ""


def extract_environment(tags: Dict[str, str], default_env: str) -> str:
    for key, value in tags.items():
        if key.lower() in {"environment", "env"} and value.strip():
            return value.strip().lower()
    return default_env.strip().lower() or "dev"


def looks_base64(value: str) -> bool:
    if not value or len(value) < 16 or len(value) % 4 != 0:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/=]+", value))


def decode_if_base64(field_name: str, raw: str) -> str:
    raw_stripped = raw.strip()
    if "${" in raw_stripped:
        return raw
    if not (field_name.endswith("_base64") or looks_base64(raw_stripped)):
        return raw

    try:
        decoded = base64.b64decode(raw_stripped, validate=True).decode(
            "utf-8", errors="ignore"
        )
    except Exception:
        return raw
    return decoded if decoded.strip() else raw


def strip_interpolation(value: str) -> str:
    value = value.strip()
    if value.startswith("${") and value.endswith("}"):
        return value[2:-1].strip()
    return value


def parse_template_vars(raw: str) -> Dict[str, str]:
    raw = raw.strip()
    if not raw:
        return {}
    try:
        parsed = ast.literal_eval(raw)
    except (SyntaxError, ValueError):
        parsed = None
    if isinstance(parsed, dict):
        return {str(key): str(value) for key, value in parsed.items()}

    values: Dict[str, str] = {}
    for key, value in re.findall(r"[\"']([^\"']+)[\"']\s*:\s*[\"']([^\"']*)[\"']", raw):
        values[key] = value
    return values


def render_template_text(template_text: str, variables: Dict[str, str]) -> Tuple[str, bool]:
    unresolved = False

    def replace(match: re.Match[str]) -> str:
        nonlocal unresolved
        name = match.group(1)
        if name in variables:
            return variables[name]
        unresolved = True
        return match.group(0)

    rendered = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", replace, template_text)
    return rendered, unresolved


def resolve_path_module(path_expr: str, module_dir: Path) -> Path:
    path_text = path_expr.replace("${path.module}", str(module_dir))
    candidate = Path(path_text)
    if not candidate.is_absolute():
        candidate = module_dir / candidate
    return candidate.resolve()


def resolve_templatefile_expression(
    expression: str, module_dir: Path, repo_root: Path
) -> Tuple[str, bool]:
    match = re.search(
        r"templatefile\(\s*\"([^\"]+)\"\s*,\s*(\{.*\})\s*\)",
        expression,
        re.DOTALL,
    )
    if not match:
        return expression, True

    template_path = resolve_path_module(match.group(1), module_dir)
    try:
        template_path.relative_to(repo_root.resolve())
    except ValueError:
        return expression, True

    if not template_path.is_file():
        return expression, True

    variables = parse_template_vars(match.group(2))
    try:
        template_text = template_path.read_text(encoding="utf-8")
    except OSError:
        return expression, True

    return render_template_text(template_text, variables)


def resolve_cloud_init_expression(
    value: str,
    local_values: Dict[str, Any],
    module_dir: Path,
    repo_root: Path,
) -> Tuple[str, bool]:
    expression = strip_interpolation(value)

    local_match = re.fullmatch(r"local\.([A-Za-z_][A-Za-z0-9_]*)", expression)
    if local_match:
        local_value = unwrap_hcl_value(local_values.get(local_match.group(1)))
        if isinstance(local_value, str) and local_value.strip():
            return resolve_cloud_init_expression(
                local_value, local_values, module_dir, repo_root
            )
        return value, True

    base64_match = re.fullmatch(r"base64encode\((.*)\)", expression, re.DOTALL)
    if base64_match:
        inner = base64_match.group(1).strip()
        return resolve_cloud_init_expression(inner, local_values, module_dir, repo_root)

    if expression.startswith("templatefile("):
        return resolve_templatefile_expression(expression, module_dir, repo_root)

    return value, "${" in value


def extract_cloud_init(
    resource_body: Dict[str, Any],
    local_values: Dict[str, Any],
    module_dir: Path,
    repo_root: Path,
) -> Tuple[str, str, bool]:
    for field in CLOUD_INIT_FIELDS:
        raw_value = unwrap_hcl_value(resource_body.get(field))
        if isinstance(raw_value, str) and raw_value.strip():
            resolved, expression_unresolvable = resolve_cloud_init_expression(
                raw_value, local_values, module_dir, repo_root
            )
            cleaned = strip_hcl_heredoc(resolved)
            decoded = decode_if_base64(field, cleaned)
            unresolvable = expression_unresolvable or "${" in decoded.strip()
            return field, decoded, unresolvable
    return "", "", False


def extract_yaml_packages(cloud_init_text: str) -> list[str]:
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
    return [item.strip().lower() for item in packages if isinstance(item, str) and item.strip()]
