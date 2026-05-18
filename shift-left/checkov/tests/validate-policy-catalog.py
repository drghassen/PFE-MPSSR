#!/usr/bin/env python3
"""Validate CloudSentinel Checkov custom policy catalog integrity."""

from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as exc:  # pragma: no cover - CI image provides PyYAML via Checkov
    raise SystemExit(f"[checkov-catalog] PyYAML missing: {exc}") from exc


REPO_ROOT = Path(__file__).resolve().parents[3]
POLICY_ROOT = REPO_ROOT / "shift-left" / "checkov" / "policies"
AZURE_POLICY_ROOT = POLICY_ROOT / "azure"
MAPPING_FILE = POLICY_ROOT / "mapping.json"
SUPPRESSIONS_FILE = REPO_ROOT / "shift-left" / "checkov" / "config" / "checkov-suppressions.yml"

DANGEROUS_SUPPRESSIONS = {
    "CKV_AZURE_59",
    "CKV_AZURE_99",
    "CKV_AZURE_100",
    "CKV_AZURE_101",
    "CKV_AZURE_109",
    "CKV_AZURE_140",
    "CKV_AZURE_189",
    "CKV2_AZURE_1",
    "CKV2_AZURE_21",
    "CKV2_AZURE_32",
    "CKV2_AZURE_33",
    "CKV2_AZURE_40",
    "CKV2_CS_AZ_008",
    "CKV2_CS_AZ_010",
    "CKV2_CS_AZ_039",
}


def fail(message: str) -> None:
    print(f"[checkov-catalog][ERROR] {message}", file=sys.stderr)
    raise SystemExit(1)


def walk_values(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_values(child)


def python_policy_id(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    ast.parse(text, filename=str(path))
    match = re.search(r'id\s*=\s*["\'](CKV2_CS_AZ_\d+)["\']', text)
    if not match:
        fail(f"missing policy id in {path}")
    return match.group(1)


def yaml_policy_id(path: Path) -> str:
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    metadata = doc.get("metadata")
    if not isinstance(metadata, dict) or not metadata.get("id"):
        fail(f"missing metadata.id in {path}")
    definition = doc.get("definition")
    if not isinstance(definition, dict):
        fail(f"missing definition in {path}")
    for node in walk_values(definition):
        if node.get("operator") == "exists":
            fail(f"weak YAML operator 'exists' is forbidden in {path}")
    return str(metadata["id"])


def validate_python_packages() -> None:
    for directory in sorted(path for path in AZURE_POLICY_ROOT.rglob("*") if path.is_dir()):
        if directory.name == "__pycache__":
            continue
        if not (directory / "__init__.py").is_file():
            fail(f"missing __init__.py required by Checkov external Python checks: {directory}")


def validate_suppressions() -> None:
    doc = yaml.safe_load(SUPPRESSIONS_FILE.read_text(encoding="utf-8")) or {}
    skipped = doc.get("skip-check", [])
    if skipped is None:
        skipped = []
    if not isinstance(skipped, list):
        fail("checkov suppressions skip-check must be a list")
    forbidden = sorted(DANGEROUS_SUPPRESSIONS & {str(item) for item in skipped})
    if forbidden:
        fail(
            "dangerous Checkov suppressions must stay visible for OPA/DefectDojo: "
            + ", ".join(forbidden)
        )


def main() -> None:
    validate_python_packages()
    validate_suppressions()

    mapping = json.loads(MAPPING_FILE.read_text(encoding="utf-8"))
    custom_mapping_ids = {key for key in mapping if key.startswith("CKV2_CS_AZ_")}
    policy_ids: dict[str, Path] = {}

    for path in sorted(AZURE_POLICY_ROOT.rglob("*")):
        if "__pycache__" in path.parts:
            continue
        if path.name == "__init__.py":
            continue
        if path.suffix == ".py":
            policy_id = python_policy_id(path)
        elif path.suffix in {".yaml", ".yml"}:
            policy_id = yaml_policy_id(path)
        else:
            continue

        if policy_id in policy_ids:
            fail(f"duplicate policy id {policy_id}: {policy_ids[policy_id]} and {path}")
        policy_ids[policy_id] = path

    missing_mapping = sorted(set(policy_ids) - custom_mapping_ids)
    orphan_mapping = sorted(custom_mapping_ids - set(policy_ids))
    if missing_mapping:
        fail(f"missing mapping entries: {', '.join(missing_mapping)}")
    if orphan_mapping:
        fail(f"orphan mapping entries: {', '.join(orphan_mapping)}")

    print(f"[checkov-catalog] PASS policies={len(policy_ids)} mappings={len(custom_mapping_ids)}")


if __name__ == "__main__":
    main()
