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


def main() -> None:
    mapping = json.loads(MAPPING_FILE.read_text(encoding="utf-8"))
    custom_mapping_ids = {key for key in mapping if key.startswith("CKV2_CS_AZ_")}
    policy_ids: dict[str, Path] = {}

    for path in sorted(AZURE_POLICY_ROOT.rglob("*")):
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
