#!/usr/bin/env python3
"""Generate a resource_id-scoped Cloud Custodian policy file."""

from __future__ import annotations

import argparse
import copy
from pathlib import Path

import yaml


def _load_policy(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    if not isinstance(doc, dict) or not isinstance(doc.get("policies"), list):
        raise ValueError("Custodian policy file must contain a top-level policies list")
    return doc


def _find_policy(doc: dict, policy_name: str) -> dict:
    matches = [
        policy
        for policy in doc["policies"]
        if isinstance(policy, dict) and policy.get("name") == policy_name
    ]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one policy named {policy_name!r}, found {len(matches)}")
    return matches[0]


def scope_policy(doc: dict, policy_name: str, resource_id: str) -> dict:
    scoped_doc = copy.deepcopy(doc)
    scoped_policy = copy.deepcopy(_find_policy(doc, policy_name))

    filters = scoped_policy.get("filters") or []
    if not isinstance(filters, list):
        filters = [filters]

    scoped_policy["filters"] = [
        {
            "type": "value",
            "key": "id",
            "op": "eq",
            "value": resource_id,
        },
        *filters,
    ]
    scoped_doc["policies"] = [scoped_policy]
    return scoped_doc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy-file", required=True, type=Path)
    parser.add_argument("--policy-name", required=True)
    parser.add_argument("--resource-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    scoped = scope_policy(_load_policy(args.policy_file), args.policy_name, args.resource_id)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(scoped, fh, sort_keys=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
