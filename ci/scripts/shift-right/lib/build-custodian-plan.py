#!/usr/bin/env python3
"""Build the Cloud Custodian remediation plan from an OPA drift decision."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _error(path: Path | None, code: str, message: str, **details: Any) -> int:
    payload = {
        "code": code,
        "message": message,
        "details": details,
    }
    if path is not None:
        _write_json(path, payload)
    print(json.dumps(payload, sort_keys=True), file=sys.stderr)
    return 1


def _as_bool(value: Any) -> bool:
    return value is True


def _is_l3_remediation_candidate(item: dict[str, Any]) -> bool:
    policy = str(item.get("custodian_policy") or "").strip()
    return (
        str(item.get("remediation_level") or "") == "L3"
        and _as_bool(item.get("requires_remediation"))
        and bool(policy)
    )


def _is_arm_resource_id(resource_id: str) -> bool:
    return resource_id.lower().startswith("/subscriptions/")


def _effective_violations(decision: dict[str, Any]) -> list[Any]:
    result = decision.get("result")
    if not isinstance(result, dict):
        raise ValueError("decision.result must be an object")

    violations = result.get("effective_violations")
    if violations is None:
        violations = result.get("violations")
    if not isinstance(violations, list):
        raise ValueError("decision.result.effective_violations or violations must be an array")
    return violations


def build_plan(decision: dict[str, Any]) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    plan: list[dict[str, str]] = []
    invalid_targets: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for raw in _effective_violations(decision):
        if not isinstance(raw, dict) or not _is_l3_remediation_candidate(raw):
            continue

        policy = str(raw.get("custodian_policy") or "").strip()
        resource_id = str(raw.get("resource_id") or "").strip()

        if not _is_arm_resource_id(resource_id):
            invalid_targets.append({
                "resource_id": resource_id,
                "custodian_policy": policy,
                "severity": str(raw.get("severity") or "UNKNOWN"),
            })
            continue

        key = (policy, resource_id)
        if key in seen:
            continue
        seen.add(key)

        plan.append({
            "policy": policy,
            "resource_id": resource_id,
            "resource_type": str(raw.get("resource_type") or raw.get("type") or "unknown"),
            "severity": str(raw.get("severity") or "UNKNOWN"),
            "verification_script": str(raw.get("verification_script") or ""),
            "correlation_id": str(raw.get("correlation_id") or "unknown"),
        })

    return plan, invalid_targets


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--decision", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--error-output", type=Path)
    args = parser.parse_args()

    try:
        decision = json.loads(args.decision.read_text(encoding="utf-8"))
        if not isinstance(decision, dict):
            raise ValueError("OPA decision must be a JSON object")

        _effective_violations(decision)
        plan, invalid_targets = build_plan(decision)
    except Exception as exc:
        return _error(
            args.error_output,
            "invalid_opa_drift_decision",
            "failed to parse OPA drift decision",
            decision_path=str(args.decision),
            error=str(exc),
        )

    if invalid_targets:
        return _error(
            args.error_output,
            "invalid_resource_id",
            "OPA L3 remediation contains invalid or non-ARM resource_id",
            invalid_targets=invalid_targets,
            remediation_scope="L3_DRIFT_ONLY_RESOURCE_ID_SCOPED",
        )

    _write_json(args.output, plan)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
