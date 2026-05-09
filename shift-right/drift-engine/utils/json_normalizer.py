from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from utils.diff_engine import _diff_paths, _extract_changed_paths
from utils.plan_parser import (
    _actions_key,
    _iter_resource_changes,
    _safe_dict,
    _safe_list_str,
)
from utils.security_taxonomy import (
    classify_drift_severity,
    classify_security_dimensions,
)

logger = logging.getLogger(__name__)

# Re-export everything the test suite imports directly from this module.
__all__ = [
    "DriftSummary",
    "normalize_terraform_plan",
    "classify_drift_severity",
    "classify_security_dimensions",
    "drift_items_to_defectdojo_generic_findings",
    "_diff_paths",
]


@dataclass(frozen=True)
class DriftSummary:
    resources_changed: int
    outputs_changed: int
    resources_by_action: dict[str, int]
    provider_names: list[str]
    filtered_items: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Output-level drift inference
# ---------------------------------------------------------------------------

def _infer_resources_from_outputs(
    plan_json: dict[str, Any],
    output_changes: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Infer managed-resource drift from changed Terraform outputs.
    Skipped when `configuration` is absent from the plan JSON.
    """
    if not plan_json.get("configuration"):
        logger.warning(
            "infer_resources_skipped",
            extra={
                "reason": "configuration block absent in plan JSON",
                "hint": "Set include_plan_json: true in drift_config.yaml",
            },
        )
        return []

    outputs_config = (
        _safe_dict(plan_json.get("configuration"))
        .get("root_module", {})
        .get("outputs", {})
    )
    if not isinstance(outputs_config, dict):
        return []

    resource_changes = {
        rc["address"]: rc
        for rc in plan_json.get("resource_changes", [])
        if isinstance(rc, dict) and isinstance(rc.get("address"), str)
    }

    inferred: list[dict[str, Any]] = []
    for output_name, output_cfg in outputs_config.items():
        if output_name not in output_changes or not isinstance(output_cfg, dict):
            continue
        references = _safe_list_str(
            _safe_dict(output_cfg.get("expression")).get("references")
        )
        for ref in references:
            if ref not in resource_changes:
                continue
            rc = resource_changes[ref]
            actions = _safe_list_str(_safe_dict(rc.get("change")).get("actions"))
            if "no-op" in actions or actions == ["no-op"]:
                continue
            inferred.append(
                {
                    "address": rc["address"],
                    "type": rc.get("type", "unknown"),
                    "mode": rc.get("mode", "managed"),
                    "name": rc.get("name", ""),
                    "provider_name": rc.get("provider_name"),
                    "resource_id": None,
                    "actions": actions,
                    "changed_paths": _extract_changed_paths(rc),
                    "drifted": True,
                    "provenance": "inferred_from_output",
                    "inferred_from_output": output_name,
                }
            )
    return inferred


# ---------------------------------------------------------------------------
# Public normalizer
# ---------------------------------------------------------------------------

def normalize_terraform_plan(
    plan_json: dict[str, Any],
) -> tuple[DriftSummary, list[dict[str, Any]]]:
    """
    Normalize `terraform show -json` output into a compact drift representation.
    Items carry security_dimensions (observation) but NO severity — OPA decides.
    """
    items: list[dict[str, Any]] = []
    filtered: list[dict[str, Any]] = []
    provider_names: set[str] = set()
    resources_by_action: dict[str, int] = {}
    seen: set[str] = set()

    for rc in _iter_resource_changes(plan_json):
        address = str(rc.get("address") or "")
        if address and address in seen:
            continue

        change = _safe_dict(rc.get("change"))
        actions = _safe_list_str(change.get("actions"))
        mode = str(rc.get("mode") or "managed")
        rtype = str(rc.get("type") or "")
        name = str(rc.get("name") or "")
        provider_name = str(rc.get("provider_name") or "")
        if provider_name:
            provider_names.add(provider_name)

        # Data sources are read-only and not security-relevant drift.
        if mode == "data":
            filtered.append(
                {"address": address, "mode": mode, "type": rtype, "name": name,
                 "actions": actions, "filter_reason": "data_source"}
            )
            continue

        before = change.get("before")
        after = change.get("after")
        changed_paths = _diff_paths(before, after)
        is_noop_or_read = actions == ["no-op"] or actions == ["read"]

        if not changed_paths and is_noop_or_read:
            filtered.append(
                {"address": address, "mode": mode, "type": rtype, "name": name,
                 "actions": actions, "filter_reason": "noop_read_no_change"}
            )
            continue

        if not changed_paths:
            changed_paths = ["(sensitive or unknown)"]

        if address:
            seen.add(address)

        action_key = _actions_key(actions)
        resources_by_action[action_key] = resources_by_action.get(action_key, 0) + 1

        resource_id = None
        if isinstance(after, dict) and isinstance(after.get("id"), str):
            resource_id = after.get("id")
        elif isinstance(before, dict) and isinstance(before.get("id"), str):
            resource_id = before.get("id")

        dims = classify_security_dimensions(rtype, changed_paths)
        items.append(
            {
                "address": address,
                "mode": mode,
                "type": rtype,
                "name": name,
                "provider_name": provider_name or None,
                "actions": actions,
                "resource_id": resource_id,
                "changed_paths": changed_paths,
                "drifted": True,
                "security_dimensions": dims,
                "is_security_relevant": bool(dims),
            }
        )

    # Output-level drift
    output_changes = plan_json.get("output_changes") or {}
    if isinstance(output_changes, dict):
        for out_name, out_change in sorted(output_changes.items()):
            if not isinstance(out_name, str) or not isinstance(out_change, dict):
                continue
            before = out_change.get("before")
            after = out_change.get("after")
            actions = _safe_list_str(out_change.get("actions")) or ["update"]
            changed_paths = _diff_paths(before, after)
            if not changed_paths:
                continue
            action_key = _actions_key(actions)
            resources_by_action[action_key] = resources_by_action.get(action_key, 0) + 1
            items.append(
                {
                    "address": f"output.{out_name}",
                    "mode": "output",
                    "type": "output",
                    "name": out_name,
                    "provider_name": None,
                    "actions": actions,
                    "resource_id": None,
                    "changed_paths": changed_paths,
                    "drifted": True,
                }
            )

        for inferred in _infer_resources_from_outputs(plan_json, output_changes):
            address = str(inferred.get("address") or "")
            if address and address in seen:
                continue
            if address:
                seen.add(address)
            pname = str(inferred.get("provider_name") or "")
            if pname:
                provider_names.add(pname)
            action_key = _actions_key(_safe_list_str(inferred.get("actions")))
            resources_by_action[action_key] = resources_by_action.get(action_key, 0) + 1
            items.append(inferred)

    managed_count = sum(1 for i in items if i.get("mode") != "output")
    output_count = sum(1 for i in items if i.get("mode") == "output")
    return DriftSummary(
        resources_changed=managed_count,
        outputs_changed=output_count,
        resources_by_action=resources_by_action,
        provider_names=sorted(provider_names),
        filtered_items=filtered,
    ), items


# ---------------------------------------------------------------------------
# DefectDojo formatter
# ---------------------------------------------------------------------------

def drift_items_to_defectdojo_generic_findings(
    items: list[dict[str, Any]],
    scan_date: str,
    default_severity: str = "Medium",
) -> dict[str, Any]:
    """Converts normalized drift items to DefectDojo 'Generic Findings Import' JSON."""
    findings: list[dict[str, Any]] = []
    for item in items:
        address = str(item.get("address") or "unknown")
        severity = item.get("severity") or classify_drift_severity(
            str(item.get("type") or ""),
            item.get("changed_paths") or [],
            item.get("resource_id"),
            item.get("provenance"),
        )
        findings.append(
            {
                "title": f"Terraform drift detected: {address}",
                "vuln_id_from_tool": f"drift_type:{str(item.get('type') or 'unknown')}",
                "component_name": address,
                "unique_id_from_tool": (
                    f"cloudsentinel-drift:{str(item.get('type') or 'unknown')}:{address}"
                ),
                "severity": severity,
                "date": scan_date,
                "description": (
                    "CloudSentinel Drift Engine detected a configuration drift between "
                    "Terraform state and the live Azure resource.\n\n"
                    f"- Address: {address}\n"
                    f"- Resource type: {str(item.get('type') or 'unknown')}\n"
                    f"- Provider: {item.get('provider_name') or 'unknown'}\n"
                    f"- Actions: {item.get('actions') or []}\n"
                    f"- Changed paths (sample): {(item.get('changed_paths') or [])[:20]}\n"
                ),
                "mitigation": (
                    "Reconcile drift by running 'terraform apply' or reverting manual changes. "
                    "Consider enforcing Azure Policy / RBAC to prevent unmanaged changes."
                ),
                "references": "Terraform refresh-only plan output (internal).",
            }
        )
    return {"findings": findings}
