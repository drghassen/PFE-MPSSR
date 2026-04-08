from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class DriftSummary:
    resources_changed: int
    resources_by_action: dict[str, int]
    provider_names: list[str]


def _actions_key(actions: list[str]) -> str:
    if not actions:
        return "unknown"
    return "+".join(actions)


def _iter_resource_changes(plan_json: dict[str, Any]) -> Iterable[dict[str, Any]]:
    for item in plan_json.get("resource_changes") or []:
        if isinstance(item, dict):
            yield item


def _safe_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _safe_list_str(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for v in value:
        if isinstance(v, str):
            out.append(v)
    return out


def _diff_paths(before: Any, after: Any, prefix: str = "", max_paths: int = 50) -> list[str]:
    """
    Lightweight structural diff that returns up to `max_paths` changed JSON paths.
    Values are not returned to avoid leaking sensitive data.
    """

    paths: list[str] = []

    def add(path: str) -> None:
        if len(paths) < max_paths:
            paths.append(path or "$")

    def walk(a: Any, b: Any, p: str) -> None:
        if len(paths) >= max_paths:
            return
        if type(a) != type(b):
            add(p)
            return
        if isinstance(a, dict):
            keys = set(a.keys()) | set(b.keys())
            for k in sorted(keys):
                if len(paths) >= max_paths:
                    return
                if k not in a or k not in b:
                    add(f"{p}.{k}" if p else k)
                    continue
                walk(a[k], b[k], f"{p}.{k}" if p else k)
            return
        if isinstance(a, list):
            if len(a) != len(b):
                add(p)
                # Still compare common prefix to avoid missing useful paths when under max_paths.
                common = min(len(a), len(b))
                for i in range(common):
                    if len(paths) >= max_paths:
                        return
                    walk(a[i], b[i], f"{p}[{i}]")
                for i in range(common, max(len(a), len(b))):
                    if len(paths) >= max_paths:
                        return
                    add(f"{p}[{i}]")
                return
            for i, (av, bv) in enumerate(zip(a, b)):
                if len(paths) >= max_paths:
                    return
                walk(av, bv, f"{p}[{i}]")
            return
        if a != b:
            add(p)

    walk(before, after, prefix)
    return paths


def normalize_terraform_plan(plan_json: dict[str, Any]) -> tuple[DriftSummary, list[dict[str, Any]]]:
    """
    Normalize `terraform show -json` output into a compact drift representation.
    """

    items: list[dict[str, Any]] = []
    provider_names: set[str] = set()
    resources_by_action: dict[str, int] = {}

    for rc in _iter_resource_changes(plan_json):
        change = _safe_dict(rc.get("change"))
        actions = _safe_list_str(change.get("actions"))

        # In refresh-only plans, no-op means no drift for that resource.
        if actions == ["no-op"]:
            continue

        address = str(rc.get("address") or "")
        mode = str(rc.get("mode") or "managed")
        rtype = str(rc.get("type") or "")
        name = str(rc.get("name") or "")
        provider_name = str(rc.get("provider_name") or "")
        if provider_name:
            provider_names.add(provider_name)

        before = change.get("before")
        after = change.get("after")

        changed_paths = _diff_paths(before, after)

        action_key = _actions_key(actions)
        resources_by_action[action_key] = resources_by_action.get(action_key, 0) + 1

        resource_id = None
        if isinstance(after, dict) and isinstance(after.get("id"), str):
            resource_id = after.get("id")
        elif isinstance(before, dict) and isinstance(before.get("id"), str):
            resource_id = before.get("id")

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
            }
        )

    summary = DriftSummary(
        resources_changed=len(items),
        resources_by_action=resources_by_action,
        provider_names=sorted(provider_names),
    )
    return summary, items


def drift_items_to_defectdojo_generic_findings(
    items: list[dict[str, Any]],
    scan_date: str,
    default_severity: str = "Medium",
) -> dict[str, Any]:
    """
    Converts normalized drift items to DefectDojo 'Generic Findings Import' JSON.
    """

    findings: list[dict[str, Any]] = []
    for item in items:
        address = str(item.get("address") or "unknown")
        actions = item.get("actions") or []
        changed_paths = item.get("changed_paths") or []
        provider_name = item.get("provider_name") or "unknown"

        findings.append(
            {
                "title": f"Terraform drift detected: {address}",
                "severity": default_severity,
                "date": scan_date,
                "description": (
                    "CloudSentinel Drift Engine detected a configuration drift between Terraform state "
                    "and the live Azure resource.\n\n"
                    f"- Address: {address}\n"
                    f"- Provider: {provider_name}\n"
                    f"- Actions: {actions}\n"
                    f"- Changed paths (sample): {changed_paths[:20]}\n"
                ),
                "mitigation": "Reconcile drift by running 'terraform apply' or reverting manual changes. Consider enforcing Azure Policy / RBAC to prevent unmanaged changes.",
                "references": "Terraform refresh-only plan output (internal).",
            }
        )

    return {"findings": findings}
