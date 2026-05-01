from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Iterable

logger = logging.getLogger(__name__)


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
    # For refresh-only plans, Terraform/OpenTofu may put the actual drift under
    # `resource_drift` instead of `resource_changes`.
    for item in plan_json.get("resource_drift") or []:
        if isinstance(item, dict):
            yield item
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


def _iter_configuration_resources(
    plan_json: dict[str, Any],
) -> Iterable[tuple[str, dict[str, Any]]]:
    """
    Iterate resources from plan.configuration.root_module (and nested module calls)
    and return canonical resource addresses with their config metadata.
    """

    configuration = _safe_dict(plan_json.get("configuration"))
    root = _safe_dict(configuration.get("root_module"))
    if not root:
        return

    stack: list[tuple[str, dict[str, Any]]] = [("", root)]
    while stack:
        prefix, module_obj = stack.pop()

        for resource in module_obj.get("resources") or []:
            if not isinstance(resource, dict):
                continue
            raw_address = str(resource.get("address") or "").strip()
            if not raw_address:
                continue

            # Terraform may already emit absolute addresses in nested modules.
            if raw_address.startswith("module."):
                full_address = raw_address
            else:
                full_address = f"{prefix}{raw_address}" if prefix else raw_address

            yield full_address, resource

        module_calls = _safe_dict(module_obj.get("module_calls"))
        for call_name, call_obj in module_calls.items():
            if not isinstance(call_name, str) or not call_name:
                continue
            call = _safe_dict(call_obj)
            child_module = _safe_dict(call.get("module"))
            if not child_module:
                continue
            child_prefix = f"{prefix}module.{call_name}."
            stack.append((child_prefix, child_module))


def _configuration_resource_index(plan_json: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for address, resource in _iter_configuration_resources(plan_json):
        out[address] = {
            "mode": str(resource.get("mode") or "managed"),
            "type": str(resource.get("type") or ""),
            "name": str(resource.get("name") or ""),
            "provider_name": str(resource.get("provider_config_key") or ""),
        }
    return out


def _output_reference_map(plan_json: dict[str, Any]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    configuration = _safe_dict(plan_json.get("configuration"))
    root = _safe_dict(configuration.get("root_module"))
    outputs = _safe_dict(root.get("outputs"))
    for output_name, output_obj in outputs.items():
        if not isinstance(output_name, str) or not output_name:
            continue
        obj = _safe_dict(output_obj)
        expr = _safe_dict(obj.get("expression"))
        refs = _safe_list_str(expr.get("references"))
        if refs:
            out[output_name] = refs
    return out


def _guess_resource_address_from_reference(ref: str) -> str | None:
    """
    Best-effort extraction of a resource address from a Terraform expression reference.
    Returns None when the reference is clearly non-resource (var/local/module output/etc.).
    """

    tokens = [t for t in ref.split(".") if t]
    if len(tokens) < 2:
        return None

    for idx in range(0, len(tokens) - 1):
        current = tokens[idx]
        nxt = tokens[idx + 1]
        if current in {"var", "local", "path", "terraform", "each", "count"}:
            continue
        if current == "data":
            continue
        if current == "module":
            continue
        # Resource types in Terraform are snake_case provider-prefixed names.
        if "_" not in current:
            continue
        if nxt in {"*", "id"}:
            continue
        # Remove traversal index only from the resource name token.
        resource_name = nxt.split("[", 1)[0]
        if not resource_name:
            continue
        prefix = ".".join(tokens[:idx])
        if prefix:
            return f"{prefix}.{current}.{resource_name}"
        return f"{current}.{resource_name}"
    return None


def _resource_type_from_address(address: str) -> str:
    parts = [p for p in address.split(".") if p]
    if len(parts) < 2:
        return "unknown"
    if parts[0] == "module":
        # module.<name>.<resource_type>.<resource_name>
        for idx in range(2, len(parts)):
            if "_" in parts[idx]:
                return parts[idx]
        return "unknown"
    if parts[0] == "data":
        if len(parts) >= 3:
            return parts[1]
        return "unknown"
    return parts[0]


def _resource_name_from_address(address: str) -> str:
    parts = [p for p in address.split(".") if p]
    if len(parts) < 2:
        return ""
    # Last meaningful token is usually the resource name or index selector.
    token = parts[-1]
    return token.split("[", 1)[0]


def _diff_paths(
    before: Any, after: Any, prefix: str = "", max_paths: int = 50
) -> list[str]:
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
        if type(a) is not type(b):
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


def _extract_changed_paths(resource_change: dict[str, Any]) -> list[str]:
    change = _safe_dict(resource_change.get("change"))
    changed_paths = _diff_paths(change.get("before"), change.get("after"))
    if changed_paths:
        return changed_paths
    return ["change"]


def _infer_resources_from_outputs(
    plan_json: dict[str, Any],
    output_changes: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Infer managed-resource drift from changed Terraform outputs.

    If the plan JSON does not include configuration, inference is skipped because
    output expressions are the only reliable provenance graph.
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

    inferred: list[dict[str, Any]] = []
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

    for output_name, output_cfg in outputs_config.items():
        if output_name not in output_changes:
            continue
        if not isinstance(output_cfg, dict):
            continue
        references = _safe_list_str(
            _safe_dict(output_cfg.get("expression")).get("references")
        )
        for ref in references:
            if ref in resource_changes:
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


def normalize_terraform_plan(
    plan_json: dict[str, Any],
) -> tuple[DriftSummary, list[dict[str, Any]]]:
    """
    Normalize `terraform show -json` output into a compact drift representation.
    """

    items: list[dict[str, Any]] = []
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

        before = change.get("before")
        after = change.get("after")

        changed_paths = _diff_paths(before, after)

        # For `plan -refresh-only`, provider often reports `actions=["no-op"]` even when
        # the state is refreshed to different values. Treat "no-op + diff" as drift.
        if not changed_paths:
            continue
        if address:
            seen.add(address)

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
                "drifted": True,
            }
        )

    # Also capture output-level drift, which can be the only thing that changes in refresh-only plans.
    output_changes = plan_json.get("output_changes") or {}
    if isinstance(output_changes, dict):
        for out_name, out_change in sorted(output_changes.items()):
            if not isinstance(out_name, str):
                continue
            if not isinstance(out_change, dict):
                continue
            before = out_change.get("before")
            after = out_change.get("after")
            changed_paths = _diff_paths(before, after)
            if not changed_paths:
                continue
            actions = _safe_list_str(out_change.get("actions")) or ["update"]
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

        for inferred_item in _infer_resources_from_outputs(plan_json, output_changes):
            address = str(inferred_item.get("address") or "")
            if address and address in seen:
                continue
            if address:
                seen.add(address)
            provider_name = str(inferred_item.get("provider_name") or "")
            if provider_name:
                provider_names.add(provider_name)
            action_key = _actions_key(_safe_list_str(inferred_item.get("actions")))
            resources_by_action[action_key] = resources_by_action.get(action_key, 0) + 1
            items.append(inferred_item)

    summary = DriftSummary(
        resources_changed=len(items),
        resources_by_action=resources_by_action,
        provider_names=sorted(provider_names),
    )
    return summary, items


_SEVERITY_MAP: dict[tuple[str, str], str] = {
    ("azurerm_network_security_group", "security_rule"): "Critical",
    ("azurerm_network_security_rule", "access"): "Critical",
    ("azurerm_linux_virtual_machine", "admin_password"): "Critical",
    ("azurerm_key_vault", "access_policy"): "High",
    ("azurerm_key_vault", "network_acls"): "High",
    ("azurerm_storage_account", "min_tls_version"): "High",
    ("azurerm_storage_account", "allow_blob_public_access"): "High",
    ("azurerm_sql_server", "administrator_login_password"): "Critical",
    ("azurerm_monitor_diagnostic_setting", "enabled_log"): "Medium",
    ("azurerm_log_analytics_workspace", "retention_in_days"): "Low",
}

RESOURCE_TYPE_SEVERITY_MAP = {
    "azurerm_virtual_machine": "High",
    "azurerm_linux_virtual_machine": "High",
    "azurerm_storage_account": "High",
    "azurerm_sql_server": "High",
    "azurerm_key_vault": "High",
    "azurerm_network_security_group": "Medium",
    "azurerm_resource_group": "Low",
    "azurerm_virtual_network": "Low",
    "_default": "Medium",
}


def classify_drift_severity(
    resource_type: str,
    changed_paths: list[str],
    resource_id: str | None = None,
    provenance: str | None = None,
) -> str:
    if resource_id is None and provenance == "inferred_from_output":
        return RESOURCE_TYPE_SEVERITY_MAP.get(
            resource_type,
            RESOURCE_TYPE_SEVERITY_MAP["_default"],
        )
    for path in changed_paths:
        segment = path.split(".")[0]
        key = (resource_type, segment)
        if key in _SEVERITY_MAP:
            return _SEVERITY_MAP[key]
    return "Medium"


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

        # If OPA already evaluated this item (via enrich_drift_items_with_opa),
        # use its severity directly to avoid overwriting OPA decision with the
        # static classify_drift_severity() fallback.
        if item.get("opa_evaluated"):
            severity = item.get("severity") or default_severity
        else:
            severity = classify_drift_severity(
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
                "unique_id_from_tool": f"cloudsentinel-drift:{str(item.get('type') or 'unknown')}:{address}",
                "severity": severity,
                "date": scan_date,
                "description": (
                    "CloudSentinel Drift Engine detected a configuration drift between Terraform state "
                    "and the live Azure resource.\n\n"
                    f"- Address: {address}\n"
                    f"- Resource type: {str(item.get('type') or 'unknown')}\n"
                    f"- Provider: {provider_name}\n"
                    f"- Actions: {actions}\n"
                    f"- Changed paths (sample): {changed_paths[:20]}\n"
                ),
                "mitigation": "Reconcile drift by running 'terraform apply' or reverting manual changes. Consider enforcing Azure Policy / RBAC to prevent unmanaged changes.",
                "references": "Terraform refresh-only plan output (internal).",
            }
        )

    return {"findings": findings}
