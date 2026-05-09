from __future__ import annotations

from typing import Any, Iterable


def _safe_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _safe_list_str(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [v for v in value if isinstance(v, str)]


def _actions_key(actions: list[str]) -> str:
    return "+".join(actions) if actions else "unknown"


def _iter_resource_changes(plan_json: dict[str, Any]) -> Iterable[dict[str, Any]]:
    # For refresh-only plans, drift appears under `resource_drift` first.
    for item in plan_json.get("resource_drift") or []:
        if isinstance(item, dict):
            yield item
    for item in plan_json.get("resource_changes") or []:
        if isinstance(item, dict):
            yield item


def _iter_configuration_resources(
    plan_json: dict[str, Any],
) -> Iterable[tuple[str, dict[str, Any]]]:
    """Iterate resources from plan.configuration.root_module (and nested modules)."""
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
            full_address = (
                raw_address
                if raw_address.startswith("module.")
                else (f"{prefix}{raw_address}" if prefix else raw_address)
            )
            yield full_address, resource

        module_calls = _safe_dict(module_obj.get("module_calls"))
        for call_name, call_obj in module_calls.items():
            if not isinstance(call_name, str) or not call_name:
                continue
            child_module = _safe_dict(_safe_dict(call_obj).get("module"))
            if child_module:
                stack.append((f"{prefix}module.{call_name}.", child_module))


def _configuration_resource_index(plan_json: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        address: {
            "mode": str(resource.get("mode") or "managed"),
            "type": str(resource.get("type") or ""),
            "name": str(resource.get("name") or ""),
            "provider_name": str(resource.get("provider_config_key") or ""),
        }
        for address, resource in _iter_configuration_resources(plan_json)
    }


def _output_reference_map(plan_json: dict[str, Any]) -> dict[str, list[str]]:
    root = _safe_dict(
        _safe_dict(plan_json.get("configuration")).get("root_module")
    )
    outputs = _safe_dict(root.get("outputs"))
    result: dict[str, list[str]] = {}
    for output_name, output_obj in outputs.items():
        if not isinstance(output_name, str) or not output_name:
            continue
        refs = _safe_list_str(
            _safe_dict(_safe_dict(output_obj).get("expression")).get("references")
        )
        if refs:
            result[output_name] = refs
    return result


def _guess_resource_address_from_reference(ref: str) -> str | None:
    """Best-effort extraction of a resource address from a Terraform expression reference."""
    tokens = [t for t in ref.split(".") if t]
    if len(tokens) < 2:
        return None
    for idx in range(len(tokens) - 1):
        current = tokens[idx]
        nxt = tokens[idx + 1]
        if current in {"var", "local", "path", "terraform", "each", "count", "data", "module"}:
            continue
        if "_" not in current:
            continue
        if nxt in {"*", "id"}:
            continue
        resource_name = nxt.split("[", 1)[0]
        if not resource_name:
            continue
        prefix = ".".join(tokens[:idx])
        return f"{prefix}.{current}.{resource_name}" if prefix else f"{current}.{resource_name}"
    return None


def _resource_type_from_address(address: str) -> str:
    parts = [p for p in address.split(".") if p]
    if len(parts) < 2:
        return "unknown"
    if parts[0] == "module":
        return next((p for p in parts[2:] if "_" in p), "unknown")
    if parts[0] == "data":
        return parts[1] if len(parts) >= 3 else "unknown"
    return parts[0]


def _resource_name_from_address(address: str) -> str:
    parts = [p for p in address.split(".") if p]
    return parts[-1].split("[", 1)[0] if len(parts) >= 2 else ""
