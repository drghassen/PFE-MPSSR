from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


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
            for k in sorted(set(a.keys()) | set(b.keys())):
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
    if len(paths) >= max_paths:
        logger.warning(
            "diff_paths_truncated: limit=%d reached — some changed paths may not appear in the report",
            max_paths,
        )
    return paths


def _extract_changed_paths(resource_change: dict[str, Any]) -> list[str]:
    from utils.plan_parser import _safe_dict
    change = _safe_dict(resource_change.get("change"))
    changed_paths = _diff_paths(change.get("before"), change.get("after"))
    return changed_paths if changed_paths else ["change"]
