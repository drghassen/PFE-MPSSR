#!/usr/bin/env python3
"""Exception mapping, output and audit emission logic."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple

from .fetch_utils import now_utc, parse_datetime, safe_str, save_json, to_rfc3339, ensure_dir
from .fetch_validation import FetchContext, extract_v2_exception, is_active_accepted, legacy_window_open


def emit_audit_event(ctx: FetchContext, event_type: str, payload: Dict[str, Any]) -> None:
    event = {
        "timestamp": to_rfc3339(now_utc()),
        "component": "fetch-exceptions",
        "event_type": event_type,
        **payload,
    }
    ensure_dir(ctx.audit_log_file)
    with open(ctx.audit_log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, separators=(",", ":")) + "\n")


def json_payload(ctx: FetchContext, exceptions: List[Dict[str, Any]], meta: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "cloudsentinel": {
            "exceptions": {
                "schema_version": ctx.schema_version,
                "generated_at": to_rfc3339(now_utc()),
                "legacy_compatibility": {
                    "enabled": ctx.legacy_compat,
                    "sunset_date": ctx.legacy_sunset_date,
                },
                "metadata": meta,
                "exceptions": exceptions,
            }
        }
    }


def drop(ctx: FetchContext, ra: Dict[str, Any], reason: str) -> None:
    record = {
        "id": f"RA-{safe_str(ra.get('id')) or 'unknown'}",
        "reason": reason,
        "dropped_at": to_rfc3339(now_utc()),
    }
    ctx.dropped.append(record)
    ctx.logger.warning(f"Dropping risk acceptance {record['id']}: {reason}")
    emit_audit_event(ctx, "exception_dropped", record)


def save_outputs(ctx: FetchContext, payload: Dict[str, Any]) -> None:
    save_json(ctx.output_file, payload)
    save_json(ctx.dropped_file, {"dropped_exceptions": ctx.dropped})


def map_risk_acceptances(ctx: FetchContext, raw_ras: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    mapped: List[Dict[str, Any]] = []

    for ra in raw_ras:
        if not is_active_accepted(ra):
            continue

        ex, error = extract_v2_exception(ctx, ra)
        if ex is None:
            drop(ctx, ra, error or "unknown mapping error")
            continue

        mapped.append(ex)
        emit_audit_event(
            ctx,
            "exception_mapped",
            {
                "exception_id": ex["exception_id"],
                "scanner": ex["scanner"],
                "scope_type": ex["scope_type"],
                "break_glass": ex["break_glass"],
                "expires_at": ex.get("expires_at"),
            },
        )

    approval_durations: List[float] = []
    active_break_glass = 0
    active_by_severity = {sev: 0 for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}

    for ex in mapped:
        sev = ex.get("severity", "MEDIUM")
        if sev in active_by_severity:
            active_by_severity[sev] += 1
        if ex.get("break_glass", False):
            active_break_glass += 1

        approved_at = parse_datetime(safe_str(ex.get("approved_at")))
        created_at = parse_datetime(safe_str(ex.get("created_at")))
        if approved_at and created_at and approved_at >= created_at:
            approval_durations.append((approved_at - created_at).total_seconds() / 3600.0)

    avg_approval_hours = round(sum(approval_durations) / len(approval_durations), 2) if approval_durations else 0.0

    meta = {
        "source": "defectdojo",
        "repo": ctx.ci_project_path,
        "branch": ctx.ci_commit_ref_name,
        "legacy_mode": ctx.legacy_compat and legacy_window_open(ctx),
        "legacy_sunset": ctx.legacy_sunset_date,
        "total_raw": len(raw_ras),
        "total_mapped": len(mapped),
        "total_dropped": len(ctx.dropped),
        "governance_metrics": {
            "active_by_severity": active_by_severity,
            "active_break_glass": active_break_glass,
            "expired_dropped": len([d for d in ctx.dropped if "expired" in d.get("reason", "")]),
            "avg_approval_time_hours": avg_approval_hours,
        },
    }

    if ctx.legacy_compat and not legacy_window_open(ctx):
        ctx.logger.warning("Legacy compatibility window is closed by sunset date")

    return mapped, meta
