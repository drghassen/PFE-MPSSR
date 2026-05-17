import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import psycopg2
from psycopg2.extras import Json


CS_DIR = Path(os.getenv("CS_DIR", ".cloudsentinel"))
PG_DSN = os.getenv(
    "CS_PG_DSN",
    "host=localhost dbname=cloudsentinel user=cloudsentinel password=cloudsentinel123",
)
PIPELINE_ID = os.getenv(
    "CI_PIPELINE_ID",
    f"local-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
)


def load(name):
    path = CS_DIR / name
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def get(doc, path, default=None):
    value = doc
    for key in path:
        if not isinstance(value, dict) or key not in value:
            return default
        value = value[key]
    return value


def as_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def scanner_count(data, key):
    return as_int(data.get(key), 0)


def finding_row(pipeline_id, finding):
    source = finding.get("source") or {}
    resource = finding.get("resource") or {}
    location = resource.get("location") or {}
    severity = finding.get("severity") or {}
    remediation = finding.get("remediation") or {}
    context = finding.get("context") or {}
    dedup = context.get("deduplication") or {}
    git = context.get("git") or {}
    trace = context.get("traceability") or {}

    return (
        pipeline_id,
        finding.get("id"),
        source.get("tool", "unknown"),
        source.get("id"),
        source.get("scanner_type"),
        finding.get("category"),
        severity.get("level", "INFO"),
        finding.get("status", "FAILED"),
        finding.get("confidence"),
        resource.get("type"),
        resource.get("name"),
        resource.get("path"),
        location.get("file"),
        location.get("start_line"),
        location.get("end_line"),
        dedup.get("fingerprint"),
        bool(dedup.get("is_duplicate", False)),
        dedup.get("duplicate_of"),
        git.get("in_latest_push"),
        remediation.get("sla_hours"),
        trace.get("source_report"),
        trace.get("source_index"),
        trace.get("normalized_at"),
        finding.get("description"),
        Json(finding),
    )


def export_pipeline(cur, golden, opa, exceptions):
    meta = golden.get("metadata") or {}
    git = meta.get("git") or {}
    normalizer = meta.get("normalizer") or {}
    result = (opa or {}).get("result") or {}
    if result.get("allow") is True:
        gate = "ALLOW"
    elif result.get("allow") is False:
        gate = "DENY"
    else:
        gate = "UNKNOWN"
    exc_mode = get(
        exceptions or {},
        ["cloudsentinel", "exceptions", "metadata", "mode"],
        "UNKNOWN",
    )

    cur.execute(
        """
        INSERT INTO pipeline_runs
          (pipeline_id, scan_id, timestamp, environment, execution_mode, repository,
           branch, commit_sha, author_email, normalizer_version, gate_decision,
           exception_mode, updated_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now())
        ON CONFLICT (pipeline_id) DO UPDATE SET
          scan_id = EXCLUDED.scan_id,
          timestamp = EXCLUDED.timestamp,
          environment = EXCLUDED.environment,
          execution_mode = EXCLUDED.execution_mode,
          repository = EXCLUDED.repository,
          branch = EXCLUDED.branch,
          commit_sha = EXCLUDED.commit_sha,
          author_email = EXCLUDED.author_email,
          normalizer_version = EXCLUDED.normalizer_version,
          gate_decision = EXCLUDED.gate_decision,
          exception_mode = EXCLUDED.exception_mode,
          updated_at = now()
        """,
        (
            PIPELINE_ID,
            golden.get("scan_id") or meta.get("scan_id"),
            meta.get("timestamp"),
            meta.get("environment", "unknown"),
            get(meta, ["execution", "mode"], "unknown"),
            git.get("repository"),
            git.get("branch"),
            git.get("commit"),
            git.get("author_email"),
            normalizer.get("version"),
            gate,
            exc_mode,
        ),
    )


def export_scanner_stats(cur, golden):
    for tool, data in (get(golden, ["summary", "by_tool"], {}) or {}).items():
        cur.execute(
            """
            INSERT INTO scanner_stats
              (pipeline_id, scanner, status, count_critical, count_high, count_medium,
               count_low, count_info, count_total, count_exempted)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (pipeline_id, scanner) DO UPDATE SET
              status = EXCLUDED.status,
              count_critical = EXCLUDED.count_critical,
              count_high = EXCLUDED.count_high,
              count_medium = EXCLUDED.count_medium,
              count_low = EXCLUDED.count_low,
              count_info = EXCLUDED.count_info,
              count_total = EXCLUDED.count_total,
              count_exempted = EXCLUDED.count_exempted
            """,
            (
                PIPELINE_ID,
                tool,
                data.get("status", "NOT_RUN"),
                scanner_count(data, "CRITICAL"),
                scanner_count(data, "HIGH"),
                scanner_count(data, "MEDIUM"),
                scanner_count(data, "LOW"),
                scanner_count(data, "INFO"),
                scanner_count(data, "TOTAL"),
                scanner_count(data, "EXEMPTED"),
            ),
        )


def export_findings(cur, golden):
    cur.execute("DELETE FROM normalized_findings WHERE pipeline_id = %s", (PIPELINE_ID,))
    for finding in golden.get("findings", []) or []:
        cur.execute(
            """
            INSERT INTO normalized_findings
              (pipeline_id, finding_id, scanner, scanner_rule, scanner_type, category,
               severity, status, confidence, resource_type, resource_name, resource_path,
               resource_file, start_line, end_line, fingerprint, is_duplicate,
               duplicate_of, in_latest_push, sla_hours, source_report, source_index,
               normalized_at, description, raw_finding)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (pipeline_id, finding_id) DO UPDATE SET
              scanner = EXCLUDED.scanner,
              scanner_rule = EXCLUDED.scanner_rule,
              scanner_type = EXCLUDED.scanner_type,
              category = EXCLUDED.category,
              severity = EXCLUDED.severity,
              status = EXCLUDED.status,
              confidence = EXCLUDED.confidence,
              resource_type = EXCLUDED.resource_type,
              resource_name = EXCLUDED.resource_name,
              resource_path = EXCLUDED.resource_path,
              resource_file = EXCLUDED.resource_file,
              start_line = EXCLUDED.start_line,
              end_line = EXCLUDED.end_line,
              fingerprint = EXCLUDED.fingerprint,
              is_duplicate = EXCLUDED.is_duplicate,
              duplicate_of = EXCLUDED.duplicate_of,
              in_latest_push = EXCLUDED.in_latest_push,
              sla_hours = EXCLUDED.sla_hours,
              source_report = EXCLUDED.source_report,
              source_index = EXCLUDED.source_index,
              normalized_at = EXCLUDED.normalized_at,
              description = EXCLUDED.description,
              raw_finding = EXCLUDED.raw_finding
            """,
            finding_row(PIPELINE_ID, finding),
        )


def export_opa(cur, opa):
    cur.execute("DELETE FROM opa_decision_events WHERE pipeline_id = %s", (PIPELINE_ID,))
    if not opa:
        return

    result = opa.get("result") or {}
    metrics = result.get("metrics") or {}
    governance = metrics.get("governance") or {}
    gate = result.get("_gate") or {}

    cur.execute(
        """
        INSERT INTO opa_metrics
          (pipeline_id, allow, critical_effective, high_effective, failed_input,
           failed_effective, excepted_findings, active_break_glass,
           expired_enabled_exceptions, evaluated_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (pipeline_id) DO UPDATE SET
          allow = EXCLUDED.allow,
          critical_effective = EXCLUDED.critical_effective,
          high_effective = EXCLUDED.high_effective,
          failed_input = EXCLUDED.failed_input,
          failed_effective = EXCLUDED.failed_effective,
          excepted_findings = EXCLUDED.excepted_findings,
          active_break_glass = EXCLUDED.active_break_glass,
          expired_enabled_exceptions = EXCLUDED.expired_enabled_exceptions,
          evaluated_at = EXCLUDED.evaluated_at
        """,
        (
            PIPELINE_ID,
            result.get("allow"),
            as_int(metrics.get("critical")),
            as_int(metrics.get("high")),
            as_int(metrics.get("failed_input")),
            as_int(metrics.get("failed_effective")),
            as_int(metrics.get("excepted_findings")),
            as_int(governance.get("active_break_glass")),
            as_int(governance.get("expired_enabled_exceptions")),
            gate.get("evaluated_at"),
        ),
    )

    for event_type, key in (("DENY", "deny"), ("WARN", "warn")):
        for event in result.get(key, []) or []:
            message = event if isinstance(event, str) else json.dumps(event, sort_keys=True)
            cur.execute(
                """
                INSERT INTO opa_decision_events
                  (pipeline_id, event_type, message, raw_event)
                VALUES (%s,%s,%s,%s)
                ON CONFLICT (pipeline_id, event_type, message) DO UPDATE SET
                  raw_event = EXCLUDED.raw_event
                """,
                (
                    PIPELINE_ID,
                    event_type,
                    message,
                    Json(event if isinstance(event, dict) else {"message": message}),
                ),
            )


def export_drift(cur, drift):
    if not drift:
        return

    result = drift.get("result") or {}
    effective_ids = {
        item.get("resource_id")
        for item in result.get("effective_violations", []) or []
        if item.get("resource_id")
    }

    cur.execute("DELETE FROM drift_violations WHERE pipeline_id = %s", (PIPELINE_ID,))
    for violation in result.get("violations", []) or []:
        cur.execute(
            """
            INSERT INTO drift_violations
              (pipeline_id, timestamp, resource_id, severity, requires_remediation,
               custodian_policy, verification_script, correlation_id, is_effective,
               raw_violation)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                PIPELINE_ID,
                datetime.now(timezone.utc),
                violation.get("resource_id"),
                violation.get("severity", "INFO"),
                bool(violation.get("requires_remediation", False)),
                violation.get("custodian_policy"),
                violation.get("verification_script"),
                violation.get("correlation_id"),
                violation.get("resource_id") in effective_ids,
                Json(violation),
            ),
        )


def export_remediation(cur, remediation):
    if not remediation:
        return

    cur.execute(
        """
        INSERT INTO remediation_runs
          (pipeline_id, timestamp, total_candidates, verified, failed,
           skipped_unverifiable, remediation_failed)
        VALUES (%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (pipeline_id) DO UPDATE SET
          timestamp = EXCLUDED.timestamp,
          total_candidates = EXCLUDED.total_candidates,
          verified = EXCLUDED.verified,
          failed = EXCLUDED.failed,
          skipped_unverifiable = EXCLUDED.skipped_unverifiable,
          remediation_failed = EXCLUDED.remediation_failed
        """,
        (
            PIPELINE_ID,
            remediation.get("timestamp"),
            as_int(remediation.get("total_candidates")),
            as_int(remediation.get("verified")),
            as_int(remediation.get("failed")),
            as_int(remediation.get("skipped_unverifiable")),
            bool(remediation.get("remediation_failed", False)),
        ),
    )


def run():
    golden = load("golden_report.json")
    opa = load("opa_decision.json")
    drift = load("opa_drift_decision.json")
    remediation = load("runtime-state/remediation-summary.json")
    exceptions = load("exceptions.json")

    if not golden:
        print("[CS-METRICS] golden_report.json introuvable - export ignore")
        sys.exit(0)

    conn = psycopg2.connect(PG_DSN)
    try:
        with conn:
            with conn.cursor() as cur:
                export_pipeline(cur, golden, opa, exceptions)
                export_scanner_stats(cur, golden)
                export_findings(cur, golden)
                export_opa(cur, opa)
                export_drift(cur, drift)
                export_remediation(cur, remediation)
    finally:
        conn.close()

    print(f"[CS-METRICS] Pipeline {PIPELINE_ID} exporte vers PostgreSQL")


if __name__ == "__main__":
    run()
