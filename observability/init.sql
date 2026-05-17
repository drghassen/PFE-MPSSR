CREATE TABLE IF NOT EXISTS pipeline_runs (
  pipeline_id        TEXT PRIMARY KEY,
  scan_id            TEXT NOT NULL,
  timestamp          TIMESTAMPTZ NOT NULL,
  environment        TEXT NOT NULL DEFAULT 'unknown',
  execution_mode     TEXT NOT NULL DEFAULT 'unknown',
  repository         TEXT,
  branch             TEXT,
  commit_sha         TEXT,
  author_email       TEXT,
  normalizer_version TEXT,
  gate_decision      TEXT NOT NULL DEFAULT 'UNKNOWN',
  exception_mode     TEXT NOT NULL DEFAULT 'UNKNOWN',
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT pipeline_runs_gate_decision_chk CHECK (gate_decision IN ('ALLOW', 'DENY', 'UNKNOWN'))
);

ALTER TABLE pipeline_runs ADD COLUMN IF NOT EXISTS execution_mode TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE pipeline_runs ADD COLUMN IF NOT EXISTS repository TEXT;
ALTER TABLE pipeline_runs ADD COLUMN IF NOT EXISTS normalizer_version TEXT;
ALTER TABLE pipeline_runs ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE pipeline_runs ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

CREATE TABLE IF NOT EXISTS scanner_stats (
  id             SERIAL PRIMARY KEY,
  pipeline_id    TEXT NOT NULL REFERENCES pipeline_runs(pipeline_id) ON DELETE CASCADE,
  scanner        TEXT NOT NULL,
  status         TEXT NOT NULL,
  count_critical INT NOT NULL DEFAULT 0,
  count_high     INT NOT NULL DEFAULT 0,
  count_medium   INT NOT NULL DEFAULT 0,
  count_low      INT NOT NULL DEFAULT 0,
  count_info     INT NOT NULL DEFAULT 0,
  count_total    INT NOT NULL DEFAULT 0,
  count_exempted INT NOT NULL DEFAULT 0,
  inserted_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

DELETE FROM scanner_stats a
USING scanner_stats b
WHERE a.id > b.id
  AND a.pipeline_id = b.pipeline_id
  AND a.scanner = b.scanner;

CREATE UNIQUE INDEX IF NOT EXISTS scanner_stats_pipeline_scanner_uidx
  ON scanner_stats(pipeline_id, scanner);

CREATE TABLE IF NOT EXISTS normalized_findings (
  id             SERIAL PRIMARY KEY,
  pipeline_id    TEXT NOT NULL REFERENCES pipeline_runs(pipeline_id) ON DELETE CASCADE,
  finding_id     TEXT NOT NULL,
  scanner        TEXT NOT NULL,
  scanner_rule   TEXT,
  scanner_type   TEXT,
  category       TEXT,
  severity       TEXT NOT NULL,
  status         TEXT NOT NULL,
  confidence     TEXT,
  resource_type  TEXT,
  resource_name  TEXT,
  resource_path  TEXT,
  resource_file  TEXT,
  start_line     INT,
  end_line       INT,
  fingerprint    TEXT,
  is_duplicate   BOOLEAN NOT NULL DEFAULT false,
  duplicate_of   TEXT,
  in_latest_push BOOLEAN,
  sla_hours      INT,
  source_report  TEXT,
  source_index   INT,
  normalized_at  TIMESTAMPTZ,
  description    TEXT,
  raw_finding     JSONB NOT NULL DEFAULT '{}'::jsonb,
  inserted_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS normalized_findings_pipeline_finding_uidx
  ON normalized_findings(pipeline_id, finding_id);
CREATE INDEX IF NOT EXISTS normalized_findings_latest_idx
  ON normalized_findings(pipeline_id, severity, scanner, category);
CREATE INDEX IF NOT EXISTS normalized_findings_fingerprint_idx
  ON normalized_findings(fingerprint);

CREATE TABLE IF NOT EXISTS opa_metrics (
  pipeline_id                  TEXT PRIMARY KEY REFERENCES pipeline_runs(pipeline_id) ON DELETE CASCADE,
  allow                        BOOLEAN,
  critical_effective           INT NOT NULL DEFAULT 0,
  high_effective               INT NOT NULL DEFAULT 0,
  failed_input                 INT NOT NULL DEFAULT 0,
  failed_effective             INT NOT NULL DEFAULT 0,
  excepted_findings            INT NOT NULL DEFAULT 0,
  active_break_glass           INT NOT NULL DEFAULT 0,
  expired_enabled_exceptions   INT NOT NULL DEFAULT 0,
  evaluated_at                 TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS opa_decision_events (
  id          SERIAL PRIMARY KEY,
  pipeline_id TEXT NOT NULL REFERENCES pipeline_runs(pipeline_id) ON DELETE CASCADE,
  event_type  TEXT NOT NULL,
  message     TEXT NOT NULL,
  raw_event   JSONB NOT NULL DEFAULT '{}'::jsonb,
  inserted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT opa_decision_events_type_chk CHECK (event_type IN ('DENY', 'WARN'))
);

CREATE UNIQUE INDEX IF NOT EXISTS opa_decision_events_pipeline_type_message_uidx
  ON opa_decision_events(pipeline_id, event_type, message);

CREATE TABLE IF NOT EXISTS drift_violations (
  id                    SERIAL PRIMARY KEY,
  pipeline_id           TEXT NOT NULL REFERENCES pipeline_runs(pipeline_id) ON DELETE CASCADE,
  timestamp             TIMESTAMPTZ NOT NULL,
  resource_id           TEXT NOT NULL,
  severity              TEXT NOT NULL,
  requires_remediation  BOOLEAN NOT NULL DEFAULT false,
  custodian_policy      TEXT,
  verification_script   TEXT,
  correlation_id        TEXT,
  is_effective          BOOLEAN NOT NULL DEFAULT false,
  raw_violation         JSONB NOT NULL DEFAULT '{}'::jsonb,
  inserted_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE drift_violations ADD COLUMN IF NOT EXISTS verification_script TEXT;
ALTER TABLE drift_violations ADD COLUMN IF NOT EXISTS correlation_id TEXT;
ALTER TABLE drift_violations ADD COLUMN IF NOT EXISTS raw_violation JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE drift_violations ADD COLUMN IF NOT EXISTS inserted_at TIMESTAMPTZ NOT NULL DEFAULT now();

DELETE FROM drift_violations a
USING drift_violations b
WHERE a.id > b.id
  AND a.pipeline_id = b.pipeline_id
  AND a.resource_id = b.resource_id
  AND COALESCE(a.custodian_policy, '') = COALESCE(b.custodian_policy, '');

CREATE UNIQUE INDEX IF NOT EXISTS drift_violations_pipeline_resource_policy_uidx
  ON drift_violations(pipeline_id, resource_id, COALESCE(custodian_policy, ''));

CREATE TABLE IF NOT EXISTS remediation_runs (
  id                      SERIAL PRIMARY KEY,
  pipeline_id             TEXT NOT NULL REFERENCES pipeline_runs(pipeline_id) ON DELETE CASCADE,
  timestamp               TIMESTAMPTZ NOT NULL,
  total_candidates        INT NOT NULL DEFAULT 0,
  verified                INT NOT NULL DEFAULT 0,
  failed                  INT NOT NULL DEFAULT 0,
  skipped_unverifiable    INT NOT NULL DEFAULT 0,
  remediation_failed      BOOLEAN NOT NULL DEFAULT false,
  inserted_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

DELETE FROM remediation_runs a
USING remediation_runs b
WHERE a.id > b.id
  AND a.pipeline_id = b.pipeline_id;

CREATE UNIQUE INDEX IF NOT EXISTS remediation_runs_pipeline_uidx
  ON remediation_runs(pipeline_id);

CREATE OR REPLACE VIEW v_latest_pipeline AS
SELECT pr.*
FROM pipeline_runs pr
ORDER BY pr.updated_at DESC, pr.timestamp DESC, pr.pipeline_id DESC
LIMIT 1;

CREATE OR REPLACE VIEW v_security_posture_latest AS
WITH latest AS (
  SELECT *
  FROM pipeline_runs
  ORDER BY updated_at DESC, timestamp DESC, pipeline_id DESC
  LIMIT 1
),
drift AS (
  SELECT pipeline_id, count(*) FILTER (WHERE is_effective) AS effective_drift
  FROM drift_violations
  GROUP BY pipeline_id
),
remediation AS (
  SELECT
    pipeline_id,
    sum(total_candidates) AS total_candidates,
    sum(verified) AS verified,
    sum(failed) AS failed,
    bool_or(remediation_failed) AS remediation_failed
  FROM remediation_runs
  GROUP BY pipeline_id
)
SELECT
  latest.pipeline_id,
  latest.scan_id,
  latest.timestamp,
  latest.environment,
  latest.branch,
  latest.commit_sha,
  latest.gate_decision,
  latest.exception_mode,
  COALESCE(om.critical_effective, 0) AS critical_effective,
  COALESCE(om.high_effective, 0) AS high_effective,
  COALESCE(om.failed_input, 0) AS failed_input,
  COALESCE(om.failed_effective, 0) AS failed_effective,
  COALESCE(om.excepted_findings, 0) AS excepted_findings,
  COALESCE(om.active_break_glass, 0) AS active_break_glass,
  COALESCE(om.expired_enabled_exceptions, 0) AS expired_enabled_exceptions,
  COALESCE(drift.effective_drift, 0) AS effective_drift,
  COALESCE(remediation.total_candidates, 0) AS remediation_candidates,
  COALESCE(remediation.verified, 0) AS remediation_verified,
  COALESCE(remediation.failed, 0) AS remediation_failed_count,
  COALESCE(remediation.remediation_failed, false) AS remediation_failed,
  CASE
    WHEN COALESCE(remediation.total_candidates, 0) = 0 THEN NULL
    ELSE round((remediation.verified::numeric / NULLIF(remediation.total_candidates, 0)) * 100, 2)
  END AS remediation_rate,
  GREATEST(0, LEAST(100,
    100
    - COALESCE(om.critical_effective, 0) * 25
    - COALESCE(om.high_effective, 0) * 10
    - COALESCE(om.failed_effective, 0) * 8
    - COALESCE(drift.effective_drift, 0) * 20
    - COALESCE(om.active_break_glass, 0) * 30
    - COALESCE(om.expired_enabled_exceptions, 0) * 15
    - CASE WHEN COALESCE(remediation.remediation_failed, false) THEN 20 ELSE 0 END
  ))::INT AS posture_score
FROM latest
LEFT JOIN opa_metrics om ON om.pipeline_id = latest.pipeline_id
LEFT JOIN drift ON drift.pipeline_id = latest.pipeline_id
LEFT JOIN remediation ON remediation.pipeline_id = latest.pipeline_id;

CREATE OR REPLACE VIEW v_scanner_latest AS
SELECT ss.*
FROM scanner_stats ss
JOIN v_latest_pipeline lp ON lp.pipeline_id = ss.pipeline_id;

CREATE OR REPLACE VIEW v_findings_latest AS
SELECT nf.*
FROM normalized_findings nf
JOIN v_latest_pipeline lp ON lp.pipeline_id = nf.pipeline_id;

CREATE OR REPLACE VIEW v_drift_latest AS
SELECT dv.*
FROM drift_violations dv
JOIN v_latest_pipeline lp ON lp.pipeline_id = dv.pipeline_id;
