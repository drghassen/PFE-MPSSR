#!/usr/bin/env bash

# ==============================================================================
# CloudSentinel Normalizer
# Description: Merges scanner outputs (Gitleaks, Checkov, Trivy) into a
#              unified Golden Report consumed by OPA as the single gatekeeper.
# ==============================================================================

set -euo pipefail

log_info() { echo -e "\e[34m[INFO]\e[0m $1"; }
log_warn() { echo -e "\e[33m[WARN]\e[0m $1" >&2; }
log_error() { echo -e "\e[31m[ERROR]\e[0m $1" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || log_error "Missing required command: $1"
}

now_ms() {
  date +%s%3N 2>/dev/null || printf '%s000' "$(date +%s)"
}

ROOT_DIR=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
OUTPUT_DIR="${ROOT_DIR}/.cloudsentinel"
OUTPUT_FILE="${OUTPUT_DIR}/golden_report.json"
SCHEMA_VERSION="1.1.0"
ENVIRONMENT="${ENVIRONMENT:-${CI_ENVIRONMENT_NAME:-dev}}"

EXECUTION_MODE="${CLOUDSENTINEL_EXECUTION_MODE:-}"
if [[ -z "$EXECUTION_MODE" ]]; then
  if [[ -n "${CI:-}" ]]; then
    EXECUTION_MODE="ci"
  else
    EXECUTION_MODE="local"
  fi
fi

case "${EXECUTION_MODE,,}" in
  ci|local|advisory)
    EXECUTION_MODE="${EXECUTION_MODE,,}"
    ;;
  *)
    log_warn "Unknown EXECUTION_MODE='${EXECUTION_MODE}'. Falling back to 'local'."
    EXECUTION_MODE="local"
    ;;
esac

LOCAL_FAST="${CLOUDSENTINEL_LOCAL_FAST:-}"
SCHEMA_STRICT="${CLOUDSENTINEL_SCHEMA_STRICT:-false}"
if [[ -z "$LOCAL_FAST" ]]; then
  if [[ "$EXECUTION_MODE" == "local" || "$EXECUTION_MODE" == "advisory" ]]; then
    LOCAL_FAST="true"
  else
    LOCAL_FAST="false"
  fi
fi

case "${LOCAL_FAST,,}" in
  true|false)
    LOCAL_FAST="${LOCAL_FAST,,}"
    ;;
  *)
    log_warn "Unknown LOCAL_FAST='${LOCAL_FAST}'. Falling back to 'false'."
    LOCAL_FAST="false"
    ;;
esac

case "${SCHEMA_STRICT,,}" in
  true|false)
    SCHEMA_STRICT="${SCHEMA_STRICT,,}"
    ;;
  *)
    log_warn "Unknown SCHEMA_STRICT='${SCHEMA_STRICT}'. Falling back to 'false'."
    SCHEMA_STRICT="false"
    ;;
esac

case "${ENVIRONMENT,,}" in
  dev|test|staging|prod)
    ENVIRONMENT="${ENVIRONMENT,,}"
    ;;
  stage)
    ENVIRONMENT="staging"
    ;;
  *)
    log_warn "Unknown ENVIRONMENT='${ENVIRONMENT}'. Falling back to 'dev'."
    ENVIRONMENT="dev"
    ;;
esac

# NOTE: Thresholds (CRITICAL_MAX, HIGH_MAX) are captured here to expose contractually
# the gate configuration to OPA and to downstream audit. OPA remains the single
# decision-maker; this script only embeds the requested limits in the input.

GITLEAKS_REPORT="${ROOT_DIR}/.cloudsentinel/gitleaks_opa.json"
CHECKOV_REPORT="${ROOT_DIR}/.cloudsentinel/checkov_opa.json"
TRIVY_REPORT_PRIMARY="${ROOT_DIR}/.cloudsentinel/trivy_opa.json"
TRIVY_REPORT_LEGACY="${ROOT_DIR}/shift-left/trivy/reports/opa/trivy_opa.json"
if [[ -f "$TRIVY_REPORT_PRIMARY" ]]; then
  TRIVY_REPORT="$TRIVY_REPORT_PRIMARY"
elif [[ -f "$TRIVY_REPORT_LEGACY" ]]; then
  TRIVY_REPORT="$TRIVY_REPORT_LEGACY"
else
  TRIVY_REPORT="$TRIVY_REPORT_PRIMARY"
fi

# --- Thresholds: sanitize to non-negative integers (fallback 0/2) ------------
parse_threshold() {
  local value="$1" fallback="$2"
  if [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "$value"
  else
    echo "$fallback"
  fi
}

CRITICAL_MAX_INT=$(parse_threshold "${CRITICAL_MAX:-}" 0)
HIGH_MAX_INT=$(parse_threshold "${HIGH_MAX:-}" 2)

hash_file() {
  local file=$1
  if [[ ! -f "$file" ]]; then
    echo ""
    return
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
    return
  fi
  echo ""
}

report_trace() {
  local file=$1
  local tool=$2
  local skip=${3:-false}
  local present=false
  local valid_json=false
  local status="NOT_RUN"
  local reason=""
  local checksum=""

  if [[ "$skip" == "true" ]]; then
    reason="skipped_local_fast"
  elif [[ -f "$file" ]]; then
    present=true
    if jq -e '.' "$file" >/dev/null 2>&1; then
      valid_json=true
      checksum="$(hash_file "$file")"
      status="$(jq -r '
        (
          .status
          // (if ((.has_findings // false) == true or ((.stats.TOTAL // 0) > 0))
              then "FAILED"
              else "PASSED"
              end)
        )
        | tostring
        | ascii_upcase
      ' "$file" 2>/dev/null || echo "NOT_RUN")"
      if [[ "$status" != "PASSED" && "$status" != "FAILED" && "$status" != "NOT_RUN" ]]; then
        status="NOT_RUN"
      fi
    else
      reason="invalid_json"
    fi
  else
    reason="missing_report"
  fi

  jq -n \
    --arg tool "$tool" \
    --arg path "$file" \
    --arg status "$status" \
    --arg reason "$reason" \
    --arg checksum "$checksum" \
    --argjson present "$present" \
    --argjson valid_json "$valid_json" \
    '{
      tool: $tool,
      path: $path,
      present: $present,
      valid_json: $valid_json,
      status: $status,
      reason: $reason,
      sha256: (if $checksum == "" then null else $checksum end)
    }'
}

require_cmd jq
require_cmd git

read_report() {
  local file=$1
  local tool=$2
  local skip=${3:-false}

  if [[ "$skip" == "true" ]]; then
    log_info "Skipping ${tool} in local-fast mode." >&2
    jq -n \
      --arg tool "$tool" \
      --arg file "$file" \
      '{
        tool: $tool,
        version: "unknown",
        status: "NOT_RUN",
        stats: {
          CRITICAL: 0,
          HIGH: 0,
          MEDIUM: 0,
          LOW: 0,
          INFO: 0,
          TOTAL: 0,
          EXEMPTED: 0,
          FAILED: 0,
          PASSED: 0,
          error: false
        },
        findings: [],
        errors: ["skipped_local_fast: " + $file]
      }'
    return
  fi

  if [[ -f "$file" ]] && jq -e '.' "$file" >/dev/null 2>&1; then
    cat "$file"
    return
  fi

  log_warn "Report for ${tool} is missing or invalid at ${file}. Injecting NOT_RUN status."
  jq -n \
    --arg tool "$tool" \
    --arg file "$file" \
    '{
      tool: $tool,
      version: "unknown",
      status: "NOT_RUN",
      stats: {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0,
        INFO: 0,
        TOTAL: 0,
        EXEMPTED: 0,
        FAILED: 0,
        PASSED: 0,
        error: true
      },
      findings: [],
      errors: ["missing_or_invalid_report: " + $file]
    }'
}

log_info "Starting CloudSentinel normalization process..."
START_TIME=$(now_ms)

TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
GIT_BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")"
GIT_COMMIT="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
GIT_COMMIT_DATE="$(git log -1 --format=%cI 2>/dev/null || echo "$TIMESTAMP")"
GIT_AUTHOR_EMAIL="$(git log -1 --format=%ae 2>/dev/null || echo "unknown@example.invalid")"
PIPELINE_ID="${CI_PIPELINE_ID:-local}"

GITLEAKS_JSON=$(read_report "$GITLEAKS_REPORT" "gitleaks")
CHECKOV_JSON=$(read_report "$CHECKOV_REPORT" "checkov" "$LOCAL_FAST")
TRIVY_JSON=$(read_report "$TRIVY_REPORT" "trivy" "$LOCAL_FAST")
TRACE_GITLEAKS_JSON=$(report_trace "$GITLEAKS_REPORT" "gitleaks")
TRACE_CHECKOV_JSON=$(report_trace "$CHECKOV_REPORT" "checkov" "$LOCAL_FAST")
TRACE_TRIVY_JSON=$(report_trace "$TRIVY_REPORT" "trivy" "$LOCAL_FAST")

mkdir -p "$OUTPUT_DIR"
TMP_REPORT="$(mktemp -t cloudsentinel-golden.XXXXXX.json)"
trap 'rm -f "$TMP_REPORT"' EXIT

jq -n \
  --arg schema_version "$SCHEMA_VERSION" \
  --arg timestamp "$TIMESTAMP" \
  --arg branch "$GIT_BRANCH" \
  --arg commit "$GIT_COMMIT" \
  --arg commit_date "$GIT_COMMIT_DATE" \
  --arg author_email "$GIT_AUTHOR_EMAIL" \
  --arg pipeline_id "$PIPELINE_ID" \
  --arg environment "$ENVIRONMENT" \
  --arg execution_mode "$EXECUTION_MODE" \
  --argjson critical_max "$CRITICAL_MAX_INT" \
  --argjson high_max "$HIGH_MAX_INT" \
  --argjson trace_gitleaks "$TRACE_GITLEAKS_JSON" \
  --argjson trace_checkov "$TRACE_CHECKOV_JSON" \
  --argjson trace_trivy "$TRACE_TRIVY_JSON" \
  --argjson gitleaks "$GITLEAKS_JSON" \
  --argjson checkov "$CHECKOV_JSON" \
  --argjson trivy "$TRIVY_JSON" \
  '
  def severity_lut: {
    "CRITICAL": "CRITICAL",
    "CRIT": "CRITICAL",
    "SEV5": "CRITICAL",
    "SEVERITY5": "CRITICAL",
    "VERY_HIGH": "CRITICAL",
    "HIGH": "HIGH",
    "SEV4": "HIGH",
    "SEVERITY4": "HIGH",
    "MEDIUM": "MEDIUM",
    "MODERATE": "MEDIUM",
    "SEV3": "MEDIUM",
    "SEVERITY3": "MEDIUM",
    "LOW": "LOW",
    "MINOR": "LOW",
    "SEV2": "LOW",
    "SEVERITY2": "LOW",
    "INFO": "INFO",
    "INFORMATIONAL": "INFO",
    "SEV1": "INFO",
    "SEVERITY1": "INFO",
    "UNKNOWN": "INFO"
  };

  def sla_map: {
    "CRITICAL": 24,
    "HIGH": 168,
    "MEDIUM": 720,
    "LOW": 2160,
    "INFO": 8760
  };

  def first_non_empty($arr):
    ($arr | map(select(. != null and . != ""))) as $clean
    | if ($clean | length) > 0 then $clean[0] else null end;

  def obj_field($obj; $key):
    if ($obj | type) == "object" then $obj[$key] else null end;

  def norm_severity($value):
    (($value // "MEDIUM") | tostring | ascii_upcase) as $s
    | (severity_lut[$s] // "MEDIUM");

  def norm_path($value):
    (($value // "unknown") | tostring) as $raw
    | ($raw | gsub("\\\\"; "/") | gsub("/\\./"; "/") | gsub("/+"; "/")) as $p1
    | (if ($p1 | startswith("./")) then $p1[2:] else $p1 end) as $p2
    | (if $p2 == "" then "unknown" else $p2 end);

  def norm_status($value):
    (($value // "FAILED") | tostring | ascii_upcase) as $s
    | if $s == "EXEMPTED" then "EXEMPTED"
      elif $s == "PASSED" then "PASSED"
      else "FAILED"
      end;

  def default_category($tool):
    if $tool == "gitleaks" then "SECRETS"
    elif $tool == "checkov" then "INFRASTRUCTURE_AS_CODE"
    elif $tool == "trivy" then "VULNERABILITIES"
    else "UNKNOWN"
    end;

  def canonical_category($f; $tool):
    (first_non_empty([$f.category, $f.Category, ""]) | tostring | ascii_upcase) as $raw_cat
    | (first_non_empty([$f.finding_type, obj_field($f.source; "scanner_type"), ""]) | tostring | ascii_downcase) as $stype
    | if $tool == "gitleaks" then "SECRETS"
      elif $tool == "checkov" then "INFRASTRUCTURE_AS_CODE"
      elif ($raw_cat == "SECRET" or $raw_cat == "SECRETS" or $stype == "secret") then "SECRETS"
      else "VULNERABILITIES"
      end;

  def source_report_name($tool):
    if $tool == "gitleaks" then "gitleaks_opa.json"
    elif $tool == "checkov" then "checkov_opa.json"
    elif $tool == "trivy" then "trivy_opa.json"
    else "unknown_report"
    end;

  def scanner_status($raw; $failed):
    (($raw // "") | tostring | ascii_upcase) as $status
    | if $status == "NOT_RUN" then "NOT_RUN"
      elif $status == "PASSED" then "PASSED"
      elif $status == "FAILED" then "FAILED"
      elif $failed > 0 then "FAILED"
      else "PASSED"
      end;

  def normalize_finding($f; $tool; $version; $idx):
    (first_non_empty([$f.id, $f.rule_id, $f.RuleID, $f.VulnerabilityID, "UNKNOWN"]) | tostring) as $raw_id
    | (first_non_empty([$f.description, $f.message, $f.title, $f.check_name, "No description"]) | tostring) as $desc
    | (canonical_category($f; $tool)) as $category
    | (first_non_empty([obj_field($f.resource; "name"), $f.resource, $f.file, $f.target, "unknown"]) | tostring) as $resource_name
    | (norm_path(first_non_empty([obj_field($f.resource; "path"), $f.file, $f.target, "unknown"]))) as $resource_path
    | ((obj_field(obj_field($f.resource; "location"); "start_line") // $f.start_line // $f.line // obj_field($f.metadata; "line") // 0) | tonumber? // 0) as $start_line
    | ((obj_field(obj_field($f.resource; "location"); "end_line") // $f.end_line // obj_field($f.metadata; "end_line") // $start_line) | tonumber? // $start_line) as $end_line
    | (norm_severity(obj_field($f.severity; "level") // $f.severity // $f.original_severity // "MEDIUM")) as $severity_level
    | (norm_status($f.status // "FAILED")) as $status
    | (first_non_empty([obj_field(obj_field($f.context; "deduplication"); "fingerprint"), $f.fingerprint, ("fp:" + ([$tool, $raw_id, $resource_path, ($start_line | tostring)] | join("|")))]) | tostring) as $fingerprint
    | ((obj_field($f.severity; "cvss_score") // $f.cvss_score // obj_field($f.metadata; "cvss") // null) | tonumber? // null) as $cvss_score
    | {
        id: ("CS-" + $tool + "-" + $raw_id),
        source: {
          tool: $tool,
          version: ($version // "unknown"),
          id: $raw_id,
          scanner_type: (first_non_empty([$f.finding_type, obj_field($f.source; "scanner_type"), ($category | ascii_downcase), "security"]) | tostring)
        },
        resource: {
          name: $resource_name,
          version: (first_non_empty([obj_field($f.resource; "version"), obj_field($f.metadata; "installed_version"), "N/A"]) | tostring),
          type: (first_non_empty([obj_field($f.resource; "type"), $f.finding_type, "asset"]) | tostring),
          path: $resource_path,
          location: {
            file: $resource_path,
            start_line: $start_line,
            end_line: $end_line
          }
        },
        description: $desc,
        severity: {
          level: $severity_level,
          original_severity: (first_non_empty([obj_field($f.severity; "level"), $f.severity, "UNKNOWN"]) | tostring),
          cvss_score: $cvss_score
        },
        category: $category,
        status: $status,
        remediation: {
          sla_hours: (sla_map[$severity_level] // 720),
          fix_version: (first_non_empty([$f.fix_version, obj_field($f.metadata; "fixed_version"), "N/A"]) | tostring),
          references: (($f.references // obj_field($f.metadata; "references") // []) | if type == "array" then map(tostring) else [] end)
        },
        context: {
          git: {
            author_email: $author_email,
            commit_date: $commit_date
          },
          deduplication: {
            fingerprint: $fingerprint,
            is_duplicate: false,
            duplicate_of: null
          },
          traceability: {
            source_report: source_report_name($tool),
            source_index: $idx,
            normalized_at: $timestamp
          }
        }
      };

  def process_scanner($data; $name):
    (($data.findings // []) | if type == "array" then . else [] end | to_entries | map(normalize_finding(.value; $name; ($data.version // "unknown"); .key))) as $norm
    | ($norm | map(select(.status == "FAILED")) | length) as $failed
    | ($norm | map(select(.status == "EXEMPTED")) | length) as $exempted
    | ($norm | map(select(.status == "PASSED")) | length) as $passed
    | {
        tool: $name,
        version: ($data.version // "unknown"),
        status: scanner_status($data.status; $failed),
        errors: (($data.errors // []) | if type == "array" then map(tostring) else [] end),
        stats: {
          CRITICAL: ($norm | map(select(.status == "FAILED" and .severity.level == "CRITICAL")) | length),
          HIGH: ($norm | map(select(.status == "FAILED" and .severity.level == "HIGH")) | length),
          MEDIUM: ($norm | map(select(.status == "FAILED" and .severity.level == "MEDIUM")) | length),
          LOW: ($norm | map(select(.status == "FAILED" and .severity.level == "LOW")) | length),
          INFO: ($norm | map(select(.status == "FAILED" and .severity.level == "INFO")) | length),
          TOTAL: $failed,
          EXEMPTED: $exempted,
          FAILED: $failed,
          PASSED: $passed
        },
        findings: $norm
      };

  {
    schema_version: $schema_version,
    metadata: {
      tool: "cloudsentinel",
      timestamp: $timestamp,
      generation_duration_ms: 0,
      environment: ($environment | ascii_downcase),
      execution: {
        mode: $execution_mode
      },
      git: {
        branch: $branch,
        commit: $commit,
        commit_date: $commit_date,
        author_email: $author_email,
        pipeline_id: $pipeline_id
      },
      normalizer: {
        version: $schema_version,
        source_reports: {
          gitleaks: $trace_gitleaks,
          checkov: $trace_checkov,
          trivy: $trace_trivy
        }
      }
    },
    scanners: {
      gitleaks: process_scanner($gitleaks; "gitleaks"),
      checkov: process_scanner($checkov; "checkov"),
      trivy: process_scanner($trivy; "trivy")
    }
  }
  | .findings = ([.scanners.gitleaks.findings, .scanners.checkov.findings, .scanners.trivy.findings] | flatten)
  | (.findings | map(select(.status == "FAILED"))) as $failed_findings
  | (.findings | map(select(.status == "EXEMPTED")) | length) as $exempted_count
  | (.findings | map(select(.status == "PASSED")) | length) as $passed_count
  | .summary = {
      global: {
        CRITICAL: ($failed_findings | map(select(.severity.level == "CRITICAL")) | length),
        HIGH: ($failed_findings | map(select(.severity.level == "HIGH")) | length),
        MEDIUM: ($failed_findings | map(select(.severity.level == "MEDIUM")) | length),
        LOW: ($failed_findings | map(select(.severity.level == "LOW")) | length),
        INFO: ($failed_findings | map(select(.severity.level == "INFO")) | length),
        TOTAL: ($failed_findings | length),
        EXEMPTED: $exempted_count,
        FAILED: ($failed_findings | length),
        PASSED: $passed_count
      },
      by_tool: {
        gitleaks: {
          CRITICAL: .scanners.gitleaks.stats.CRITICAL,
          HIGH: .scanners.gitleaks.stats.HIGH,
          MEDIUM: .scanners.gitleaks.stats.MEDIUM,
          LOW: .scanners.gitleaks.stats.LOW,
          INFO: .scanners.gitleaks.stats.INFO,
          TOTAL: .scanners.gitleaks.stats.TOTAL,
          EXEMPTED: .scanners.gitleaks.stats.EXEMPTED,
          FAILED: .scanners.gitleaks.stats.FAILED,
          PASSED: .scanners.gitleaks.stats.PASSED,
          status: .scanners.gitleaks.status
        },
        checkov: {
          CRITICAL: .scanners.checkov.stats.CRITICAL,
          HIGH: .scanners.checkov.stats.HIGH,
          MEDIUM: .scanners.checkov.stats.MEDIUM,
          LOW: .scanners.checkov.stats.LOW,
          INFO: .scanners.checkov.stats.INFO,
          TOTAL: .scanners.checkov.stats.TOTAL,
          EXEMPTED: .scanners.checkov.stats.EXEMPTED,
          FAILED: .scanners.checkov.stats.FAILED,
          PASSED: .scanners.checkov.stats.PASSED,
          status: .scanners.checkov.status
        },
        trivy: {
          CRITICAL: .scanners.trivy.stats.CRITICAL,
          HIGH: .scanners.trivy.stats.HIGH,
          MEDIUM: .scanners.trivy.stats.MEDIUM,
          LOW: .scanners.trivy.stats.LOW,
          INFO: .scanners.trivy.stats.INFO,
          TOTAL: .scanners.trivy.stats.TOTAL,
          EXEMPTED: .scanners.trivy.stats.EXEMPTED,
          FAILED: .scanners.trivy.stats.FAILED,
          PASSED: .scanners.trivy.stats.PASSED,
          status: .scanners.trivy.status
        }
      },
      by_category: {
        SECRETS: ($failed_findings | map(select(.category == "SECRETS")) | length),
        INFRASTRUCTURE_AS_CODE: ($failed_findings | map(select(.category == "INFRASTRUCTURE_AS_CODE")) | length),
        VULNERABILITIES: ($failed_findings | map(select(.category == "VULNERABILITIES")) | length)
      }
    }
  | .quality_gate = {
      decision: "NOT_EVALUATED",
      reason: "evaluation-performed-by-opa-only",
      thresholds: {
        critical_max: $critical_max,
        high_max: $high_max
      },
      details: {
        reasons: ["opa_is_single_enforcement_point"],
        not_run_scanners: (
          [
            (if .scanners.gitleaks.status == "NOT_RUN" then "gitleaks" else empty end),
            (if .scanners.checkov.status == "NOT_RUN" then "checkov" else empty end),
            (if .scanners.trivy.status == "NOT_RUN" then "trivy" else empty end)
          ]
        )
      }
    }
  ' > "$TMP_REPORT"

END_TIME=$(now_ms)
DURATION=$((END_TIME - START_TIME))

jq --argjson duration "$DURATION" '.metadata.generation_duration_ms = $duration' "$TMP_REPORT" > "$OUTPUT_FILE"

# Optional JSON schema validation if jsonschema (python) is available
SCHEMA_FILE="${ROOT_DIR}/shift-left/normalizer/schema/cloudsentinel_report.schema.json"
if command -v python >/dev/null 2>&1 && [[ -f "$SCHEMA_FILE" ]]; then
  # [F4 FIX] Capture RC explicitly — `$?` after `if !` always equals 1 (negation result),
  # losing the original Python exit code (42 = jsonschema missing, 1 = validation failed).
  PYTHON_SCHEMA_RC=0
  set +e
  python - "$OUTPUT_FILE" "$SCHEMA_FILE" <<'PYCODE'
import json, sys
try:
    from jsonschema import validate, Draft7Validator
except ImportError:
    sys.exit(42)

doc_path, schema_path = sys.argv[1], sys.argv[2]
with open(doc_path) as f:
    doc = json.load(f)
with open(schema_path) as f:
    schema = json.load(f)
Draft7Validator.check_schema(schema)
validate(doc, schema)
PYCODE
  PYTHON_SCHEMA_RC=$?
  set -e

  if [[ "$PYTHON_SCHEMA_RC" -eq 42 ]]; then
    if [[ "$SCHEMA_STRICT" == "true" ]]; then
      log_error "jsonschema python module required but not installed (pip install jsonschema)."
    else
      log_warn "jsonschema python module not installed; schema validation skipped."
    fi
  elif [[ "$PYTHON_SCHEMA_RC" -ne 0 ]]; then
    log_error "Golden report failed schema validation. See ${SCHEMA_FILE}"
  fi
else
  if [[ "$SCHEMA_STRICT" == "true" ]]; then
    log_error "jsonschema validation required but python or schema is missing."
  else
    log_warn "jsonschema validation skipped (python or schema missing)."
  fi
fi

log_info "Golden Report generated successfully: $OUTPUT_FILE"
log_info "OPA input ready → run 'bash shift-left/opa/run-opa.sh --enforce' for the gate decision."
