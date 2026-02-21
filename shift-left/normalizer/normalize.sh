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
SCHEMA_VERSION="1.0.0"
ENVIRONMENT="${ENVIRONMENT:-${CI_ENVIRONMENT_NAME:-dev}}"

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

CRITICAL_MAX="${CRITICAL_MAX:-0}"
HIGH_MAX="${HIGH_MAX:-2}"

GITLEAKS_REPORT="${ROOT_DIR}/.cloudsentinel/gitleaks_opa.json"
CHECKOV_REPORT="${ROOT_DIR}/.cloudsentinel/checkov_opa.json"
TRIVY_REPORT="${ROOT_DIR}/shift-left/trivy/reports/opa/trivy_opa.json"

[[ "$CRITICAL_MAX" =~ ^[0-9]+$ ]] || log_error "CRITICAL_MAX must be an integer"
[[ "$HIGH_MAX" =~ ^[0-9]+$ ]] || log_error "HIGH_MAX must be an integer"

require_cmd jq
require_cmd git

read_report() {
  local file=$1
  local tool=$2

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
CHECKOV_JSON=$(read_report "$CHECKOV_REPORT" "checkov")
TRIVY_JSON=$(read_report "$TRIVY_REPORT" "trivy")

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
  --argjson critical_max "$CRITICAL_MAX" \
  --argjson high_max "$HIGH_MAX" \
  --argjson gitleaks "$GITLEAKS_JSON" \
  --argjson checkov "$CHECKOV_JSON" \
  --argjson trivy "$TRIVY_JSON" \
  '
  def severity_lut: {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
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

  def norm_status($value):
    (($value // "FAILED") | tostring | ascii_upcase) as $s
    | if $s == "EXEMPTED" then "EXEMPTED"
      elif $s == "PASSED" then "PASSED"
      else "FAILED"
      end;

  def default_category($tool):
    if $tool == "gitleaks" then "SECRETS"
    elif $tool == "checkov" then "INFRASTRUCTURE_AS_CODE"
    else "VULNERABILITIES"
    end;

  def scanner_status($raw; $failed):
    (($raw // "") | tostring | ascii_upcase) as $status
    | if $status == "NOT_RUN" then "NOT_RUN"
      elif $status == "PASSED" then "PASSED"
      elif $status == "FAILED" then "FAILED"
      elif $failed > 0 then "FAILED"
      else "PASSED"
      end;

  def normalize_finding($f; $tool; $version):
    (first_non_empty([$f.id, $f.rule_id, $f.RuleID, $f.VulnerabilityID, "UNKNOWN"]) | tostring) as $raw_id
    | (first_non_empty([$f.description, $f.message, $f.title, $f.check_name, "No description"]) | tostring) as $desc
    | (first_non_empty([$f.category, default_category($tool)]) | tostring) as $category
    | (first_non_empty([obj_field($f.resource; "name"), $f.resource, $f.file, $f.target, "unknown"]) | tostring) as $resource_name
    | (first_non_empty([obj_field($f.resource; "path"), $f.file, $f.target, "unknown"]) | tostring) as $resource_path
    | ((obj_field(obj_field($f.resource; "location"); "start_line") // $f.start_line // $f.line // obj_field($f.metadata; "line") // 0) | tonumber? // 0) as $start_line
    | ((obj_field(obj_field($f.resource; "location"); "end_line") // $f.end_line // obj_field($f.metadata; "end_line") // $start_line) | tonumber? // $start_line) as $end_line
    | (norm_severity(obj_field($f.severity; "level") // $f.severity // $f.original_severity // "MEDIUM")) as $severity_level
    | (norm_status($f.status // "FAILED")) as $status
    | (first_non_empty([obj_field(obj_field($f.context; "deduplication"); "fingerprint"), $f.fingerprint, ("fp:" + ([$tool, $raw_id, $resource_path, ($start_line | tostring)] | join("|")))]) | tostring) as $fingerprint
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
          original_severity: (first_non_empty([obj_field($f.severity; "level"), $f.severity, "UNKNOWN"]) | tostring)
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
          }
        }
      };

  def process_scanner($data; $name):
    (($data.findings // []) | if type == "array" then . else [] end | map(normalize_finding(.; $name; ($data.version // "unknown")))) as $norm
    | ($norm | map(select(.status == "FAILED")) | length) as $failed
    | ($norm | map(select(.status == "EXEMPTED")) | length) as $exempted
    | ($norm | map(select(.status == "PASSED")) | length) as $passed
    | {
        tool: $name,
        version: ($data.version // "unknown"),
        status: scanner_status($data.status; $failed),
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
      git: {
        branch: $branch,
        commit: $commit,
        commit_date: $commit_date,
        author_email: $author_email,
        pipeline_id: $pipeline_id
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
  | ([.scanners | to_entries[] | select(.value.status == "NOT_RUN") | .key]) as $not_run_scanners
  | ([
      (if ($not_run_scanners | length) > 0 then "Scanners not run: " + ($not_run_scanners | join(", ")) else empty end),
      (if .summary.global.CRITICAL > $critical_max then "CRITICAL findings exceed threshold (" + (.summary.global.CRITICAL | tostring) + ">" + ($critical_max | tostring) + ")" else empty end),
      (if .summary.global.HIGH > $high_max then "HIGH findings exceed threshold (" + (.summary.global.HIGH | tostring) + ">" + ($high_max | tostring) + ")" else empty end)
    ] | map(select(. != null))) as $gate_reasons
  | .quality_gate = {
      decision: (if ($gate_reasons | length) > 0 then "FAILED" else "PASSED" end),
      reason: (if ($gate_reasons | length) > 0 then ($gate_reasons | join("; ")) else "Thresholds respected and all scanners executed" end),
      thresholds: {
        critical_max: $critical_max,
        high_max: $high_max
      },
      details: {
        reasons: $gate_reasons,
        not_run_scanners: $not_run_scanners
      }
    }
  ' > "$TMP_REPORT"

END_TIME=$(now_ms)
DURATION=$((END_TIME - START_TIME))

jq --argjson duration "$DURATION" '.metadata.generation_duration_ms = $duration' "$TMP_REPORT" > "$OUTPUT_FILE"

log_info "Golden Report generated successfully: $OUTPUT_FILE"
log_info "Quality Gate Decision: $(jq -r '.quality_gate.decision' "$OUTPUT_FILE")"
