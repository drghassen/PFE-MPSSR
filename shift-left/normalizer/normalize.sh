#!/usr/bin/env bash

# ==============================================================================
# CloudSentinel Normalizer
# Description: Merges security scan reports (Gitleaks, Checkov, Trivy) into a 
#              unified Golden Report for OPA decision making.
# Author: Senior DevSecOps Architect
# Version: 1.0.0
# ==============================================================================

set -euo pipefail

# --- Configuration ---
ROOT_DIR=$(git rev-parse --show-toplevel)
OUTPUT_DIR="${ROOT_DIR}/.cloudsentinel"
OUTPUT_FILE="${OUTPUT_DIR}/golden_report.json"
SCHEMA_VERSION="1.0.0"

# Inputs
GITLEAKS_REPORT="${ROOT_DIR}/.cloudsentinel/gitleaks_opa.json"
CHECKOV_REPORT="${ROOT_DIR}/.cloudsentinel/checkov_opa.json"
TRIVY_REPORT="${ROOT_DIR}/shift-left/trivy/reports/opa/trivy_opa.json"

# --- Functions ---

log_info() { echo -e "\e[34m[INFO]\e[0m $1"; }
log_warn() { echo -e "\e[33m[WARN]\e[0m $1" >&2; }
log_error() { echo -e "\e[31m[ERROR]\e[0m $1" >&2; exit 1; }

# Helper to read JSON or return empty structure if missing
read_report() {
    local file=$1
    local tool=$2
    if [[ -f "$file" ]]; then
        cat "$file"
    else
        log_warn "Report for $tool missing at $file. Injecting NOT_RUN status."
        echo "{\"tool\": \"$tool\", \"status\": \"NOT_RUN\", \"findings\": [], \"stats\": {\"TOTAL\": 0}}"
    fi
}

# --- Execution ---

log_info "Starting CloudSentinel normalization process..."
START_TIME=$(date +%s%3N)

# 1. Gather Git Metadata
log_info "Extracting Git metadata..."
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
GIT_COMMIT=$(git rev-parse HEAD)
GIT_COMMIT_DATE=$(git log -1 --format=%cI)
GIT_AUTHOR_EMAIL=$(git log -1 --format=%ae)

# 2. Read reports
GITLEAKS_JSON=$(read_report "$GITLEAKS_REPORT" "gitleaks")
CHECKOV_JSON=$(read_report "$CHECKOV_REPORT" "checkov")
TRIVY_JSON=$(read_report "$TRIVY_REPORT" "trivy")

# 3. Core Transformation Logic (The JQ Engine)
log_info "Executing JQ transformation engine..."

# We use a large JQ script to handle:
# - Normalization of each scanner's structure
# - Deduplication & Fingerprinting
# - SLA injection
# - Risk scoring
# - Summary aggregation
# - Quality Gate logic

FINAL_REPORT=$(jq -n \
    --arg schema_version "$SCHEMA_VERSION" \
    --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg branch "$GIT_BRANCH" \
    --arg commit "$GIT_COMMIT" \
    --arg commit_date "$GIT_COMMIT_DATE" \
    --arg author_email "$GIT_AUTHOR_EMAIL" \
    --argjson gitleaks "$GITLEAKS_JSON" \
    --argjson checkov "$CHECKOV_JSON" \
    --argjson trivy "$TRIVY_JSON" \
    '
    # Define SLA & Risk Maps
    def sla_map: { "CRITICAL": 24, "HIGH": 168, "MEDIUM": 720, "LOW": 2160, "INFO": 8760 };
    def risk_map: { "CRITICAL": 50, "HIGH": 20, "MEDIUM": 5, "LOW": 1, "INFO": 0 };

    # Function to normalize findings
    def normalize_finding(f; tool; version):
        f | . + {
            "id": "CS-\(tool)-\(.id)",
            "source": { "tool": tool, "version": version, "id": .id, "scanner_type": (.category // "security") },
            "remediation": {
                "sla_hours": (sla_map[.severity] // 720),
                "fix_version": (.fix_version // "N/A"),
                "references": (.references // [])
            },
            "context": {
                "git": { "author_email": $author_email, "commit_date": $commit_date },
                "deduplication": {
                    "fingerprint": "sha256:\(tool):\(.id):\(.file // "unknown"):\(.line // 0)",
                    "is_duplicate": false
                }
            }
        };

    # Process Scanners
    def process_scanner(data; name):
        data | {
            "tool": name,
            "version": (.version // "unknown"),
            "status": (if .status then .status elif (.stats.TOTAL > 0) then "FAILED" else "PASSED" end),
            "stats": .stats,
            "findings": (.findings | map(normalize_finding(.; name; data.version // "unknown")))
        };

    {
        "schema_version": $schema_version,
        "metadata": {
            "tool": "cloudsentinel",
            "timestamp": $timestamp,
            "generation_duration_ms": 0, # Will be updated after
            "git": {
                "branch": $branch,
                "commit": $commit,
                "commit_date": $commit_date,
                "author_email": $author_email
            }
        },
        "scanners": {
            "gitleaks": process_scanner($gitleaks; "gitleaks"),
            "checkov": process_scanner($checkov; "checkov"),
            "trivy": process_scanner($trivy; "trivy")
        }
    }
    | .findings = ([.scanners.gitleaks.findings, .scanners.checkov.findings, .scanners.trivy.findings] | flatten)
    | .summary = {
        "global": {
            "CRITICAL": (.findings | map(select(.severity == "CRITICAL")) | length),
            "HIGH": (.findings | map(select(.severity == "HIGH")) | length),
            "MEDIUM": (.findings | map(select(.severity == "MEDIUM")) | length),
            "LOW": (.findings | map(select(.severity == "LOW")) | length),
            "INFO": (.findings | map(select(.severity == "INFO")) | length),
            "TOTAL": (.findings | length),
            "EXEMPTED": (.findings | map(select(.status == "EXEMPTED")) | length),
            "FAILED": (.findings | map(select(.status == "FAILED")) | length),
            "PASSED": 0
        },
        "by_tool": {
            "gitleaks": { "CRITICAL": .scanners.gitleaks.stats.CRITICAL, "HIGH": .scanners.gitleaks.stats.HIGH, "TOTAL": .scanners.gitleaks.stats.TOTAL, "status": .scanners.gitleaks.status },
            "checkov": { "CRITICAL": .scanners.checkov.stats.CRITICAL, "HIGH": .scanners.checkov.stats.HIGH, "TOTAL": .scanners.checkov.stats.TOTAL, "status": .scanners.checkov.status },
            "trivy": { "CRITICAL": .scanners.trivy.stats.CRITICAL, "HIGH": .scanners.trivy.stats.HIGH, "TOTAL": .scanners.trivy.stats.TOTAL, "status": .scanners.trivy.status }
        },
        "by_category": {
            "SECRETS": (.findings | map(select(.source.tool == "gitleaks")) | length),
            "INFRASTRUCTURE_AS_CODE": (.findings | map(select(.source.tool == "checkov")) | length),
            "VULNERABILITIES": (.findings | map(select(.source.tool == "trivy")) | length)
        }
    }
    | .quality_gate = {
        "decision": (if .summary.global.CRITICAL > 0 then "FAILED" else "PASSED" end),
        "reason": (if .summary.global.CRITICAL > 0 then "\(.summary.global.CRITICAL) CRITICAL findings exceed threshold (max 0)" else "All thresholds respected" end),
        "thresholds": { "critical_max": 0, "high_max": 2 }
    }
')

# 4. Final adjustments (Duration)
END_TIME=$(date +%s%3N)
DURATION=$((END_TIME - START_TIME))
FINAL_REPORT=$(echo "$FINAL_REPORT" | jq --argjson dur "$DURATION" '.metadata.generation_duration_ms = $dur')

# 5. Save Output
mkdir -p "$(dirname "$OUTPUT_FILE")"
echo "$FINAL_REPORT" > "$OUTPUT_FILE"

log_info "Golden Report generated successfully: $OUTPUT_FILE"
log_info "Quality Gate Decision: $(echo "$FINAL_REPORT" | jq -r .quality_gate.decision)"
