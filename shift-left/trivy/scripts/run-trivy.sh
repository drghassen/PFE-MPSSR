#!/usr/bin/env bash
set -euo pipefail

################################################################################
# CloudSentinel — Trivy Orchestrator v7.0 (Enterprise)
#
# Scan types:
#   image  → trivy image  (OS+lib vuln + embedded secrets)
#   fs     → trivy fs     (SCA language pkgs + secrets in source)
#   config → trivy config (Dockerfile misconfigurations — CIS Docker Benchmark)
#
# Responsibility matrix:
#   IaC (Terraform)         → Checkov       (out of scope here)
#   Secrets (source/git)    → Gitleaks      (pre-commit + CI)
#   Enforcement (ALLOW/DENY) → OPA          (Quality Gate downstream)
#
# Trivy exits 0 always — findings are normalised to JSON and fed to OPA.
################################################################################

# ── Path Resolution ───────────────────────────────────────────────────────────
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Configs
CONFIG_DEFAULT="$BASE_DIR/configs/trivy.yaml"
CONFIG_CI="$BASE_DIR/configs/trivy-ci.yaml"
MAPPING_FILE="$BASE_DIR/configs/severity-mapping.json"
IGNORE_FILE="$BASE_DIR/.trivyignore"

# Sub-scanners
SCAN_IMAGE="$SCRIPT_DIR/scan-image.sh"
SCAN_FS="$SCRIPT_DIR/scan-fs.sh"
SCAN_CONFIG="$SCRIPT_DIR/scan-config.sh"

# Report directories
REPORTS_RAW_DIR="$BASE_DIR/reports/raw"
REPORTS_OPA_DIR="$BASE_DIR/reports/opa"
mkdir -p "$REPORTS_RAW_DIR" "$REPORTS_OPA_DIR"

OPA_FINAL_REPORT="$REPORTS_OPA_DIR/trivy_opa.json"

# ── Logging ───────────────────────────────────────────────────────────────────
log()  { echo -e "\033[1;34m[CloudSentinel][Trivy]\033[0m $*"; }
warn() { echo -e "\033[1;33m[CloudSentinel][Trivy][WARN]\033[0m $*" >&2; }
err()  { echo -e "\033[1;31m[CloudSentinel][Trivy][ERROR]\033[0m $*" >&2; }

# ── Mode Detection ────────────────────────────────────────────────────────────
SCAN_MODE="${SCAN_MODE:-local}"
[[ -n "${CI:-}" ]] && SCAN_MODE="ci"
export SCAN_MODE

CONFIG_FILE="$CONFIG_DEFAULT"
[[ "$SCAN_MODE" == "ci" ]] && CONFIG_FILE="$CONFIG_CI"

# ── Arguments ─────────────────────────────────────────────────────────────────
TARGET="${1:-}"
SCAN_TYPE="${2:-}"   # image | fs | config (explicit required — no fragile heuristics)

if [[ -z "$TARGET" || -z "$SCAN_TYPE" ]]; then
  err "Usage: $0 <target> <scan_type>"
  err "  scan_type: image | fs | config"
  err ""
  err "Examples:"
  err "  $0 alpine:3.18 image        # Container image vulnerability + secret scan"
  err "  $0 ./src fs                 # SCA + secret scan on source directory"
  err "  $0 ./Dockerfile config      # Dockerfile misconfig scan (CIS Docker Benchmark)"
  exit 1
fi

# ── Cache Configuration ───────────────────────────────────────────────────────
export TRIVY_CACHE_DIR="$REPO_ROOT/.trivy-cache"

log "Scan type : $SCAN_TYPE"
log "Target    : $TARGET"
log "Mode      : $SCAN_MODE"
log "Config    : $CONFIG_FILE"
log "Cache     : $TRIVY_CACHE_DIR"

# ── Dispatch to appropriate scanner ──────────────────────────────────────────
case "$SCAN_TYPE" in
  image)
    bash "$SCAN_IMAGE" "$TARGET"
    RAW_RESULTS="$REPORTS_RAW_DIR/trivy-image-raw.json"
    ;;
  fs)
    bash "$SCAN_FS" "$TARGET"
    RAW_RESULTS="$REPORTS_RAW_DIR/trivy-fs-raw.json"
    ;;
  config)
    bash "$SCAN_CONFIG" "$TARGET"
    RAW_RESULTS="$REPORTS_RAW_DIR/trivy-config-raw.json"
    ;;
  *)
    err "Unknown scan type: '$SCAN_TYPE'. Valid types: image | fs | config"
    exit 1
    ;;
esac

# ── Validate raw output ───────────────────────────────────────────────────────
[[ ! -f "$RAW_RESULTS" ]] && { err "Raw scan output not found: $RAW_RESULTS"; exit 1; }
jq empty "$RAW_RESULTS" 2>/dev/null || { err "Invalid JSON in raw output: $RAW_RESULTS"; exit 1; }

log "Normalising findings for OPA..."

# ── Git metadata ──────────────────────────────────────────────────────────────
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")"
COMMIT="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"

# ── OPA Normalisation ─────────────────────────────────────────────────────────
# Trivy JSON structure:
#   .Results[] → { Type, Class, Target, Vulnerabilities[], Secrets[], Misconfigurations[] }
#
# Class values:
#   "os-pkgs"   → OS package vulnerabilities   → category: INFRASTRUCTURE
#   "lang-pkgs" → Language/library SCA         → category: APPLICATION
#   "secret"    → Secrets found                → category: SECRET
#   "config"    → Dockerfile misconfiguration  → category: CONFIGURATION
#
# All findings unified into a single normalised array for OPA evaluation.
jq -n \
  --arg timestamp "$TIMESTAMP" \
  --arg branch    "$BRANCH"    \
  --arg commit    "$COMMIT"    \
  --arg scan_type "$SCAN_TYPE" \
  --arg target    "$TARGET"    \
  --slurpfile raw     "$RAW_RESULTS"  \
  --slurpfile mapping "$MAPPING_FILE" \
'
  ($raw[0].Results // []) as $results
  | ($mapping[0].severity_mapping) as $sev_map
  | ($mapping[0].categories)       as $cat_map
  | ($mapping[0].remediation_sla)  as $sla_map

  | ($results | map(
      . as $result
      | (
          # ── Vulnerabilities (OS + SCA) ──────────────────────────────────
          (.Vulnerabilities // [] | map({
            id:          (.VulnerabilityID // "UNKNOWN"),
            resource:    (.PkgName         // "unknown"),
            file:        ($result.Target   // "unknown"),
            description: (.Title           // .Description // "N/A"),
            severity:    ($sev_map[.Severity | ascii_upcase] // "LOW"),
            category:    ($cat_map[$result.Class // ""] // "UNKNOWN"),
            status:      "FAILED",
            finding_type: "vulnerability",
            metadata: {
              installed_version: (.InstalledVersion // "N/A"),
              fixed_version:     (.FixedVersion     // "N/A"),
              references:        (.References       // [])
            }
          }))

          +

          # ── Secrets ──────────────────────────────────────────────────────
          (.Secrets // [] | map({
            id:          (.RuleID      // "SECRET-UNKNOWN"),
            resource:    (.Category    // "unknown"),
            file:        ($result.Target // "unknown"),
            description: (.Title      // "Secret detected"),
            severity:    ($sev_map[.Severity | ascii_upcase] // "HIGH"),
            category:    "SECRET",
            status:      "FAILED",
            finding_type: "secret",
            metadata: {
              match:   (.Match // ""),
              line:    (.StartLine // 0),
              end_line: (.EndLine // 0)
            }
          }))

          +

          # ── Misconfigurations (Dockerfile CIS) ───────────────────────────
          (.Misconfigurations // [] | map({
            id:          (.ID          // "MISCONFIG-UNKNOWN"),
            resource:    (.Type        // "unknown"),
            file:        ($result.Target // "unknown"),
            description: (.Title       // .Description // "N/A"),
            severity:    ($sev_map[.Severity | ascii_upcase] // "MEDIUM"),
            category:    "CONFIGURATION",
            status:      "FAILED",
            finding_type: "misconfig",
            metadata: {
              resolution: (.Resolution // "N/A"),
              references: (.References // [])
            }
          }))
        )
    ) | flatten) as $findings

  | {
      tool:      "trivy",
      version:   "7.0",
      timestamp: $timestamp,
      branch:    $branch,
      commit:    $commit,
      scan_type: $scan_type,
      target:    $target,
      stats: {
        CRITICAL: ($findings | map(select(.severity == "CRITICAL")) | length),
        HIGH:     ($findings | map(select(.severity == "HIGH"))     | length),
        MEDIUM:   ($findings | map(select(.severity == "MEDIUM"))   | length),
        LOW:      ($findings | map(select(.severity == "LOW"))      | length),
        TOTAL:    ($findings | length),
        by_type: {
          vulnerability: ($findings | map(select(.finding_type == "vulnerability")) | length),
          secret:        ($findings | map(select(.finding_type == "secret"))        | length),
          misconfig:     ($findings | map(select(.finding_type == "misconfig"))     | length)
        },
        by_category: {
          INFRASTRUCTURE: ($findings | map(select(.category == "INFRASTRUCTURE")) | length),
          APPLICATION:    ($findings | map(select(.category == "APPLICATION"))    | length),
          CONFIGURATION:  ($findings | map(select(.category == "CONFIGURATION"))  | length),
          SECRET:         ($findings | map(select(.category == "SECRET"))         | length)
        }
      },
      remediation_sla: $sla_map,
      findings: $findings
    }
' > "$OPA_FINAL_REPORT"

# ── Summary ───────────────────────────────────────────────────────────────────
TOTAL=$(jq '.stats.TOTAL' "$OPA_FINAL_REPORT")
CRITICAL=$(jq '.stats.CRITICAL' "$OPA_FINAL_REPORT")
HIGH=$(jq '.stats.HIGH' "$OPA_FINAL_REPORT")

log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "OPA Report : $OPA_FINAL_REPORT"
log "Total      : $TOTAL findings"
log "Critical   : $CRITICAL | High: $HIGH"
log "Enforcement: Delegated to OPA Quality Gate"
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

exit 0
