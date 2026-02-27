#!/usr/bin/env bash
set -euo pipefail

################################################################################
# CloudSentinel - Checkov Wrapper v5.0 (PFE)
# - Centralise les rapports dans .cloudsentinel/
# - Normalise les sévérités et catégories via mapping.json
# - Aucun bypass local: les exceptions sont gérées uniquement par OPA
################################################################################

# --- Couleurs & Logs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[Checkov][INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[Checkov][SUCCESS]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[Checkov][WARN]${NC} $*" >&2; }
log_err()     { echo -e "${RED}[Checkov][ERROR]${NC} $*" >&2; }

# --- Chemins & Dossiers ---
# On récupère la racine du projet Git
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Dossier de sortie centralisé pour OPA
OUT_DIR="$REPO_ROOT/.cloudsentinel"
mkdir -p "$OUT_DIR" 

# Fichiers de configuration
POLICIES_DIR="${SCRIPT_DIR}/policies"
MAPPING_FILE="${POLICIES_DIR}/mapping.json"
CONFIG_FILE="${SCRIPT_DIR}/.checkov.yml"

# Fichiers de rapports (on utilise des noms fixes pour éviter l'accumulation)
REPORT_RAW="$OUT_DIR/checkov_raw.json"
REPORT_OPA="$OUT_DIR/checkov_opa.json"
REPORT_LOG="$OUT_DIR/checkov_scan.log"

emit_not_run() {
    local reason=$1
    local branch
    local commit
    branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")"
    commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"

    log_warn "Scan marked as NOT_RUN: $reason"
    echo '{"results":{"failed_checks":[]}}' > "$REPORT_RAW"
    jq -n \
      --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
      --arg branch "$branch" \
      --arg commit "$commit" \
      --arg repo "$REPO_ROOT" \
      --arg reason "$reason" \
      '{
        tool: "checkov",
        version: "unknown",
        has_findings: false,
        status: "NOT_RUN",
        timestamp: $timestamp,
        branch: $branch,
        commit: $commit,
        repository: $repo,
        stats: {
          CRITICAL: 0,
          HIGH: 0,
          MEDIUM: 0,
          LOW: 0,
          INFO: 0,
          TOTAL: 0,
          EXEMPTED: 0,
          FAILED: 0,
          PASSED: 0
        },
        errors: [$reason],
        findings: []
      }' > "$REPORT_OPA"
}

# --- Prérequis ---
command -v checkov >/dev/null 2>&1 || { log_err "Checkov n'est pas installé."; exit 2; }
command -v jq >/dev/null 2>&1 || { log_err "jq n'est pas installé."; exit 2; }

[[ -f "$MAPPING_FILE" ]] || { log_err "Mapping introuvable: $MAPPING_FILE"; emit_not_run "mapping_file_missing"; exit 0; }
# --- Préparation du Scan ---
SCAN_TARGET="${1:-$REPO_ROOT}" # Par défaut scanne tout le repo ou le dossier passé en argument
log_info "Démarrage du scan sur : $SCAN_TARGET"

# Construction de la commande Checkov
# Si .checkov.yml existe, il est la source de vérité (frameworks + checks + policies).
checkov_cmd=(checkov --directory "$SCAN_TARGET")

if [[ ! -f "$CONFIG_FILE" ]]; then
    log_err "Config file missing: $CONFIG_FILE"
    emit_not_run "config_file_missing"
    # Do not block on scanner setup issues here: OPA remains the single gate.
    exit 0
fi

log_info "Using config: $CONFIG_FILE"
checkov_cmd+=("--config-file" "$CONFIG_FILE")

# --- Exécution ---
set +e
"${checkov_cmd[@]}" > "$REPORT_RAW" 2> "$REPORT_LOG"
EXIT_CODE=$?
set -e

# Code 2 = Erreur technique
if [ $EXIT_CODE -eq 2 ]; then
    log_err "Erreur technique Checkov. Consultez $REPORT_LOG"
    emit_not_run "checkov_execution_error"
    # Bloque le job (technique) : OPA ne doit pas décider sur un scanner en échec dur.
    exit 2
fi

# Si le fichier est vide ou invalide (aucun fichier .tf trouvé par ex)
if ! jq -e '.' "$REPORT_RAW" >/dev/null 2>&1; then
    log_warn "Aucun résultat exploitable. Génération d'un rapport vide."
    echo '{"results":{"failed_checks":[]}}' > "$REPORT_RAW"
fi

# --- Métadonnées Git ---
BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")"
COMMIT="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"

# --- Normalisation JQ (Le Cœur du Système) ---
log_info "Normalisation des résultats pour OPA..."

CHECKOV_VERSION="$(checkov --version 2>/dev/null | head -n1 | tr -d '\r' || echo unknown)"
[[ -z "$CHECKOV_VERSION" ]] && CHECKOV_VERSION="unknown"

jq -n \
  --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
  --arg branch "$BRANCH" \
  --arg commit "$COMMIT" \
  --arg repo "$REPO_ROOT" \
  --arg version "$CHECKOV_VERSION" \
  --slurpfile raw "$REPORT_RAW" \
  --slurpfile mapping "$MAPPING_FILE" \
'
  def get_map(id): ($mapping[0][id] // {category: "UNKNOWN", severity: null});

  def allowed_check(id):
    (id | startswith("CKV2_CS_AZ_"))
    or (id | startswith("CKV_AZURE_"))
    or (id | startswith("CKV_K8S_"));

  ($raw | flatten | map(.results.failed_checks // []) | flatten) as $findings
  | ($findings 
    | map(select(allowed_check(.check_id))) 
    | map({
        id: .check_id,
        resource: {
          name: .resource,
          path: .file_path
        },
        file: .file_path,
        line: .file_line_range[0],
        message: .check_name,
        category: (get_map(.check_id).category // (.check_class // "UNKNOWN")),
        severity: ((get_map(.check_id).severity // .severity // "MEDIUM") | ascii_upcase),
        status: "FAILED",
        fingerprint: (
          (.check_id + ":" + (.file_path // "unknown") + ":" + ((.file_line_range[0] // 0)|tostring))
          | @base64
        )
      })
    ) as $normalized
    
  # ---------------------------------------------------------------------------
  # NOTE: has_findings is a SCAN OBSERVATION, not a gate decision.
  # The block/allow decision is EXCLUSIVELY made by OPA (run-opa.sh).
  # Never use this field to gate a pipeline directly.
  # ---------------------------------------------------------------------------
  | {
      tool: "checkov",
      version: $version,
      has_findings: ($normalized | map(select(.status == "FAILED")) | length > 0),
      timestamp: $timestamp,
      branch: $branch,
      commit: $commit,
      repository: $repo,
      stats: {
        CRITICAL: ($normalized | map(select(.status == "FAILED" and .severity == "CRITICAL")) | length),
        HIGH:     ($normalized | map(select(.status == "FAILED" and .severity == "HIGH")) | length),
        MEDIUM:   ($normalized | map(select(.status == "FAILED" and .severity == "MEDIUM")) | length),
        LOW:      ($normalized | map(select(.status == "FAILED" and .severity == "LOW")) | length),
        INFO:     ($normalized | map(select(.status == "FAILED" and .severity == "INFO")) | length),
        TOTAL:    ($normalized | map(select(.status == "FAILED")) | length),
        EXEMPTED: 0,
        FAILED:   ($normalized | map(select(.status == "FAILED")) | length),
        PASSED:   ($normalized | map(select(.status == "PASSED")) | length)
      },
      findings: $normalized
    }
' > "$REPORT_OPA"

# --- Résumé Final ---
TOTAL_FAIL=$(jq '.stats.TOTAL' "$REPORT_OPA")

if [ "$TOTAL_FAIL" -gt 0 ]; then
    log_warn "Scan terminé : $TOTAL_FAIL violations détectées."
    # Affiche les 5 premières
    jq -r '.findings[] | select(.status == "FAILED") | "  [\(.severity)] \(.id) -> \(.resource)"' "$REPORT_OPA" | head -n 5
else
    log_success "Scan terminé : Aucune violation détectée."
fi

log_success "Rapport disponible : $REPORT_OPA"
exit 0
