#!/usr/bin/env bash
set -e

# ==============================================================================
# CloudSentinel — Orchestrateur de Scan Complet (End-to-End Flow)
#
# Ce script lance la chaîne complète :
# 1. Scanners (Gitleaks, Checkov, Trivy)
# 2. Normalisation (Extraction des données pures)
# 3. Decision (OPA Quality Gate)
# ==============================================================================

# --- Couleurs ---
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_step() {
    echo -e "\n${BOLD}${PURPLE}STAGE: $*${NC}"
    echo -e "${PURPLE}─────────────────────────────────────────────────────────────────${NC}"
}

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

# --- 1. SCANNERS ---
log_step "Exécution des Scanners (Détection)"

echo -e "${CYAN}[1/3] Gitleaks (Secrets)...${NC}"
bash shift-left/gitleaks/run-gitleaks.sh

echo -e "\n${CYAN}[2/3] Checkov (IaC)...${NC}"
# On scanne un dossier de test ou l'infra par défaut
bash shift-left/checkov/run-checkov.sh infra/azure/dev

echo -e "\n${CYAN}[3/3] Trivy (Vulnerabilities)...${NC}"
# On scanne en mode config par défaut
(cd shift-left/trivy && bash scripts/run-trivy.sh ../../infra/azure/dev config)

# --- 2. NORMALIZATION ---
log_step "Normalisation (Fusion & Standardisation)"
bash shift-left/normalizer/normalize.sh

# --- 3. OPA DECISION ---
log_step "OPA Decision (Gouvernance & Quality Gate)"
# On utilise le script PEP que nous avons créé
# Mode --advisory pour voir le résultat sans bloquer le script bash
bash shift-left/opa/run-opa.sh --advisory

echo -e "\n${BOLD}${PURPLE}Flux CloudSentinel terminé avec succès. ✅${NC}"
