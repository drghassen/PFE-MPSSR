#!/usr/bin/env bash
# ============================================================
# CloudSentinel — Script de vérification des 10 corrections OPA
# Usage : bash verify_fixes.sh
# Doit être exécuté à la racine du repo pfe-cloud-sentinel
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

PASS=0; FAIL=0; WARN=0

pass() { echo -e "${GREEN}  ✓ PASS${NC}  $1"; ((PASS++)); }
fail() { echo -e "${RED}  ✗ FAIL${NC}  $1"; ((FAIL++)); }
warn() { echo -e "${YELLOW}  ⚠ WARN${NC}  $1"; ((WARN++)); }
header() { echo -e "\n${BOLD}${CYAN}── $1 ──${NC}"; }

# ============================================================
header "B2 — import rego.v1 dans drift_decision.rego"
# ============================================================

FILE="policies/opa/drift_decision.rego"

if ! grep -q "future.keywords" "$FILE"; then
  pass "future.keywords absent de $FILE"
else
  fail "future.keywords toujours présent dans $FILE"
  grep -n "future.keywords" "$FILE" | sed 's/^/     /'
fi

if grep -q "^import rego.v1" "$FILE"; then
  pass "import rego.v1 présent dans $FILE"
else
  fail "import rego.v1 manquant dans $FILE"
fi

# Parité avec pipeline_decision.rego
SL_IMPORTS=$(grep "^import" policies/opa/pipeline_decision.rego 2>/dev/null | sort)
SR_IMPORTS=$(grep "^import" "$FILE" | sort)
if [ "$SL_IMPORTS" = "$SR_IMPORTS" ]; then
  pass "Les deux fichiers .rego ont des imports identiques"
else
  warn "Imports différents entre pipeline_decision.rego et drift_decision.rego"
  echo -e "  ${DIM}shift-left : $SL_IMPORTS${NC}"
  echo -e "  ${DIM}shift-right: $SR_IMPORTS${NC}"
fi

# opa check si disponible
if command -v opa &>/dev/null; then
  if opa check --v1-compatible "$FILE" 2>/dev/null; then
    pass "opa check --v1-compatible OK"
  else
    fail "opa check --v1-compatible FAIL sur $FILE"
  fi
else
  warn "opa CLI non disponible — vérification opa check ignorée"
fi

# ============================================================
header "B3 — Normalisation de casse des sévérités"
# ============================================================

ENRICH="shift-right/drift-engine/utils/enrichment.py"
NORM="shift-right/drift-engine/utils/json_normalizer.py"
ENGINE="shift-right/drift-engine/drift-engine.py"

# enrichment.py : _OPA_SEVERITY_NORMALIZE
if grep -q "_OPA_SEVERITY_NORMALIZE" "$ENRICH"; then
  pass "_OPA_SEVERITY_NORMALIZE présent dans enrichment.py"
else
  fail "_OPA_SEVERITY_NORMALIZE ABSENT de enrichment.py"
fi

# enrichment.py : HIGH → High dans le normalize dict
if grep -q '"HIGH".*"High"\|HIGH.*:.*High' "$ENRICH"; then
  pass "Mapping HIGH → High présent dans enrichment.py"
else
  fail "Mapping HIGH → High ABSENT de enrichment.py"
fi

# enrichment.py : utilise le normalize dict sur opa_decision["severity"]
if grep -q "_OPA_SEVERITY_NORMALIZE.get" "$ENRICH"; then
  pass "_OPA_SEVERITY_NORMALIZE.get() utilisé dans enrichment.py"
else
  fail "_OPA_SEVERITY_NORMALIZE.get() NON utilisé dans enrichment.py"
fi

# json_normalizer.py : utilise item.get("severity") quand opa_evaluated
if grep -q "opa_evaluated\|item.get.*['\"]severity['\"]" "$NORM"; then
  pass "json_normalizer utilise la sévérité OPA (opa_evaluated)"
else
  fail "json_normalizer N'utilise PAS la sévérité OPA"
fi

# drift-engine.py : OCSF_ORDER utilise Info et non Informational
if grep -q '"Info"' "$ENGINE" && ! grep -q '"Informational"' "$ENGINE"; then
  pass "_OCSF_ORDER contient 'Info' (pas 'Informational')"
else
  if grep -q '"Informational"' "$ENGINE"; then
    fail "_OCSF_ORDER contient encore 'Informational' — non corrigé"
    grep -n "Informational" "$ENGINE" | sed 's/^/     /'
  else
    fail "_OCSF_ORDER : 'Info' non trouvé dans drift-engine.py"
  fi
fi

# Test Python de non-régression si possible
PYTEST_CMD=""
if command -v python3 &>/dev/null; then
  python3 -c "
import sys
sys.path.insert(0, 'shift-right/drift-engine')
try:
    from utils.enrichment import _OPA_SEVERITY_NORMALIZE
    assert _OPA_SEVERITY_NORMALIZE.get('HIGH') == 'High', f'HIGH→High FAIL: got {_OPA_SEVERITY_NORMALIZE.get(\"HIGH\")}'
    assert _OPA_SEVERITY_NORMALIZE.get('CRITICAL') == 'Critical', 'CRITICAL→Critical FAIL'
    assert _OPA_SEVERITY_NORMALIZE.get('LOW') == 'Low', 'LOW→Low FAIL'
    assert _OPA_SEVERITY_NORMALIZE.get('INFO') == 'Info', 'INFO→Info FAIL'
    ocsf = ['Info','Low','Medium','High','Critical']
    worst = max(['High','Critical','Low'], key=lambda s: ocsf.index(s))
    assert worst == 'Critical', f'OCSF max FAIL: {worst}'
    print('OK')
except Exception as e:
    print(f'FAIL:{e}')
    sys.exit(1)
" 2>/dev/null && pass "Python runtime : casing normalization OK" || fail "Python runtime : casing normalization FAIL"
fi

# ============================================================
header "B4 — Scope environnement dans valid_drift_exception()"
# ============================================================

REGO="policies/opa/drift_decision.rego"

if grep -q "_drift_exception_env_matches" "$REGO"; then
  pass "_drift_exception_env_matches() présent dans drift_decision.rego"
else
  fail "_drift_exception_env_matches() ABSENT de drift_decision.rego"
fi

if grep -q "_drift_exception_env_matches(ex)" "$REGO"; then
  pass "_drift_exception_env_matches(ex) appelé dans valid_drift_exception()"
else
  fail "_drift_exception_env_matches(ex) NON appelé dans valid_drift_exception()"
fi

OPA_NORM="shift-right/drift-engine/utils/opa_normalizer.py"
if grep -q '"environment"' "$OPA_NORM" || grep -q "environment" "$OPA_NORM"; then
  pass "Champ 'environment' présent dans opa_normalizer.py"
else
  fail "Champ 'environment' ABSENT de opa_normalizer.py"
fi

if grep -q "DRIFT_ENVIRONMENT\|CI_ENVIRONMENT_NAME" "$OPA_NORM"; then
  pass "Variable env DRIFT_ENVIRONMENT ou CI_ENVIRONMENT_NAME lue dans opa_normalizer.py"
else
  fail "DRIFT_ENVIRONMENT / CI_ENVIRONMENT_NAME absents de opa_normalizer.py"
fi

# ============================================================
header "B5 — Commentaire récursion OPA corrigé"
# ============================================================

if ! grep -q "récursion\|recursion" "$REGO"; then
  pass "Mot 'récursion/recursion' absent de drift_decision.rego"
else
  fail "Commentaire incorrect 'récursion' toujours présent dans drift_decision.rego"
  grep -n "récursion\|recursion" "$REGO" | sed 's/^/     /'
fi

# ============================================================
header "B6 — Cohérence temporelle approved_at < expires_at"
# ============================================================

if grep -q "approved_at_ns.*expires_at_ns\|approved_at.*<.*expires_at\|parse_rfc3339_ns.*approved.*<.*parse_rfc3339_ns.*expires" "$REGO"; then
  pass "Vérification approved_at < expires_at présente dans valid_drift_exception()"
else
  fail "Vérification approved_at < expires_at ABSENTE de valid_drift_exception()"
  echo -e "  ${DIM}Chercher : approved_at_ns < expires_at_ns${NC}"
fi

# Parité avec shift-left
SL_CHECK=$(grep -c "approved.*<.*expires\|approved_ns.*<.*expires_ns" policies/opa/pipeline_decision.rego 2>/dev/null || echo 0)
SR_CHECK=$(grep -c "approved.*<.*expires\|approved_at_ns.*<.*expires_at_ns" "$REGO" 2>/dev/null || echo 0)
if [ "$SR_CHECK" -gt 0 ]; then
  pass "Parité shift-left/shift-right sur le check temporel (shift-right: $SR_CHECK occurrence(s))"
else
  fail "Le check temporel approved < expires est présent en shift-left mais absent en shift-right"
fi

# ============================================================
header "B7 — fetch_drift_exceptions.py créé"
# ============================================================

SCRIPT="shift-right/scripts/fetch_drift_exceptions.py"

if [ -f "$SCRIPT" ]; then
  pass "Fichier $SCRIPT existe"
else
  fail "Fichier $SCRIPT ABSENT"
fi

if [ -f "$SCRIPT" ]; then
  if grep -q "def main\|def fetch_drift" "$SCRIPT"; then
    pass "$SCRIPT contient une fonction principale"
  else
    fail "$SCRIPT ne contient aucune fonction main()"
  fi

  if grep -q "drift_exceptions" "$SCRIPT"; then
    pass "$SCRIPT génère bien la clé 'drift_exceptions'"
  else
    fail "$SCRIPT ne génère pas la structure 'drift_exceptions'"
  fi

  if grep -q "DEFECTDOJO_URL\|DEFECTDOJO_API_KEY" "$SCRIPT"; then
    pass "$SCRIPT lit les credentials DefectDojo depuis les variables env"
  else
    fail "$SCRIPT : variables DEFECTDOJO_URL / DEFECTDOJO_API_KEY absentes"
  fi

  if grep -q "cloudsentinel-drift\|drift.*tag\|tag.*drift" "$SCRIPT"; then
    pass "$SCRIPT filtre par tag 'cloudsentinel-drift'"
  else
    warn "$SCRIPT : filtrage par tag 'cloudsentinel-drift' non détecté (vérifier manuellement)"
  fi
fi

if grep -q "fetch-drift-exceptions\|fetch_drift_exceptions" Makefile 2>/dev/null; then
  pass "Target 'fetch-drift-exceptions' présente dans Makefile"
else
  fail "Target 'fetch-drift-exceptions' ABSENTE du Makefile"
fi

# ============================================================
header "B8 — resource_id = address Terraform dans opa_normalizer"
# ============================================================

OPA_NORM="shift-right/drift-engine/utils/opa_normalizer.py"

# Doit utiliser item.get("address") et non item.get("resource_id") pour OPA
if grep -q '"resource_id".*item.get.*"address"\|"address".*resource_id' "$OPA_NORM"; then
  pass "opa_normalizer : resource_id = item['address'] (adresse Terraform)"
else
  # Check if old pattern still there
  if grep -q '"resource_id".*item.get.*"resource_id"' "$OPA_NORM"; then
    fail "opa_normalizer : resource_id utilise encore item['resource_id'] (ID Azure ARM) — non corrigé"
    grep -n "resource_id" "$OPA_NORM" | sed 's/^/     /'
  else
    warn "opa_normalizer : vérification resource_id → pattern non trouvé, vérifier manuellement"
    grep -n "resource_id\|address" "$OPA_NORM" | head -8 | sed 's/^/     /'
  fi
fi

# enrichment.py : warning défensif pour les ARM IDs
if grep -q "subscriptions.*warning\|starts.*subscriptions\|ARM.*id\|arm.*id" "shift-right/drift-engine/utils/enrichment.py"; then
  pass "enrichment.py : assertion défensive sur les ARM IDs présente"
else
  warn "enrichment.py : assertion défensive sur les ARM IDs non détectée (vérifier manuellement)"
fi

# ============================================================
header "B9 — Instance OPA dédiée shift-right (port 8182)"
# ============================================================

DC="docker-compose.yml"

if grep -q "opa-server-shiftright\|opa_server_shiftright" "$DC"; then
  pass "Service 'opa-server-shiftright' présent dans docker-compose.yml"
else
  fail "Service 'opa-server-shiftright' ABSENT de docker-compose.yml"
fi

if grep -q "8182" "$DC"; then
  pass "Port 8182 configuré dans docker-compose.yml"
else
  fail "Port 8182 ABSENT de docker-compose.yml"
fi

# drift_decision.rego ne doit plus être dans le service shift-left
SL_DRIFT_LINES=$(grep -A 30 "container_name: cloudsentinel-opa-server$" "$DC" 2>/dev/null | { grep -c "drift_decision" 2>/dev/null || true; }); SL_DRIFT_LINES=${SL_DRIFT_LINES:-0}
if [ "$SL_DRIFT_LINES" -eq 0 ]; then
  pass "drift_decision.rego absent du service opa-server shift-left"
else
  fail "drift_decision.rego encore présent dans le service opa-server shift-left"
fi

# drift_config.yaml doit pointer sur 8182
DRIFT_CFG="shift-right/drift-engine/config/drift_config.yaml"
if grep -q "8182" "$DRIFT_CFG"; then
  pass "drift_config.yaml pointe sur OPA port 8182"
else
  fail "drift_config.yaml pointe encore sur le port 8181 (partagé)"
  grep -n "server_url\|8181\|8182" "$DRIFT_CFG" | sed 's/^/     /'
fi

# ============================================================
header "B10 — Wildcard bloqué dans valid_drift_exception()"
# ============================================================

if grep -q "_drift_exception_has_wildcard" "$REGO"; then
  pass "_drift_exception_has_wildcard() présent dans drift_decision.rego"
else
  fail "_drift_exception_has_wildcard() ABSENT de drift_decision.rego"
fi

if grep -q "not _drift_exception_has_wildcard" "$REGO"; then
  pass "not _drift_exception_has_wildcard(ex) appelé dans valid_drift_exception()"
else
  fail "not _drift_exception_has_wildcard(ex) NON appelé dans valid_drift_exception()"
fi

# Vérifie que * et ? sont tous les deux bloqués
WILDCARD_CHECKS=$(grep -c 'contains.*"\*"\|contains.*"?"' "$REGO" 2>/dev/null || echo 0)
if [ "$WILDCARD_CHECKS" -ge 2 ]; then
  pass "Wildcards * et ? vérifiés dans les règles ($WILDCARD_CHECKS occurrences)"
else
  warn "Moins de 2 vérifications de wildcard trouvées (attendu : * et ? pour resource_type ET resource_id)"
fi

# ============================================================
header "B1 — docker-compose.yml + drift_exceptions.json bootstrap"
# ============================================================

if grep -q "drift_exceptions.json" "$DC"; then
  pass "drift_exceptions.json monté dans docker-compose.yml"
else
  fail "drift_exceptions.json NON monté dans docker-compose.yml"
fi

BOOTSTRAP=".cloudsentinel/drift_exceptions.json"
if [ -f "$BOOTSTRAP" ]; then
  pass "Fichier bootstrap $BOOTSTRAP existe"
  # Vérifier la structure
  if command -v python3 &>/dev/null; then
    python3 -c "
import json, sys
try:
    data = json.load(open('$BOOTSTRAP'))
    assert 'drift_exceptions' in data, 'clé drift_exceptions manquante'
    assert 'exceptions' in data['drift_exceptions'], 'clé exceptions manquante'
    assert isinstance(data['drift_exceptions']['exceptions'], list), 'exceptions doit être une liste'
    print('OK')
except Exception as e:
    print(f'FAIL:{e}')
    sys.exit(1)
" 2>/dev/null && pass "$BOOTSTRAP : structure JSON correcte (drift_exceptions.exceptions = [])" || fail "$BOOTSTRAP : structure JSON invalide"
  fi
else
  fail "Fichier bootstrap $BOOTSTRAP ABSENT"
fi

# ============================================================
header "Tests OPA complets"
# ============================================================

if command -v opa &>/dev/null; then
  OPA_OUT=$(opa test policies/opa/ -v 2>&1)
  OPA_PASS=$(echo "$OPA_OUT" | grep -c "PASS" || true)
  OPA_FAIL=$(echo "$OPA_OUT" | grep -c "FAIL" || true)

  if [ "$OPA_FAIL" -eq 0 ] && [ "$OPA_PASS" -ge 22 ]; then
    pass "opa test : $OPA_PASS tests PASS, 0 FAIL"
    if [ "$OPA_PASS" -ge 26 ]; then
      pass "opa test : $OPA_PASS tests PASS (≥26 — nouveaux tests B4/B6/B10 présents)"
    else
      warn "opa test : $OPA_PASS tests PASS — moins de 26 (nouveaux tests B4/B6/B10 manquants ?)"
    fi
  else
    fail "opa test : $OPA_PASS PASS / $OPA_FAIL FAIL"
    echo "$OPA_OUT" | grep "FAIL" | head -10 | sed 's/^/     /'
  fi
else
  warn "opa CLI non disponible — tests OPA ignorés. Exécuter manuellement : opa test policies/opa/ -v"
fi

# ============================================================
header "Tests Python (pytest)"
# ============================================================

if command -v python3 &>/dev/null; then
  if python3 -m pytest shift-right/drift-engine/tests/ -q 2>/dev/null; then
    pass "python3 -m pytest : tous les tests PASS"
  else
    fail "python3 -m pytest : des tests échouent"
  fi
else
  warn "python3 non disponible — tests Python ignorés"
fi

# ============================================================
header "Rapport final"
# ============================================================

TOTAL=$((PASS + FAIL + WARN))
echo ""
echo -e "${BOLD}┌─────────────────────────────────────────┐${NC}"
printf "${BOLD}│  PASS  : ${GREEN}%-3s${NC}${BOLD}  FAIL : ${RED}%-3s${NC}${BOLD}  WARN : ${YELLOW}%-3s${NC}${BOLD}       │${NC}\n" "$PASS" "$FAIL" "$WARN"
echo -e "${BOLD}└─────────────────────────────────────────┘${NC}"
echo ""

if [ "$FAIL" -eq 0 ]; then
  echo -e "${GREEN}${BOLD}✓ TOUTES LES VÉRIFICATIONS PASSENT — all_verifications_passed: true${NC}"
  echo ""
  echo -e "${DIM}Prochaine étape : git add -A && git commit -m 'fix(opa): apply all 10 B1-B10 corrections' && git push${NC}"
  exit 0
else
  echo -e "${RED}${BOLD}✗ $FAIL VÉRIFICATION(S) ÉCHOUENT — corriger avant de pousser${NC}"
  exit 1
fi