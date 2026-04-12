#!/bin/bash

# CloudSentinel - Diagnostic Architecture Rapide
# Usage: bash diagnostic.sh

clear
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║        CloudSentinel - Diagnostic Architecture v1.0            ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Fonction pour afficher les résultats
print_result() {
    local status=$1
    local message=$2
    if [ "$status" = "OK" ]; then
        echo "  ✅ $message"
    elif [ "$status" = "WARNING" ]; then
        echo "  ⚠️  $message"
    else
        echo "  ❌ $message"
    fi
}

# ============================================================
# 1. SÉPARATION SHIFT-LEFT vs SHIFT-RIGHT
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1️⃣  SÉPARATION ARCHITECTURALE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Packages OPA
LEFT_PKG=$(grep "^package" policies/opa/pipeline_decision.rego 2>/dev/null | awk '{print $2}')
RIGHT_PKG=$(grep "^package" policies/opa/drift_decision.rego 2>/dev/null | awk '{print $2}')

if [ "$LEFT_PKG" = "cloudsentinel.shiftleft.pipeline" ]; then
    print_result "OK" "Shift-Left package: $LEFT_PKG"
else
    print_result "FAIL" "Shift-Left package incorrect: $LEFT_PKG"
fi

if [ "$RIGHT_PKG" = "cloudsentinel.shiftright.drift" ]; then
    print_result "OK" "Shift-Right package: $RIGHT_PKG"
else
    print_result "FAIL" "Shift-Right package incorrect: $RIGHT_PKG"
fi

# Références croisées
DRIFT_IN_LEFT=$(grep -i "drift" policies/opa/pipeline_decision.rego 2>/dev/null | wc -l)
PIPELINE_IN_RIGHT=$(grep -i "pipeline" policies/opa/drift_decision.rego 2>/dev/null | wc -l)

if [ $DRIFT_IN_LEFT -eq 0 ] && [ $PIPELINE_IN_RIGHT -eq 0 ]; then
    print_result "OK" "Pas de références croisées"
else
    print_result "WARNING" "Références croisées détectées ($DRIFT_IN_LEFT left, $PIPELINE_IN_RIGHT right)"
fi

echo ""

# ============================================================
# 2. VIOLATIONS "OPA AS SOLE DECISION POINT"
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "2️⃣  PRINCIPE OPA AS SOLE DECISION POINT"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Severity maps hardcodées
SEVERITY_MAPS=$(grep -rn "_SEVERITY_MAP\|severity_map" shift-right/drift-engine/utils/ --include="*.py" 2>/dev/null | grep -v "__pycache__" | wc -l)

if [ $SEVERITY_MAPS -gt 0 ]; then
    print_result "FAIL" "Hardcoded severity maps trouvées ($SEVERITY_MAPS occurrences)"
    echo "      📁 Fichier: shift-right/drift-engine/utils/json_normalizer.py"
    echo "      🔧 Action: Phase 1 - Supprimer _SEVERITY_MAP"
else
    print_result "OK" "Pas de severity maps hardcodées"
fi

# Décisions Python sur severity
PYTHON_DECISIONS=$(grep -rn "if.*severity.*==" shift-left/ shift-right/ --include="*.py" 2>/dev/null | grep -v "__pycache__" | grep -v "test" | wc -l)

if [ $PYTHON_DECISIONS -gt 0 ]; then
    print_result "WARNING" "Décisions Python sur severity ($PYTHON_DECISIONS occurrences)"
else
    print_result "OK" "Pas de décisions Python sur severity"
fi

echo ""

# ============================================================
# 3. SYNTAXE ET VALIDITÉ OPA
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "3️⃣  SYNTAXE OPA"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if opa check policies/opa/pipeline_decision.rego &>/dev/null; then
    print_result "OK" "pipeline_decision.rego syntaxe valide"
else
    print_result "FAIL" "pipeline_decision.rego erreur syntaxe"
fi

if opa check policies/opa/drift_decision.rego &>/dev/null; then
    print_result "OK" "drift_decision.rego syntaxe valide"
else
    print_result "FAIL" "drift_decision.rego erreur syntaxe"
fi

echo ""

# ============================================================
# 4. GESTION DES EXCEPTIONS
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "4️⃣  GESTION DES EXCEPTIONS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Shift-Left
if [ -f "shift-left/opa/schema/exceptions_v2.schema.json" ]; then
    print_result "OK" "Shift-Left: exceptions_v2.schema.json existe"
else
    print_result "FAIL" "Shift-Left: schema exceptions manquant"
fi

# Shift-Right
DRIFT_EXCEPTIONS=$(find shift-right/drift-engine -name "*exception*" 2>/dev/null | wc -l)

if [ $DRIFT_EXCEPTIONS -gt 0 ]; then
    print_result "OK" "Shift-Right: exceptions implémentées"
else
    print_result "FAIL" "Shift-Right: PAS de gestion exceptions"
    echo "      🔧 Action: Phase 1.5 - Implémenter drift exceptions"
fi

echo ""

# ============================================================
# 5. CLOUD CUSTODIAN AUTO-REMEDIATION
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "5️⃣  CLOUD CUSTODIAN AUTO-REMEDIATION"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Mapping dans OPA
CUSTODIAN_MAPPING=$(grep -c "custodian_policy" policies/opa/drift_decision.rego 2>/dev/null)

if [ $CUSTODIAN_MAPPING -gt 0 ]; then
    print_result "OK" "OPA assigne policies Custodian ($CUSTODIAN_MAPPING règles)"
else
    print_result "WARNING" "Pas de mapping Custodian dans OPA"
fi

# Policies réelles
CUSTODIAN_POLICIES=$(find policies/custodian/azure -name "*.yml" -o -name "*.yaml" 2>/dev/null | wc -l)

if [ $CUSTODIAN_POLICIES -gt 0 ]; then
    print_result "OK" "Policies Custodian implémentées ($CUSTODIAN_POLICIES fichiers)"
else
    print_result "FAIL" "AUCUNE policy Custodian implémentée"
    echo "      🔧 Action: Phase 2 - Créer policies Custodian"
fi

echo ""

# ============================================================
# 6. TESTS
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "6️⃣  COUVERTURE TESTS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Tests Shift-Left
LEFT_TESTS=$(find shift-left -name "test_*.py" 2>/dev/null | wc -l)
print_result "OK" "Shift-Left: $LEFT_TESTS tests Python"

# Tests Shift-Right
RIGHT_TESTS=$(find shift-right -name "test_*.py" 2>/dev/null | wc -l)
print_result "OK" "Shift-Right: $RIGHT_TESTS tests Python"

# Tests OPA
if [ -f "policies/opa/pipeline_decision_test.rego" ]; then
    print_result "OK" "Tests OPA Shift-Left présents"
else
    print_result "WARNING" "Tests OPA Shift-Left manquants"
fi

if [ -f "policies/opa/drift_decision_test.rego" ]; then
    print_result "OK" "Tests OPA Shift-Right présents"
else
    print_result "FAIL" "Tests OPA Shift-Right MANQUANTS"
    echo "      🔧 Action: Créer drift_decision_test.rego"
fi

echo ""

# ============================================================
# RÉSUMÉ FINAL
# ============================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 RÉSUMÉ DIAGNOSTIC"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "✅ FORCES:"
echo "   • Séparation Shift-Left/Right claire"
echo "   • Packages OPA distincts"
echo "   • Syntaxe OPA valide"
echo ""
echo "❌ GAPS CRITIQUES:"
echo "   1. _SEVERITY_MAP legacy dans json_normalizer.py (Phase 1)"
echo "   2. Pas d'exceptions Shift-Right (Phase 1.5)"
echo "   3. Cloud Custodian non implémenté (Phase 2)"
echo "   4. Tests OPA Shift-Right manquants"
echo ""
echo "🎯 PROCHAINES ACTIONS:"
echo "   [ ] Supprimer _SEVERITY_MAP"
echo "   [ ] Créer drift_decision_test.rego"
echo "   [ ] Implémenter exceptions drift"
echo "   [ ] Créer policies Cloud Custodian"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📄 Rapport complet: docs/DIAGNOSTIC_$(date +%Y-%m-%d).md"
echo ""
