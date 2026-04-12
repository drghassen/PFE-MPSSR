# CloudSentinel - Diagnostic Architecture Complet

**Date** : 2026-04-12  
**Phase** : Pré-Phase 1 (après Phase 0 Shift-Right OPA)  
**Objectif** : Identifier tous les gaps, violations, et risques avant continuation

---

## ✅ FORCES CONFIRMÉES

### Séparation Architecturale
- **Packages OPA distincts** : `cloudsentinel.shiftleft.pipeline` vs `cloudsentinel.shiftright.drift`
- **Normalizers séparés** : Pas de code partagé entre Left/Right
- **Schemas distincts** : Inputs clairement définis
- **Pas de références croisées** : Aucune fuite entre contextes

### OPA comme Point de Décision
- **drift_decision.rego** : 232 lignes, classification CRITICAL→INFO fonctionnelle
- **pipeline_decision.rego** : Opérationnel avec exceptions DefectDojo
- **Syntaxe OPA** : Valide (opa check passe)
- **Tests production** : 7 drifts détectés et classifiés correctement

---

## ❌ VIOLATIONS CRITIQUES IDENTIFIÉES

### 1. Legacy Severity Map (Shift-Right)
**Fichier** : `shift-right/drift-engine/utils/json_normalizer.py`  
**Ligne** : ~50-70  
**Code** :
```python
_SEVERITY_MAP = {
    "azurerm_storage_account.min_tls_version": "HIGH",
    ...
}
```
**Impact** : Viole principe "OPA as sole decision point"  
**Status** : Code présent mais **INUTILISÉ** (OPA décide maintenant)  
**Action** : Phase 1 - Supprimer complètement

### 2. Hardcoded Thresholds (Shift-Left - à vérifier)
**À auditer** : `shift-left/normalizer/normalize.py`  
**Recherche** : `if critical_count > 0` ou similarités

---

## ⚠️ GAPS MAJEURS

### Gap 1 : Pas d'Exceptions Drift (Shift-Right)
**Problème** : 
- Shift-Left a `exceptions_v2.schema.json` + `fetch_defectdojo.py`
- Shift-Right n'a AUCUNE gestion d'exceptions
- Tous les drifts sont flagués, même les légitimes (ex: scaling manuel d'urgence)

**Impact** : 
- Fausses alertes garanties en production
- Ops team va ignorer les alertes (alert fatigue)
- Drift légitime et drift malveillant indistinguables

**Solution** : Phase 1.5
- Créer `shift-right/drift-engine/exceptions/drift_exceptions.schema.json`
- Implémenter `fetch_drift_exceptions.py`
- Intégrer dans `opa_normalizer.py`

### Gap 2 : Cloud Custodian Non Implémenté
**Problème** :
- OPA assigne `custodian_policy = "enforce-storage-tls"`
- `action_required = "auto_remediate"`
- MAIS : Aucune policy Custodian n'existe

**Impact** :
- `auto_remediate` ne fait rien
- Promesse d'auto-remediation non tenue
- Architecture incomplète

**Solution** : Phase 2
- Créer `policies/custodian/azure/enforce-storage-tls.yml`
- Implémenter exécuteur Custodian dans drift-engine
- Tester avec drift réel

### Gap 3 : Pas de Feedback Loop
**Problème** :
- Drift corrigé manuellement ou par Custodian
- Code Terraform PAS mis à jour automatiquement
- Infrastructure et IaC divergent indéfiniment

**Impact** :
- IaC devient obsolète
- Prochain `tofu apply` réintroduit le drift
- Cycle de drift infini

**Solution** : Phase 3 (future)
- Workflow GitLab : Drift → Correction → MR auto pour mettre à jour IaC

---

## 🧪 TESTS MANQUANTS

### Shift-Left
- ✅ Tests unitaires normalize.py
- ✅ Tests OPA pipeline_decision_test.rego
- ❌ Tests scope-mismatch exceptions
- ❌ Tests intégration end-to-end

### Shift-Right
- ✅ Tests unitaires drift-engine
- ❌ Tests OPA drift_decision_test.rego (CRITIQUE)
- ❌ Tests Cloud Custodian integration
- ❌ Tests exceptions drift

---

## 📊 RÈGLES COMMUNES (DEFENSE-IN-DEPTH)

### Storage TLS < 1.2
- **Shift-Left** : Checkov `CKV_AZURE_44` bloque template
- **Shift-Right** : `drift_decision.rego` détecte modification manuelle
- **✅ CORRECT** : Les deux nécessaires

### NSG Rules Permissives
- **Shift-Left** : Checkov bloque `0.0.0.0/0` dans IaC
- **Shift-Right** : Détecte ajout manuel post-déploiement
- **✅ CORRECT** : Les deux nécessaires

**Pas de confusion** : Contextes différents = règles légitimement dupliquées

---

## 🎯 PRIORITÉS D'ACTION

### P0 (Avant Soutenance)
1. **Supprimer `_SEVERITY_MAP`** (Phase 1)
2. **Créer `drift_decision_test.rego`** (validation OPA)
3. **Documenter gaps** dans mémoire PFE (honnêteté académique)

### P1 (PFE Complet)
4. **Implémenter exceptions drift** (Phase 1.5)
5. **Cloud Custodian policies** (Phase 2)
6. **Tests end-to-end** (CI validation)

### P2 (Production Future)
7. **Feedback loop IaC** (Phase 3)
8. **Monitoring 24/7** (Grafana/Prometheus)

---

## 📈 SCORE ARCHITECTURE

| Critère | Score | Note |
|---------|-------|------|
| **Séparation Left/Right** | ✅ 10/10 | Parfait |
| **OPA as Sole Decision** | ⚠️ 7/10 | Legacy code présent (inutilisé) |
| **Gestion Exceptions** | ⚠️ 5/10 | Left OK, Right manquant |
| **Auto-Remediation** | ❌ 3/10 | Mapping présent, impl. absente |
| **Tests** | ⚠️ 6/10 | Coverage ~60% |
| **Documentation** | ✅ 9/10 | CLAUDE.md + docs complètes |

**Score Global** : 7/10 (Bon, gaps identifiés)

---

## 🚀 RECOMMANDATIONS FINALES

1. **NE PAS masquer les gaps** dans le mémoire PFE
   - Shift-Right partiellement implémenté = HONNÊTE
   - "Work in progress" = acceptable académiquement
   - Mieux qu'overstater et être challengé en soutenance

2. **Prioriser robustesse over features**
   - Mieux avoir Shift-Right sans Custodian mais bien testé
   - Que Custodian implementé mais buggé

3. **Documenter architecture = valeur académique**
   - Ce diagnostic = contenu de qualité pour Chapter 2
   - Montre maturité architecturale

4. **Tests = crédibilité**
   - Créer `drift_decision_test.rego` AVANT soutenance
   - Démontre rigueur engineering

