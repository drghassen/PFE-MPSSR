# Phase 0 : OPA Integration - Shift-Right Drift Decision

## Objectif
Intégrer OPA comme point de décision unique pour l'évaluation des dérives Terraform, en remplacement du hardcoded `_SEVERITY_MAP`.

## Architecture
- **Détection** : `json_normalizer.py` (inchangé)
- **Normalisation** : `opa_normalizer.py` (nouveau)
- **Décision** : OPA Server + `drift_decision.rego` (nouveau)
- **Enrichissement** : `enrichment.py` (nouveau)
- **Audit** : DefectDojo (inchangé)

## Fichiers Créés
- `policies/opa/drift_decision.rego` (232 lignes)
- `shift-right/drift-engine/utils/opa_client.py` (153 lignes)
- `shift-right/drift-engine/utils/opa_normalizer.py` (65 lignes)
- `shift-right/drift-engine/utils/enrichment.py` (89 lignes)

## Tests Validés
- ✅ Python syntax OK
- ✅ OPA syntax OK
- ✅ OPA Server accessible depuis WSL
- ✅ 2 violations détectées (fixture test)
- ✅ Classification CRITICAL/HIGH correcte
- ✅ Cloud Custodian policy assignée

## Configuration
OPA Server : `http://localhost:8181`
Policy Path : `cloudsentinel.shiftright.drift`

## Status
✅ Phase 0 complète et validée (2026-04-12)
