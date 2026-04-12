#!/bin/bash
set -e
cd ~/pfe-cloud-sentinel

echo "=== Phase 0 : Création structure OPA Drift Integration ==="

mkdir -p shift-right/drift-engine/tests/integration
mkdir -p policies/opa

echo "Création des fichiers..."
touch policies/opa/drift_decision.rego
touch shift-right/drift-engine/utils/opa_client.py
touch shift-right/drift-engine/utils/opa_normalizer.py
touch shift-right/drift-engine/utils/enrichment.py
touch shift-right/drift-engine/tests/test_opa_integration.py
touch shift-right/drift-engine/tests/fixtures_drift_opa.json
touch shift-right/drift-engine/PHASE0_OPA_INTEGRATION.md

echo "Backup des fichiers existants..."
cp docker-compose.yml docker-compose.yml.backup
cp shift-right/drift-engine/config/drift_config.yaml shift-right/drift-engine/config/drift_config.yaml.backup
cp shift-right/drift-engine/drift-engine.py shift-right/drift-engine/drift-engine.py.backup

echo ""
echo "✅ Phase 0 : Structure créée avec succès"
echo ""
tree -L 1 policies/opa/
tree -L 1 shift-right/drift-engine/utils/
