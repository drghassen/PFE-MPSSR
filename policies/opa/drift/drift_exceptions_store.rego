# ==============================================================================
# Exception handling pour drift — 12 critères de validation (Phase 2 accomplie).
# Critères actifs dans drift_exceptions_fields.rego :
#   1-5.  source, status, requested_by, approved_by, four-eyes
#   5b.   SHA256 ID format (^[a-f0-9]{64}$) — aligné shift-left
#   6-7.  resource_type et resource_id non-vides, sans wildcard
#   8-10. approved_at RFC3339 passé, expires_at obligatoire et futur,
#         approved_at < expires_at
#   11-12. environments scope strict, repo/branch scope optionnel
# Diagnostics : drift_partial_matches_audit dans drift_exceptions_match.rego.
# ==============================================================================
# Chargement des exceptions depuis data.drift_exceptions (document statique OPA).
# ARCHITECTURE : drift_exceptions.json est monté via --data au démarrage du serveur
# OPA (opa-server-shiftright, port 8182). data.* et le package cloudsentinel.shiftright.drift
# sont des namespaces totalement distincts — aucune interaction circulaire possible.
# SÉPARATION EXPLICITE depuis les exceptions shift-left (data.cloudsentinel.exceptions)
# qui ont un format et un cycle de vie différents.
# Si le bundle n'est pas monté, default {} est utilisé → zéro exception active (fail-safe).
# ==============================================================================

package cloudsentinel.shiftright.drift

import rego.v1

default _drift_exceptions_store := {}

_drift_exceptions_store := data.cloudsentinel.drift_exceptions
