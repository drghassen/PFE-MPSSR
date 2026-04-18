# ==============================================================================
# FIX: P1.2 — Exception handling pour drift (Phase 1 simplifiée)
# LIMITATION SCOPE : Phase 1 — 6 critères de validation.
# Phase 2 (post-soutenance) : aligner sur les 12 critères du shift-left
# (SHA256 ID, tool whitelist, no wildcard resource, severity rank map,
#  partial_mismatch_reasons, scope repo/branch/env, etc.)
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
