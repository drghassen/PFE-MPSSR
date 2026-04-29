# ==============================================================================
# CloudSentinel — Shift-Right Drift Policy (context & defaults)
# ==============================================================================

package cloudsentinel.shiftright.drift

import rego.v1

# ==============================================================================
# FIX: P0.1 — Defaults fail-safe pour éviter FAIL-OPEN sur input manquant
# Si input.findings est absent/null, OPA retourne [] au lieu de undefined.
# Sans ces defaults, le client Python interprète l'absence de clé comme
# "aucune violation" — comportement FAIL-OPEN silencieux.
# ==============================================================================

default violations := []

default compliant := []

correlation_id := id if {
	id := object.get(input, "correlation_id", "")
	trim(id, " \t\r\n") != ""
} else := "unknown"
