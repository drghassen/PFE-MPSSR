# ==============================================================================
# Shift-Right Prowler — Cross-signal correlation escalation (G6)
#
# Package: cloudsentinel.shiftright.prowler  (same as prowler_decision.rego)
# OPA merges set-rules across files in the same package, so the `deny` set
# defined here is unioned with the deny set in prowler_decision.rego.
#
# This module reads correlation data injected as OPA data and adds a deny
# entry whenever CRITICAL_CONFIRMED correlations exist. It is ADDITIVE — it
# does NOT modify prowler_decision.rego.
#
# Data injection requirement:
#   correlation_report.json must be wrapped and loaded alongside this policy:
#
#     {
#       "cloudsentinel": {
#         "correlation_report": {
#           "meta": { ... },
#           "correlations": [ ... ]
#         }
#       }
#     }
#
#   This maps to data.cloudsentinel.correlation_report.correlations in OPA.
#   When the file is absent or empty, _correlations defaults to [] and this
#   module adds nothing to the deny set (fail-safe behavior).
#
#   A future iteration of opa-prowler-decision.sh will wrap and pass the file.
#   Until then, enforcement is via CORRELATION_CRITICAL_CONFIRMED in correlation.env.
# ==============================================================================

package cloudsentinel.shiftright.prowler

import rego.v1

# ---------------------------------------------------------------------------
# Correlation data (injected as OPA data, absent → empty list)
# ---------------------------------------------------------------------------

_correlations := data.cloudsentinel.correlation_report.correlations if {
	data.cloudsentinel.correlation_report.correlations
} else := []

# ---------------------------------------------------------------------------
# Escalation rules
# ---------------------------------------------------------------------------

# Produce a deny entry when any correlated pair has CRITICAL_CONFIRMED risk.
# This is in addition to the deny rules in prowler_decision.rego.
deny contains msg if {
	_critical_confirmed_count > 0
	msg := {
		"code": "CORRELATION_CRITICAL_CONFIRMED",
		"message": sprintf(
			"Cross-signal correlation: %d resource(s) have both a Critical Prowler finding and active drift. Combined risk: CRITICAL_CONFIRMED. Resources: %s",
			[
				_critical_confirmed_count,
				concat(", ", [r.resource_uid | some r in _correlations; r.combined_risk == "CRITICAL_CONFIRMED"]),
			],
		),
	}
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_critical_confirmed_count := count([r |
	some r in _correlations
	r.combined_risk == "CRITICAL_CONFIRMED"
])

_high_confirmed_count := count([r |
	some r in _correlations
	r.combined_risk == "HIGH_CONFIRMED"
])

# Expose correlation summary in the decision document (read by decision rule
# in prowler_decision.rego via the merged package view).
correlation_summary := {
	"critical_confirmed": _critical_confirmed_count,
	"high_confirmed":     _high_confirmed_count,
	"total_correlated":   count(_correlations),
}
