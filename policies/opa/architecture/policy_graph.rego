# ==============================================================================
# CloudSentinel — Policy graph & subsystem ownership (documentation module)
#
# This package does NOT participate in CI blocking or drift remediation at runtime
# unless explicitly queried. It encodes architecture invariants for operators and
# reviewers. OPA loads it with the rest of policies/opa during `opa check`.
#
# Related risks (security architecture review):
#   - Policy graph complexity: many .rego files, same-package merge — use file names
#     + this map to trace rule origin.
#   - Gate vs drift semantic divergence: intentional (CI gate vs runtime drift);
#     there is NO automatic severity coupling — document workflows accordingly.
#   - Two exception stores (shift-left vs shift-right): separate JSON paths by
#     design in Phase 1; a shared cloudsentinel.exceptions.core layer is roadmap.
# ==============================================================================

package cloudsentinel.architecture

import rego.v1

# Logical PDP boundaries (mirrors docker-compose opa-server vs opa-server-shiftright).
policy_subsystems := {
	"shift_left_gate": {
		"package": "cloudsentinel.gate",
		"docker_service": "opa-server",
		"listen_port": 8181,
		"policy_dir": "policies/opa/gate",
		"data_root_key": "cloudsentinel.exceptions",
		"data_file_host": "config/opa/data/exceptions.json",
		"ci_data_file_host": ".cloudsentinel/exceptions.json",
		"primary_http_eval": "/v1/data/cloudsentinel/gate/decision",
		"pep": "shift-left/opa/run-opa.sh",
	},
	"shift_right_drift": {
		"package": "cloudsentinel.shiftright.drift",
		"docker_service": "opa-server-shiftright",
		"listen_port": 8182,
		"policy_dir": "policies/opa/drift",
		"data_root_key": "cloudsentinel.drift_exceptions",
		"data_file_host": "config/opa/data/drift_exceptions.json",
		"ci_data_file_host": ".cloudsentinel/drift_exceptions.json",
		"pep": "ci/scripts/opa-drift-decision.sh",
	},
	"shared": {
		"authz_package": "system.authz",
		"authz_file": "policies/opa/system/authz.rego",
		"note": "Same authz policy on both PDPs; compose token from config/opa/data/opa_auth_config.json, CI token from .cloudsentinel/opa_auth_config.json",
	},
}

# Explicit non-goals / known gaps (do not treat as runtime guarantees).
architecture_notes := [
	"Gate and drift use different packages — no Rego symbol coupling between them.",
	"Severity/classification rules are not unified: gate thresholds != drift changed_paths taxonomy.",
	"Exceptions: data.cloudsentinel.exceptions (gate) vs data.cloudsentinel.drift_exceptions (drift).",
	"Future P0: optional shared severity matrix or shared exception core if product requires parity.",
]
