package cloudsentinel.gate

import rego.v1

# rego 0.69.1 — Shift-Left gate: context, thresholds, failed findings (module 1/8)

scanners := object.get(input, "scanners", {})
thresholds := object.get(object.get(input, "quality_gate", {}), "thresholds", {})
required_scanners := ["gitleaks", "checkov", "trivy"]
allowed_tools := {"gitleaks", "checkov", "trivy"}
allowed_decisions := {"accept", "mitigate", "fix", "transfer", "avoid"}

# db_ports : ports associés aux moteurs de base de données courants.
# Utilisé par CS-MULTI-SIGNAL-ROLE-SPOOFING pour corréler le contrat d'intention
# avec les findings Checkov détectant des ports DB dans des ressources web-server.
# Doit rester synchronisé avec DB_PORTS dans shift-left/normalizer/cs_norm_constants.py.
db_ports := {3306, 5432, 27017, 1433, 6379, 5984, 9042, 2181}

metadata := object.get(input, "metadata", {})
git_meta := object.get(metadata, "git", {})
environment := lower(object.get(metadata, "environment", "dev"))
execution_mode := lower(object.get(object.get(metadata, "execution", {}), "mode", "ci"))

critical_max_raw := object.get(thresholds, "critical_max", 0)
high_max_raw := object.get(thresholds, "high_max", 2)

critical_max := to_number(critical_max_raw)
high_max := to_number(high_max_raw)

# Policy-enforced ceilings — not injectable from input or CI variables.
# Input thresholds are clamped to these maximums regardless of what CI passes.
_policy_critical_max_ceiling := 0
_policy_high_max_ceiling := 5

enforced_critical_max := min([critical_max, _policy_critical_max_ceiling])
enforced_high_max := min([high_max, _policy_high_max_ceiling])

thresholds_valid if {
	to_number(critical_max_raw)
	to_number(high_max_raw)
}

severity_rank := {
	"LOW": 1,
	"MEDIUM": 2,
	"HIGH": 3,
	"CRITICAL": 4,
}

default exceptions_store := []

exceptions_store := data.cloudsentinel.exceptions.exceptions

is_local if {
	execution_mode == "local"
}

is_local if {
	execution_mode == "advisory"
}

failed_findings := [f |
	some i
	f := object.get(input, "findings", [])[i]
	object.get(f, "status", "") == "FAILED"
	not to_bool(object.get(object.get(object.get(f, "context", {}), "deduplication", {}), "is_duplicate", false))
]
