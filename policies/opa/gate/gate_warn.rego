package cloudsentinel.gate

import rego.v1

# Advisory warn signals — MEDIUM and LOW effective findings (module 9/8).
#
# warn is structurally parallel to deny but carries ZERO enforcement weight:
#   deny → allow = false  (blocks the pipeline)
#   warn → allow unchanged (purely advisory — visibility + tracking)
#
# Severity routing:
#   CRITICAL → deny  (gate_deny.rego)
#   HIGH     → deny  (gate_deny.rego)
#   MEDIUM   → warn  (this module) — SLA required, open DefectDojo ticket
#   LOW      → warn  (this module) — backlog item, review before next release

warn[msg] if {
	effective_medium > 0
	msg := sprintf(
		"MEDIUM findings (%d) — open a DefectDojo ticket or submit an exception request",
		[effective_medium],
	)
}

warn[msg] if {
	effective_low > 0
	msg := sprintf(
		"LOW findings (%d) — add to backlog and review before next release",
		[effective_low],
	)
}
