package cloudsentinel.gate

import rego.v1

# Intent contract rules (non-waivable) — module 8a/8
#
# Ces règles évaluent le contrat d'intention (intent.tf) contre les findings des scanners.
# Elles opèrent sur input.findings bruts (PAS effective_failed_findings) — ce qui les rend
# intrinsèquement non-waivable : les exceptions individuelles ne peuvent pas les neutraliser.

# non_waivable_violations : règles pour lesquelles aucune exception n'est acceptée,
# même approuvée via four-eyes dans DefectDojo. L'exception existante dans exceptions_store
# peut exempter le finding individuel de effective_failed_findings, mais la deny rule
# continue de s'appliquer car elle lit input.findings (signal brut).
non_waivable_violations := {
	"CS-INTENT-CONTRACT-MISSING",
	"CS-MULTI-SIGNAL-ROLE-SPOOFING",
	"CS-INTENT-FOUR-EYES-VIOLATION",
	"CS-INTENT-DB-INTERNET-FACING",
	"CS-SCHEMA-VERSION-UNSUPPORTED",
}

# ─── CS-INTENT-CONTRACT-MISSING ──────────────────────────────────────────────
# Bloque tout déploiement sans déclaration d'intention.
# Déclenché quand extract_intent_contract() retourne violation=MISSING_INTENT_CONTRACT.
# non_waivable : aucune exception possible, même approuvée four-eyes.
deny[msg] if {
	object.get(object.get(input, "intent_contract", {}), "violation", "") == "MISSING_INTENT_CONTRACT"
	msg := sprintf(
		"CS-INTENT-CONTRACT-MISSING [CRITICAL|non_waivable]: Intent contract absent — tout déploiement sans déclaration d'intention est bloqué (rule=%s)",
		["CS-INTENT-CONTRACT-MISSING"],
	)
}

# ─── CS-MULTI-SIGNAL-ROLE-SPOOFING ───────────────────────────────────────────
# Détection par convergence de 3 signaux indépendants. Les 3 signaux doivent être
# simultanément vrais pour déclencher le deny (réduction des faux positifs).
#
# Signal 1 — intent.declared.service_type == "web-server"
# Signal 2 — intent_mismatches contient CS-INTENT-ROLE-SPOOFING (corrélé par normalize.py)
# Signal 3 — au moins un finding Checkov de sévérité HIGH ou CRITICAL dans input.findings bruts
#
# Signal 3 utilise input.findings (PAS effective_failed_findings) : les exceptions individuelles
# sur les findings Checkov ne neutralisent PAS cette règle.
# non_waivable : aucune exception possible, même approuvée four-eyes.
deny[msg] if {
	# Signal 1 : service_type déclaré = web-server
	object.get(
		object.get(object.get(input, "intent_contract", {}), "declared", {}),
		"service_type", "",
	) == "web-server"

	# Signal 2 : normalize.py a détecté un mismatch CS-INTENT-ROLE-SPOOFING
	some mm in object.get(input, "intent_mismatches", [])
	mm.rule == "CS-INTENT-ROLE-SPOOFING"

	# Signal 3 : au moins un finding Checkov HIGH/CRITICAL dans les findings bruts
	some f in object.get(input, "findings", [])
	finding_tool(f) == "checkov"
	finding_severity_level(f) in {"HIGH", "CRITICAL"}

	msg := sprintf(
		"CS-MULTI-SIGNAL-ROLE-SPOOFING [CRITICAL|non_waivable]: role spoofing détecté — signals=[signal_1:service_type=web-server, signal_2:mismatch=%s, signal_3:checkov_finding=%s|%s]",
		[mm.rule, finding_tool(f), finding_severity_level(f)],
	)
}

# \u2500\u2500\u2500 CS-INTENT-FOUR-EYES-VIOLATION \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
deny[msg] if {
	declared := object.get(object.get(input, "intent_contract", {}), "declared", {})
	owner := trim_space(object.get(declared, "owner", ""))
	approved_by := trim_space(object.get(declared, "approved_by", ""))
	owner != ""
	approved_by != ""
	lower(owner) == lower(approved_by)
	msg := "CS-INTENT-FOUR-EYES-VIOLATION [CRITICAL|non_waivable]: owner and approved_by must be different (Four-Eyes Principle)"
}

# \u2500\u2500\u2500 CS-INTENT-DB-INTERNET-FACING \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
deny[msg] if {
	declared := object.get(object.get(input, "intent_contract", {}), "declared", {})
	service_type := object.get(declared, "service_type", "")
	exposure_level := object.get(declared, "exposure_level", "")
	service_type == "database"
	exposure_level == "internet-facing"
	msg := "CS-INTENT-DB-INTERNET-FACING [CRITICAL|non_waivable]: databases cannot be internet-facing"
}

# \u2500\u2500\u2500 CS-SCHEMA-VERSION-UNSUPPORTED \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
deny[msg] if {
	schema_version := object.get(input, "schema_version", "")
	not regex.match(`^1\.[2-9][0-9]*\.\d+$`, schema_version)
	msg := "CS-SCHEMA-VERSION-UNSUPPORTED [CRITICAL|non_waivable]: schema_version is unsupported or missing"
}
