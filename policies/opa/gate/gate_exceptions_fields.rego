package cloudsentinel.gate

import rego.v1

# Exception field accessors and scope/time predicates (module 4/8)

exception_id(ex) := lower(trim_space(object.get(ex, "id", "")))
exception_tool(ex) := lower(trim_space(object.get(ex, "tool", "")))
exception_rule(ex) := upper(trim_space(object.get(ex, "rule_id", "")))
exception_resource(ex) := lower(normalize_path(object.get(ex, "resource", "")))
exception_occurrence_file(ex) := lower(normalize_path(object.get(object.get(ex, "occurrence", {}), "file_path", "")))
exception_occurrence_hash(ex) := lower(trim_space(object.get(object.get(ex, "occurrence", {}), "hash_code", "")))
exception_severity(ex) := upper(trim_space(object.get(ex, "severity", "")))
exception_requested_by(ex) := lower(trim_space(object.get(ex, "requested_by", "")))
exception_approved_by(ex) := lower(trim_space(object.get(ex, "approved_by", "")))
exception_status(ex) := lower(trim_space(object.get(ex, "status", "")))
exception_source(ex) := lower(trim_space(object.get(ex, "source", "")))
exception_decision(ex) := lower(trim_space(object.get(ex, "decision", "")))
exception_approved_at(ex) := trim_space(object.get(ex, "approved_at", ""))
exception_expires_at(ex) := trim_space(object.get(ex, "expires_at", ""))

exception_occurrence_line(ex) := line if {
	raw := object.get(object.get(ex, "occurrence", {}), "line", -1)
	type_name(raw) == "number"
	line := raw
}

exception_occurrence_line(ex) := line if {
	raw := object.get(object.get(ex, "occurrence", {}), "line", -1)
	type_name(raw) == "string"
	trim_space(raw) != ""
	line := to_number(raw)
}

exception_occurrence_line(ex) := -1 if {
	raw := object.get(object.get(ex, "occurrence", {}), "line", -1)
	type_name(raw) == "string"
	trim_space(raw) == ""
}

exception_occurrence_line(ex) := -1 if {
	raw := object.get(object.get(ex, "occurrence", {}), "line", -1)
	type_name(raw) != "number"
	type_name(raw) != "string"
}

exception_occurrence_hash_valid(ex) if {
	exception_occurrence_hash(ex) == ""
}

exception_occurrence_hash_valid(ex) if {
	regex.match("^[a-f0-9]{64}$", exception_occurrence_hash(ex))
}

exception_has_wildcard(ex) if {
	contains(exception_resource(ex), "*")
}

exception_has_wildcard(ex) if {
	contains(exception_resource(ex), "?")
}

exception_scope_matches_repo(ex) if {
	repos := object.get(object.get(ex, "scope", {}), "repos", [])
	count(repos) == 0
}

exception_scope_matches_repo(ex) if {
	repos := object.get(object.get(ex, "scope", {}), "repos", [])
	count(repos) > 0
	current_repo := lower(trim_space(object.get(git_meta, "repo", "")))
	some r in repos
	lower(trim_space(r)) == current_repo
}

exception_scope_matches_env(ex) if {
	envs := object.get(object.get(ex, "scope", {}), "environments", [])
	count(envs) == 0
}

exception_scope_matches_env(ex) if {
	envs := object.get(object.get(ex, "scope", {}), "environments", [])
	count(envs) > 0
	some e in envs
	lower(trim_space(e)) == environment
}

exception_scope_matches_branch(ex) if {
	branches := object.get(object.get(ex, "scope", {}), "branches", [])
	count(branches) == 0
}

exception_scope_matches_branch(ex) if {
	branches := object.get(object.get(ex, "scope", {}), "branches", [])
	count(branches) > 0
	current_branch := lower(trim_space(object.get(git_meta, "branch", "")))
	some b in branches
	lower(trim_space(b)) == current_branch
}

exception_timestamp_fields_parse(ex) if {
	time.parse_rfc3339_ns(exception_approved_at(ex))
	time.parse_rfc3339_ns(exception_expires_at(ex))
}

exception_is_expired(ex) if {
	exception_expires_at(ex) != ""
	expires_ns := time.parse_rfc3339_ns(exception_expires_at(ex))
	time.now_ns() >= expires_ns
}
