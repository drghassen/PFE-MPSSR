package cloudsentinel.gate

import rego.v1

#rego 0.69.1

scanners := object.get(input, "scanners", {})
thresholds := object.get(object.get(input, "quality_gate", {}), "thresholds", {})
required_scanners := ["gitleaks", "checkov", "trivy"]
allowed_tools := {"gitleaks", "checkov", "trivy"}
allowed_scope_types := {"commit", "branch", "repo", "global"}
allowed_envs := {"dev", "test", "staging", "prod"}
allowed_roles := {"APPSEC_L1", "APPSEC_L2", "APPSEC_L3", "APPSEC_MANAGER", "SECURITY_MANAGER"}
global_scope_roles := {"APPSEC_L3", "APPSEC_MANAGER", "SECURITY_MANAGER"}
ns_per_day := 86400000000000

metadata := object.get(input, "metadata", {})
git_meta := object.get(metadata, "git", {})
environment := lower(object.get(metadata, "environment", "dev"))
execution_mode := lower(object.get(object.get(metadata, "execution", {}), "mode", "ci"))
input_repo := lower(trim_space(object.get(git_meta, "repo", object.get(git_meta, "repository", object.get(metadata, "repo", "unknown")))))
input_branch := lower(trim_space(object.get(git_meta, "branch", "unknown")))
input_commit := lower(trim_space(object.get(git_meta, "commit", "")))

default exceptions_store := []
exceptions_store := data.cloudsentinel.exceptions.exceptions

legacy_cfg := object.get(data.cloudsentinel.exceptions, "legacy_compatibility", {})
legacy_enabled := object.get(legacy_cfg, "enabled", true)
legacy_sunset_raw := object.get(legacy_cfg, "sunset_date", "2099-12-31T23:59:59Z")
legacy_window_open if {
  sunset := time.parse_rfc3339_ns(legacy_sunset_raw)
  time.now_ns() <= sunset
}
legacy_mode_allowed if {
  legacy_enabled
  legacy_window_open
}

critical_max_raw := object.get(thresholds, "critical_max", 0)
high_max_raw := object.get(thresholds, "high_max", 2)

critical_max := to_number(critical_max_raw)
high_max := to_number(high_max_raw)

thresholds_valid if {
  to_number(critical_max_raw)
  to_number(high_max_raw)
}

severity_rank := {
  "INFO": 1,
  "LOW": 2,
  "MEDIUM": 3,
  "HIGH": 4,
  "CRITICAL": 5
}

role_rank := {
  "APPSEC_L1": 1,
  "APPSEC_L2": 2,
  "APPSEC_L3": 3,
  "APPSEC_MANAGER": 4,
  "SECURITY_MANAGER": 4
}

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

normalize_path(path) := normalized if {
  type_name(path) == "string"
  p1 := replace(path, "\\", "/")
  p2 := replace(p1, "/./", "/")
  p3 := replace(p2, "//", "/")
  p4 := trim_prefix(p3, "./")
  normalized := trim(p4, "/")
}

normalize_path(path) := "" if {
  type_name(path) != "string"
}

to_bool(v) := b if {
  type_name(v) == "boolean"
  b := v
}

to_bool(v) := true if {
  type_name(v) == "string"
  vv := lower(trim_space(v))
  vv == "true"
}

to_bool(v) := true if {
  type_name(v) == "string"
  vv := lower(trim_space(v))
  vv == "1"
}

to_bool(v) := false if {
  type_name(v) == "string"
  vv := lower(trim_space(v))
  vv == "false"
}

to_bool(v) := false if {
  type_name(v) == "string"
  vv := lower(trim_space(v))
  vv == "0"
}

to_bool(v) := false if {
  type_name(v) != "boolean"
  type_name(v) != "string"
}

valid_uuid(v) if {
  regex.match("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$", trim_space(v))
}

finding_rule_id(f) := upper(trim_space(object.get(object.get(f, "source", {}), "id", "")))
finding_tool(f) := lower(trim_space(object.get(object.get(f, "source", {}), "tool", "")))

finding_fingerprint(f) := fp if {
  fp := trim_space(object.get(object.get(object.get(f, "context", {}), "deduplication", {}), "fingerprint", ""))
  fp != ""
}

finding_fingerprint(f) := fp if {
  trim_space(object.get(object.get(object.get(f, "context", {}), "deduplication", {}), "fingerprint", "")) == ""
  fp := trim_space(object.get(f, "fingerprint", ""))
  fp != ""
}

finding_fingerprint(f) := "" if {
  trim_space(object.get(object.get(object.get(f, "context", {}), "deduplication", {}), "fingerprint", "")) == ""
  trim_space(object.get(f, "fingerprint", "")) == ""
}

finding_resource_id(f) := rid if {
  rid := trim_space(object.get(object.get(f, "resource", {}), "name", ""))
  rid != ""
}

finding_resource_id(f) := rid if {
  trim_space(object.get(object.get(f, "resource", {}), "name", "")) == ""
  rid := normalize_path(object.get(object.get(f, "resource", {}), "path", ""))
  rid != ""
}

finding_resource_id(f) := rid if {
  trim_space(object.get(object.get(f, "resource", {}), "name", "")) == ""
  normalize_path(object.get(object.get(f, "resource", {}), "path", "")) == ""
  rid := normalize_path(object.get(object.get(object.get(f, "resource", {}), "location", {}), "file", ""))
  rid != ""
}

finding_resource_id(f) := "" if {
  trim_space(object.get(object.get(f, "resource", {}), "name", "")) == ""
  normalize_path(object.get(object.get(f, "resource", {}), "path", "")) == ""
  normalize_path(object.get(object.get(object.get(f, "resource", {}), "location", {}), "file", "")) == ""
}

finding_severity_level(f) := upper(trim_space(object.get(object.get(f, "severity", {}), "level", "LOW")))

is_v2_exception(ex) if {
  trim_space(object.get(ex, "exception_id", "")) != ""
}

exception_id(ex) := eid if {
  eid := trim_space(object.get(ex, "exception_id", ""))
  eid != ""
}

exception_id(ex) := eid if {
  eid := trim_space(object.get(ex, "id", ""))
  eid != ""
}

exception_id(ex) := "unknown" if {
  trim_space(object.get(ex, "exception_id", "")) == ""
  trim_space(object.get(ex, "id", "")) == ""
}

exception_tool(ex) := lower(trim_space(object.get(ex, "scanner", object.get(ex, "tool", ""))))
exception_rule(ex) := upper(trim_space(object.get(ex, "rule_id", "")))
exception_scope_type(ex) := lower(trim_space(object.get(ex, "scope_type", "repo")))
exception_repo(ex) := lower(trim_space(object.get(ex, "repo", input_repo)))
exception_branch_scope(ex) := lower(trim_space(object.get(ex, "branch_scope", "*")))
exception_commit_scope(ex) := lower(trim_space(object.get(ex, "commit_sha", object.get(ex, "commit_hash", ""))))
exception_status(ex) := upper(trim_space(object.get(ex, "status", "")))
exception_requested_by(ex) := lower(trim_space(object.get(ex, "requested_by", "")))
exception_approved_by(ex) := lower(trim_space(object.get(ex, "approved_by", "")))
exception_approved_by_role(ex) := upper(trim_space(object.get(ex, "approved_by_role", "")))
exception_expires_at(ex) := trim_space(object.get(ex, "expires_at", ""))
exception_created_at(ex) := trim_space(object.get(ex, "created_at", object.get(ex, "request_date", "")))
exception_approved_at(ex) := trim_space(object.get(ex, "approved_at", ""))
exception_justification(ex) := trim_space(object.get(ex, "justification", object.get(ex, "reason", "")))
exception_max_severity(ex) := upper(trim_space(object.get(ex, "severity", object.get(ex, "max_severity", "LOW"))))
exception_break_glass(ex) := to_bool(object.get(ex, "break_glass", false))
exception_incident_id(ex) := trim_space(object.get(ex, "incident_id", ""))
exception_resource_id(ex) := rid if {
  rid := trim_space(object.get(ex, "resource_id", ""))
  rid != ""
}

exception_resource_id(ex) := rid if {
  trim_space(object.get(ex, "resource_id", "")) == ""
  rid := trim_space(object.get(ex, "resource_name", ""))
  rid != ""
}

exception_resource_id(ex) := rid if {
  trim_space(object.get(ex, "resource_id", "")) == ""
  trim_space(object.get(ex, "resource_name", "")) == ""
  rid := normalize_path(object.get(ex, "resource_path", ""))
  rid != ""
}

exception_resource_id(ex) := "" if {
  trim_space(object.get(ex, "resource_id", "")) == ""
  trim_space(object.get(ex, "resource_name", "")) == ""
  normalize_path(object.get(ex, "resource_path", "")) == ""
}

exception_fingerprint(ex) := fp if {
  fp := lower(trim_space(object.get(ex, "fingerprint", "")))
  fp != ""
}

exception_fingerprint(ex) := fp if {
  lower(trim_space(object.get(ex, "fingerprint", ""))) == ""
  fp := lower(trim_space(object.get(ex, "resource_hash", "")))
  fp != ""
}

exception_fingerprint(ex) := "" if {
  lower(trim_space(object.get(ex, "fingerprint", ""))) == ""
  lower(trim_space(object.get(ex, "resource_hash", ""))) == ""
}

exception_env_match(ex) if {
  envs := object.get(ex, "environments", null)
  envs == null
}

exception_env_match(ex) if {
  envs := object.get(ex, "environments", [])
  type_name(envs) == "array"
  count(envs) == 0
}

exception_env_match(ex) if {
  envs := object.get(ex, "environments", [])
  type_name(envs) == "array"
  some env in envs
  lower(trim_space(env)) == environment
}

exception_has_expires_at(ex) if {
  exception_expires_at(ex) != ""
}

exception_not_expired(ex) if {
  not exception_has_expires_at(ex)
}

exception_not_expired(ex) if {
  exception_has_expires_at(ex)
  expires_ns := time.parse_rfc3339_ns(exception_expires_at(ex))
  time.now_ns() <= expires_ns
}

exception_is_expired(ex) if {
  exception_has_expires_at(ex)
  expires_ns := time.parse_rfc3339_ns(exception_expires_at(ex))
  time.now_ns() > expires_ns
}

exception_severity_allowed(ex, f) if {
  max_sev := exception_max_severity(ex)
  finding_sev := finding_severity_level(f)
  severity_rank[max_sev] >= 1
  severity_rank[finding_sev] <= severity_rank[max_sev]
}

exception_is_enabled(ex) if {
  to_bool(object.get(ex, "enabled", false))
}

# ----------------------------- Legacy validations -----------------------------

valid_rule_aliases(ex) if {
  aliases := object.get(ex, "rule_id_aliases", null)
  aliases == null
}

alias_valid(alias) if {
  type_name(alias) == "string"
  trim_space(alias) != ""
}

valid_rule_aliases(ex) if {
  aliases := object.get(ex, "rule_id_aliases", null)
  type_name(aliases) == "array"
  count([alias |
    alias := aliases[_]
    not alias_valid(alias)
  ]) == 0
}

legacy_has_resource_selector(ex) if {
  trim_space(object.get(ex, "resource_path", "")) != ""
}

legacy_has_resource_selector(ex) if {
  trim_space(object.get(ex, "resource_name", "")) != ""
}

legacy_required_fields(ex) if {
  trim_space(object.get(ex, "id", "")) != ""
  trim_space(object.get(ex, "tool", "")) != ""
  trim_space(object.get(ex, "rule_id", "")) != ""
  legacy_has_resource_selector(ex)
  count(object.get(ex, "environments", [])) > 0
  trim_space(object.get(ex, "max_severity", "")) != ""
  trim_space(object.get(ex, "requested_by", "")) != ""
  trim_space(object.get(ex, "approved_by", "")) != ""
  trim_space(object.get(ex, "commit_hash", "")) != ""
  trim_space(object.get(ex, "request_date", "")) != ""
  trim_space(object.get(ex, "expires_at", "")) != ""
}

legacy_valid_definition(ex) if {
  legacy_mode_allowed
  legacy_required_fields(ex)
  valid_rule_aliases(ex)
  allowed_tools[exception_tool(ex)]
  exception_max_severity(ex) != ""
  severity_rank[exception_max_severity(ex)] >= 1
  exception_requested_by(ex) != ""
  exception_approved_by(ex) != ""
  exception_requested_by(ex) != exception_approved_by(ex)
  regex.match("^[a-fA-F0-9]{7,40}$", trim_space(object.get(ex, "commit_hash", "")))
  request_ns := time.parse_rfc3339_ns(trim_space(object.get(ex, "request_date", "")))
  expires_ns := time.parse_rfc3339_ns(exception_expires_at(ex))
  request_ns <= time.now_ns()
  request_ns < expires_ns
  envs := object.get(ex, "environments", [])
  count([env |
    env := lower(envs[_])
    not allowed_envs[env]
  ]) == 0
}

# ------------------------------- V2 validations -------------------------------

valid_scope_type(ex) if {
  allowed_scope_types[exception_scope_type(ex)]
}

valid_approved_role(ex) if {
  allowed_roles[exception_approved_by_role(ex)]
}

valid_scope_permissions(ex) if {
  exception_scope_type(ex) != "global"
}

valid_scope_permissions(ex) if {
  exception_scope_type(ex) == "global"
  global_scope_roles[exception_approved_by_role(ex)]
}

valid_commit_scope(ex) if {
  exception_scope_type(ex) != "commit"
}

valid_commit_scope(ex) if {
  exception_scope_type(ex) == "commit"
  regex.match("^[a-fA-F0-9]{7,40}$", exception_commit_scope(ex))
}

valid_break_glass(ex) if {
  not exception_break_glass(ex)
}

valid_break_glass(ex) if {
  exception_break_glass(ex)
  exception_incident_id(ex) != ""
  role_rank[exception_approved_by_role(ex)] >= role_rank["APPSEC_L3"]
  created_ns := time.parse_rfc3339_ns(exception_created_at(ex))
  expires_ns := time.parse_rfc3339_ns(exception_expires_at(ex))
  (expires_ns - created_ns) <= (7 * ns_per_day)
}

valid_optional_expiry(ex) if {
  not exception_has_expires_at(ex)
}

valid_optional_expiry(ex) if {
  exception_has_expires_at(ex)
  created_ns := time.parse_rfc3339_ns(exception_created_at(ex))
  expires_ns := time.parse_rfc3339_ns(exception_expires_at(ex))
  created_ns < expires_ns
}

v2_required_fields(ex) if {
  valid_uuid(exception_id(ex))
  trim_space(object.get(ex, "schema_version", "")) != ""
  exception_status(ex) == "APPROVED"
  allowed_tools[exception_tool(ex)]
  exception_rule(ex) != ""
  exception_resource_id(ex) != ""
  exception_fingerprint(ex) != ""
  exception_repo(ex) != ""
  exception_branch_scope(ex) != ""
  valid_scope_type(ex)
  exception_max_severity(ex) != ""
  severity_rank[exception_max_severity(ex)] >= 1
  exception_requested_by(ex) != ""
  exception_approved_by(ex) != ""
  exception_requested_by(ex) != exception_approved_by(ex)
  valid_approved_role(ex)
  exception_justification(ex) != ""
  exception_created_at(ex) != ""
  exception_approved_at(ex) != ""
  created_ns := time.parse_rfc3339_ns(exception_created_at(ex))
  created_ns <= time.now_ns()
  approved_ns := time.parse_rfc3339_ns(exception_approved_at(ex))
  approved_ns >= created_ns
  valid_optional_expiry(ex)
  valid_scope_permissions(ex)
  valid_commit_scope(ex)
  valid_break_glass(ex)
}

valid_exception_definition(ex) if {
  is_v2_exception(ex)
  v2_required_fields(ex)
}

# ------------------------------- Match engine ---------------------------------

exception_rule_match(ex, f) if {
  exception_rule(ex) == finding_rule_id(f)
}

exception_rule_match(ex, f) if {
  aliases := object.get(ex, "rule_id_aliases", [])
  type_name(aliases) == "array"
  some alias in aliases
  upper(trim_space(alias)) == finding_rule_id(f)
}

scope_match(ex) if {
  exception_scope_type(ex) == "global"
}

scope_match(ex) if {
  exception_scope_type(ex) == "repo"
  exception_repo(ex) == input_repo
}

scope_match(ex) if {
  exception_scope_type(ex) == "branch"
  exception_repo(ex) == input_repo
  exception_branch_scope(ex) == "*"
}

scope_match(ex) if {
  exception_scope_type(ex) == "branch"
  exception_repo(ex) == input_repo
  exception_branch_scope(ex) == input_branch
}

scope_match(ex) if {
  exception_scope_type(ex) == "commit"
  exception_repo(ex) == input_repo
  c := exception_commit_scope(ex)
  c != ""
  input_commit != ""
  startswith(input_commit, c)
}

fingerprint_exact_match(ex, f) if {
  exception_fingerprint(ex) != ""
  fp := lower(trim_space(finding_fingerprint(f)))
  fp != ""
  fp == exception_fingerprint(ex)
}

resource_rule_repo_match(ex, f) if {
  rid := lower(trim_space(exception_resource_id(ex)))
  frid := lower(trim_space(finding_resource_id(f)))
  rid != ""
  frid != ""
  rid == frid
  exception_repo(ex) == input_repo
}

legacy_path_match(ex, f) if {
  sp := normalize_path(object.get(ex, "resource_path", ""))
  fp := normalize_path(object.get(object.get(f, "resource", {}), "path", ""))
  sp != ""
  fp != ""
  sp == fp
}

legacy_path_match(ex, f) if {
  sp := normalize_path(object.get(ex, "resource_path", ""))
  fp := normalize_path(object.get(object.get(f, "resource", {}), "path", ""))
  sp != ""
  fp != ""
  endswith(fp, sprintf("/%s", [sp]))
}

legacy_resource_selector_match(ex, f) if {
  selector_name := trim_space(object.get(ex, "resource_name", ""))
  selector_name != ""
  selector_name == trim_space(object.get(object.get(f, "resource", {}), "name", ""))
}

legacy_resource_selector_match(ex, f) if {
  legacy_path_match(ex, f)
}

exception_match_method(ex, f) := "fingerprint_exact" if {
  is_v2_exception(ex)
  fingerprint_exact_match(ex, f)
}

exception_match_method(ex, f) := "resource_rule_repo" if {
  is_v2_exception(ex)
  not fingerprint_exact_match(ex, f)
  resource_rule_repo_match(ex, f)
}

exception_match_method(ex, f) := "scope_controlled" if {
  is_v2_exception(ex)
  not fingerprint_exact_match(ex, f)
  not resource_rule_repo_match(ex, f)
  scope_match(ex)
}

exception_match_method(ex, f) := "legacy_resource_selector" if {
  not is_v2_exception(ex)
  legacy_resource_selector_match(ex, f)
}

exception_matches_finding(ex, f) if {
  exception_is_enabled(ex)
  valid_exception_definition(ex)
  exception_not_expired(ex)
  exception_env_match(ex)
  exception_tool(ex) == finding_tool(f)
  exception_rule_match(ex, f)
  exception_severity_allowed(ex, f)
  exception_match_method(ex, f)
}

# Active exception index (pre-filtered once, then reused by matching paths).
active_valid_enabled_exceptions := [ex |
  ex := exceptions_store[_]
  exception_is_enabled(ex)
  valid_exception_definition(ex)
  exception_not_expired(ex)
  exception_env_match(ex)
]

candidate_exceptions_for_finding(f) := [ex |
  ex := active_valid_enabled_exceptions[_]
  exception_tool(ex) == finding_tool(f)
]

legacy_exception_after_sunset[ex_id] if {
  ex := exceptions_store[_]
  exception_is_enabled(ex)
  not is_v2_exception(ex)
  ex_id := exception_id(ex)
}

invalid_enabled_exception_ids[ex_id] if {
  ex := exceptions_store[_]
  exception_is_enabled(ex)
  not valid_exception_definition(ex)
  ex_id := exception_id(ex)
}

expired_enabled_exception_ids[ex_id] if {
  ex := exceptions_store[_]
  exception_is_enabled(ex)
  valid_exception_definition(ex)
  exception_is_expired(ex)
  ex_id := exception_id(ex)
}

exception_status_not_approved_ids[ex_id] if {
  ex := exceptions_store[_]
  exception_is_enabled(ex)
  is_v2_exception(ex)
  exception_status(ex) != "APPROVED"
  ex_id := exception_id(ex)
}

exception_missing_approved_by_ids[ex_id] if {
  ex := exceptions_store[_]
  exception_is_enabled(ex)
  is_v2_exception(ex)
  exception_approved_by(ex) == ""
  ex_id := exception_id(ex)
}

exception_missing_approved_at_ids[ex_id] if {
  ex := exceptions_store[_]
  exception_is_enabled(ex)
  is_v2_exception(ex)
  exception_approved_at(ex) == ""
  ex_id := exception_id(ex)
}

prod_critical_exception_violation[ex_id] if {
  environment == "prod"
  ex := exceptions_store[_]
  exception_is_enabled(ex)
  valid_exception_definition(ex)
  exception_env_match(ex)
  exception_max_severity(ex) == "CRITICAL"
  ex_id := exception_id(ex)
}

applied_exception_ids[ex_id] if {
  f := failed_findings[_]
  ex := candidate_exceptions_for_finding(f)[_]
  exception_matches_finding(ex, f)
  ex_id := exception_id(ex)
}

applied_exception_audit[item] if {
  f := failed_findings[_]
  ex := candidate_exceptions_for_finding(f)[_]
  exception_matches_finding(ex, f)
  item := {
    "exception_id": exception_id(ex),
    "scope_type": exception_scope_type(ex),
    "commit_sha": input_commit,
    "rule_id": exception_rule(ex),
    "matching_method": exception_match_method(ex, f),
    "break_glass": exception_break_glass(ex),
  }
}

is_excepted_finding(f) if {
  ex := candidate_exceptions_for_finding(f)[_]
  exception_matches_finding(ex, f)
}

effective_failed_findings := [f |
  f := failed_findings[_]
  not is_excepted_finding(f)
]

excepted_failed_findings := [f |
  f := failed_findings[_]
  is_excepted_finding(f)
]

effective_critical := count([f |
  f := effective_failed_findings[_]
  finding_severity_level(f) == "CRITICAL"
])

effective_high := count([f |
  f := effective_failed_findings[_]
  finding_severity_level(f) == "HIGH"
])

effective_medium := count([f |
  f := effective_failed_findings[_]
  finding_severity_level(f) == "MEDIUM"
])

effective_low := count([f |
  f := effective_failed_findings[_]
  finding_severity_level(f) == "LOW"
])

effective_info := count([f |
  f := effective_failed_findings[_]
  finding_severity_level(f) == "INFO"
])

active_exceptions := [ex |
  ex := active_valid_enabled_exceptions[_]
]

active_exceptions_critical := count([ex |
  ex := active_exceptions[_]
  exception_max_severity(ex) == "CRITICAL"
])

active_exceptions_high := count([ex |
  ex := active_exceptions[_]
  exception_max_severity(ex) == "HIGH"
])

active_exceptions_medium := count([ex |
  ex := active_exceptions[_]
  exception_max_severity(ex) == "MEDIUM"
])

active_exceptions_low := count([ex |
  ex := active_exceptions[_]
  exception_max_severity(ex) == "LOW"
])

active_exceptions_info := count([ex |
  ex := active_exceptions[_]
  exception_max_severity(ex) == "INFO"
])

active_break_glass_count := count([ex |
  ex := active_exceptions[_]
  exception_break_glass(ex)
])

approval_duration_hours(ex) := hours if {
  approved := exception_approved_at(ex)
  approved != ""
  created := exception_created_at(ex)
  created != ""
  approved_ns := time.parse_rfc3339_ns(approved)
  created_ns := time.parse_rfc3339_ns(created)
  approved_ns >= created_ns
  hours := (approved_ns - created_ns) / 3600000000000
}

approval_duration_values := [h |
  ex := active_exceptions[_]
  h := approval_duration_hours(ex)
]

avg_approval_time_hours := 0 if {
  count(approval_duration_values) == 0
}

avg_approval_time_hours := sum(approval_duration_values) / count(approval_duration_values) if {
  count(approval_duration_values) > 0
}

scanner_not_run[name] if {
  not is_local
  name := required_scanners[_]
  scanner := object.get(scanners, name, {})
  object.get(scanner, "status", "NOT_RUN") == "NOT_RUN"
}

deny[msg] if {
  scanner_not_run[name]
  msg := sprintf("Scanner %s did not run or report is invalid", [name])
}

deny[msg] if {
  not thresholds_valid
  msg := "Invalid threshold configuration: critical_max/high_max must be numeric"
}

deny[msg] if {
  effective_critical > critical_max
  msg := sprintf("CRITICAL findings (%d) exceed threshold (%d)", [effective_critical, critical_max])
}

deny[msg] if {
  effective_high > high_max
  msg := sprintf("HIGH findings (%d) exceed threshold (%d)", [effective_high, high_max])
}

deny[msg] if {
  prod_critical_exception_violation[ex_id]
  msg := sprintf("Exception %s is invalid for prod: max_severity CRITICAL is forbidden", [ex_id])
}

deny[msg] if {
  invalid_enabled_exception_ids[ex_id]
  msg := sprintf("Exception %s is malformed: required audit/scope fields are invalid", [ex_id])
}

deny[msg] if {
  exception_status_not_approved_ids[ex_id]
  msg := sprintf("Exception %s is invalid: status must be APPROVED", [ex_id])
}

deny[msg] if {
  exception_missing_approved_by_ids[ex_id]
  msg := sprintf("Exception %s is invalid: approved_by is required", [ex_id])
}

deny[msg] if {
  exception_missing_approved_at_ids[ex_id]
  msg := sprintf("Exception %s is invalid: approved_at is required (RFC3339)", [ex_id])
}

deny[msg] if {
  expired_enabled_exception_ids[ex_id]
  msg := sprintf("Exception %s is invalid: expires_at is in the past", [ex_id])
}

deny[msg] if {
  legacy_exception_after_sunset[ex_id]
  msg := sprintf("Exception %s uses legacy schema which is no longer accepted", [ex_id])
}

default allow := false

allow if {
  count(deny) == 0
}

deny_reasons := sort([msg | deny[msg]])

decision := {
  "allow": allow,
  "deny": deny_reasons,
  "metrics": {
    "critical": effective_critical,
    "high": effective_high,
    "medium": effective_medium,
    "low": effective_low,
    "info": effective_info,
    "failed": count(effective_failed_findings),
    "failed_input": count(failed_findings),
    "failed_effective": count(effective_failed_findings),
    "excepted": count(excepted_failed_findings),
    "excepted_findings": count(excepted_failed_findings),
    "excepted_exception_ids": count(applied_exception_ids),
    "governance": {
      "active_exceptions_by_severity": {
        "CRITICAL": active_exceptions_critical,
        "HIGH": active_exceptions_high,
        "MEDIUM": active_exceptions_medium,
        "LOW": active_exceptions_low,
        "INFO": active_exceptions_info
      },
      "active_break_glass": active_break_glass_count,
      "expired_enabled_exceptions": count(expired_enabled_exception_ids),
      "avg_approval_time_hours": avg_approval_time_hours
    }
  },
  "thresholds": {
    "critical_max": critical_max_raw,
    "high_max": high_max_raw
  },
  "environment": environment,
  "execution_mode": execution_mode,
  "exceptions": {
    "applied_ids": sort([id | applied_exception_ids[id]]),
    "applied_count": count(applied_exception_ids),
    "applied_audit": [item | applied_exception_audit[item]],
    "strict_prod_violations": sort([id | prod_critical_exception_violation[id]]),
    "invalid_enabled_ids": sort([id | invalid_enabled_exception_ids[id]]),
    "expired_enabled_ids": sort([id | expired_enabled_exception_ids[id]]),
    "legacy_after_sunset_ids": sort([id | legacy_exception_after_sunset[id]])
  }
}
