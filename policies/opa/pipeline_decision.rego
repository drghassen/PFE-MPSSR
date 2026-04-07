package cloudsentinel.gate

import rego.v1

# rego 0.69.1

scanners := object.get(input, "scanners", {})
thresholds := object.get(object.get(input, "quality_gate", {}), "thresholds", {})
required_scanners := ["gitleaks", "checkov", "trivy"]
allowed_tools := {"gitleaks", "checkov", "trivy"}
allowed_decisions := {"accept", "mitigate", "fix", "transfer", "avoid"}

metadata := object.get(input, "metadata", {})
git_meta := object.get(metadata, "git", {})
environment := lower(object.get(metadata, "environment", "dev"))
execution_mode := lower(object.get(object.get(metadata, "execution", {}), "mode", "ci"))

critical_max_raw := object.get(thresholds, "critical_max", 0)
high_max_raw := object.get(thresholds, "high_max", 2)

critical_max := to_number(critical_max_raw)
high_max := to_number(high_max_raw)

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

finding_rule_id(f) := upper(trim_space(object.get(object.get(f, "source", {}), "id", "")))
finding_tool(f) := lower(trim_space(object.get(object.get(f, "source", {}), "tool", "")))

finding_resource_id(f) := rid if {
  rid := normalize_path(object.get(object.get(f, "resource", {}), "name", ""))
  rid != ""
}

finding_resource_id(f) := rid if {
  normalize_path(object.get(object.get(f, "resource", {}), "name", "")) == ""
  rid := normalize_path(object.get(object.get(f, "resource", {}), "path", ""))
  rid != ""
}

finding_resource_id(f) := rid if {
  normalize_path(object.get(object.get(f, "resource", {}), "name", "")) == ""
  normalize_path(object.get(object.get(f, "resource", {}), "path", "")) == ""
  rid := normalize_path(object.get(object.get(object.get(f, "resource", {}), "location", {}), "file", ""))
  rid != ""
}

finding_resource_id(f) := "" if {
  normalize_path(object.get(object.get(f, "resource", {}), "name", "")) == ""
  normalize_path(object.get(object.get(f, "resource", {}), "path", "")) == ""
  normalize_path(object.get(object.get(object.get(f, "resource", {}), "location", {}), "file", "")) == ""
}

finding_severity_level(f) := upper(trim_space(object.get(object.get(f, "severity", {}), "level", "LOW")))

exception_id(ex) := lower(trim_space(object.get(ex, "id", "")))
exception_tool(ex) := lower(trim_space(object.get(ex, "tool", "")))
exception_rule(ex) := upper(trim_space(object.get(ex, "rule_id", "")))
exception_resource(ex) := lower(normalize_path(object.get(ex, "resource", "")))
exception_severity(ex) := upper(trim_space(object.get(ex, "severity", "")))
exception_requested_by(ex) := lower(trim_space(object.get(ex, "requested_by", "")))
exception_approved_by(ex) := lower(trim_space(object.get(ex, "approved_by", "")))
exception_status(ex) := lower(trim_space(object.get(ex, "status", "")))
exception_source(ex) := lower(trim_space(object.get(ex, "source", "")))
exception_decision(ex) := lower(trim_space(object.get(ex, "decision", "")))
exception_approved_at(ex) := trim_space(object.get(ex, "approved_at", ""))
exception_expires_at(ex) := trim_space(object.get(ex, "expires_at", ""))

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

valid_exception_definition(ex) if {
  exception_id(ex) != ""
  regex.match("^[a-f0-9]{64}$", exception_id(ex))
  allowed_tools[exception_tool(ex)]
  exception_rule(ex) != ""
  exception_resource(ex) != ""
  not exception_has_wildcard(ex)
  severity_rank[exception_severity(ex)] >= 1
  exception_requested_by(ex) != ""
  exception_approved_by(ex) != ""
  exception_requested_by(ex) != exception_approved_by(ex)
  allowed_decisions[exception_decision(ex)]
  exception_source(ex) == "defectdojo"
  exception_status(ex) == "approved"
  exception_timestamp_fields_parse(ex)
  approved_ns := time.parse_rfc3339_ns(exception_approved_at(ex))
  expires_ns := time.parse_rfc3339_ns(exception_expires_at(ex))
  approved_ns <= time.now_ns()
  approved_ns < expires_ns
  not exception_is_expired(ex)
}

exception_status_not_approved_ids[ex_id] if {
  ex := exceptions_store[_]
  exception_status(ex) != "approved"
  ex_id := exception_id(ex)
}

exception_missing_approved_by_ids[ex_id] if {
  ex := exceptions_store[_]
  exception_approved_by(ex) == ""
  ex_id := exception_id(ex)
}

exception_missing_approved_at_ids[ex_id] if {
  ex := exceptions_store[_]
  exception_approved_at(ex) == ""
  ex_id := exception_id(ex)
}

invalid_enabled_exception_ids[ex_id] if {
  ex := exceptions_store[_]
  ex_id := exception_id(ex)
  ex_id != ""
  not valid_exception_definition(ex)
  not exception_is_expired(ex)
}

expired_enabled_exception_ids[ex_id] if {
  ex := exceptions_store[_]
  ex_id := exception_id(ex)
  ex_id != ""
  exception_is_expired(ex)
}

legacy_exception_after_sunset[ex_id] if {
  ex_id := ""
  false
}

active_valid_enabled_exceptions := [ex |
  ex := exceptions_store[_]
  valid_exception_definition(ex)
]

candidate_exceptions_for_finding(f) := [ex |
  ex := active_valid_enabled_exceptions[_]
  exception_tool(ex) == finding_tool(f)
]

exception_matches_finding(ex, f) if {
  exception_tool(ex) == finding_tool(f)
  exception_rule(ex) == finding_rule_id(f)
  exception_resource(ex) == lower(trim_space(finding_resource_id(f)))
  exception_scope_matches_repo(ex)
  exception_scope_matches_env(ex)
  exception_scope_matches_branch(ex)
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
    "scope_type": "strict_tool_rule_resource",
    "commit_sha": trim_space(object.get(git_meta, "commit", "")),
    "rule_id": exception_rule(ex),
    "matching_method": "tool_rule_resource_exact",
    "break_glass": false,
  }
}

partial_mismatch_reasons(ex, f) := reasons if {
  reasons := [msg |
    conditions := [
      {"cond": exception_resource(ex) != lower(trim_space(finding_resource_id(f))), "msg": "Resource path mismatch"},
      {"cond": not exception_scope_matches_repo(ex), "msg": "Scope repo mismatch"},
      {"cond": not exception_scope_matches_env(ex), "msg": "Scope environment mismatch"},
      {"cond": not exception_scope_matches_branch(ex), "msg": "Scope branch mismatch"}
    ]
    c := conditions[_]
    c.cond == true
    msg := c.msg
  ]
}

partial_matches_audit[item] if {
  f := failed_findings[_]
  ex := active_valid_enabled_exceptions[_]
  exception_tool(ex) == finding_tool(f)
  exception_rule(ex) == finding_rule_id(f)
  not exception_matches_finding(ex, f)
  
  item := {
    "exception_id": exception_id(ex),
    "rule_id": exception_rule(ex),
    "mismatch_reasons": partial_mismatch_reasons(ex, f),
    "expected_exception_resource": exception_resource(ex),
    "actual_finding_resource": finding_resource_id(f)
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

active_exceptions := [ex |
  ex := active_valid_enabled_exceptions[_]
]

active_exceptions_critical := count([ex |
  ex := active_exceptions[_]
  exception_severity(ex) == "CRITICAL"
])

active_exceptions_high := count([ex |
  ex := active_exceptions[_]
  exception_severity(ex) == "HIGH"
])

active_exceptions_medium := count([ex |
  ex := active_exceptions[_]
  exception_severity(ex) == "MEDIUM"
])

active_exceptions_low := count([ex |
  ex := active_exceptions[_]
  exception_severity(ex) == "LOW"
])

avg_approval_time_hours := 0
active_break_glass_count := 0

prod_critical_exception_violation[ex_id] if {
  environment == "prod"
  ex := active_valid_enabled_exceptions[_]
  exception_severity(ex) == "CRITICAL"
  ex_id := exception_id(ex)
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
  msg := sprintf("Exception %s is invalid for prod: severity CRITICAL is forbidden", [ex_id])
}

deny[msg] if {
  invalid_enabled_exception_ids[ex_id]
  msg := sprintf("Exception %s is malformed: required governance fields are invalid", [ex_id])
}

deny[msg] if {
  exception_status_not_approved_ids[ex_id]
  msg := sprintf("Exception %s is invalid: status must be approved", [ex_id])
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
    "info": 0,
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
        "INFO": 0
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
    "partial_matches_audit": [item | partial_matches_audit[item]],
    "strict_prod_violations": sort([id | prod_critical_exception_violation[id]]),
    "invalid_enabled_ids": sort([id | invalid_enabled_exception_ids[id]]),
    "expired_enabled_ids": sort([id | expired_enabled_exception_ids[id]]),
    "legacy_after_sunset_ids": sort([id | legacy_exception_after_sunset[id]])
  }
}
