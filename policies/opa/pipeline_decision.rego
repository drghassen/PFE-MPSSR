package cloudsentinel.gate

import rego.v1

scanners := object.get(input, "scanners", {})
thresholds := object.get(object.get(input, "quality_gate", {}), "thresholds", {})
required_scanners := ["gitleaks", "checkov", "trivy"]
allowed_tools := {"gitleaks", "checkov", "trivy"}
environment := lower(object.get(object.get(input, "metadata", {}), "environment", "dev"))

default exceptions_store := []

exceptions_store := data.cloudsentinel.exceptions.exceptions

critical_max_raw := object.get(thresholds, "critical_max", 0)
high_max_raw := object.get(thresholds, "high_max", 2)

critical_max := to_non_negative_integer(critical_max_raw, 0)
high_max := to_non_negative_integer(high_max_raw, 2)

severity_rank := {
  "INFO": 1,
  "LOW": 2,
  "MEDIUM": 3,
  "HIGH": 4,
  "CRITICAL": 5
}

is_non_negative_integer_value(v) if {
  is_number(v)
  v >= 0
  floor(v) == v
}

is_non_negative_integer_value(v) if {
  is_string(v)
  s := trim_space(v)
  regex.match("^[0-9]+$", s)
}

to_non_negative_integer(v, _) := out if {
  is_number(v)
  v >= 0
  floor(v) == v
  out := v
}

to_non_negative_integer(v, _) := out if {
  is_string(v)
  s := trim_space(v)
  regex.match("^[0-9]+$", s)
  out := to_number(s)
}

to_non_negative_integer(v, fallback) := fallback if {
  not is_non_negative_integer_value(v)
}

failed_findings := [f |
  some i
  f := object.get(input, "findings", [])[i]
  object.get(f, "status", "") == "FAILED"
]

canonical_path(path) := out if {
  p0 := trim_space(sprintf("%v", [path]))
  p1 := replace(p0, "\\", "/")
  p2 := replace(p1, "/./", "/")
  p3 := replace(p2, "//", "/")
  p4 := replace(p3, "//", "/")
  p5 := trim_prefix(p4, "./")
  out := p5
}

path_segments(path) := segs if {
  c := canonical_path(path)
  segs := [seg |
    seg := split(c, "/")[_]
    seg != ""
  ]
}

suffix_segments_match(expected, actual) if {
  n := count(expected)
  n > 0
  n <= count(actual)
  offset := count(actual) - n
  count([1 |
    i := numbers.range(0, n - 1)[_]
    actual[offset+i] == expected[i]
  ]) == n
}

finding_rule_id(f) := upper(trim_space(sprintf("%v", [object.get(object.get(f, "source", {}), "id", "")])))

exception_rule_match(ex, f) if {
  upper(trim_space(sprintf("%v", [object.get(ex, "rule_id", "")]))) == finding_rule_id(f)
}

exception_rule_match(ex, f) if {
  aliases := object.get(ex, "rule_id_aliases", [])
  type_name(aliases) == "array"
  target_rule := finding_rule_id(f)
  some alias in aliases
  upper(trim_space(alias)) == target_rule
}

has_required_exception_fields(ex) if {
  object.get(ex, "id", "") != ""
  object.get(ex, "tool", "") != ""
  object.get(ex, "rule_id", "") != ""
  object.get(ex, "resource_path", "") != ""
  count(object.get(ex, "environments", [])) > 0
  object.get(ex, "max_severity", "") != ""
  object.get(ex, "reason", "") != ""
  object.get(ex, "ticket", "") != ""
  object.get(ex, "requested_by", "") != ""
  object.get(ex, "approved_by", "") != ""
  object.get(ex, "commit_hash", "") != ""
  object.get(ex, "request_date", "") != ""
  object.get(ex, "expires_at", "") != ""
}

valid_email(email) if {
  regex.match("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", lower(email))
}

valid_exception_tool(ex) if {
  tool := lower(object.get(ex, "tool", ""))
  allowed_tools[tool]
}

valid_exception_env_values(ex) if {
  envs := object.get(ex, "environments", [])
  count([env |
    env := lower(envs[_])
    env != "dev"
    env != "test"
    env != "staging"
    env != "prod"
  ]) == 0
}

valid_exception_max_severity(ex) if {
  max_sev := upper(object.get(ex, "max_severity", ""))
  severity_rank[max_sev] >= 1
}

valid_exception_primary_rule_id(ex) if {
  rule_id := object.get(ex, "rule_id", "")
  type_name(rule_id) == "string"
  trim_space(rule_id) != ""
}

valid_exception_resource_path(ex) if {
  path_raw := object.get(ex, "resource_path", "")
  type_name(path_raw) == "string"
  path := canonical_path(object.get(ex, "resource_path", ""))
  path != ""
  path != "."
  not contains(path, "*")
  not startswith(path, "../")
  not contains(path, "/../")
}

valid_exception_rule_aliases(ex) if {
  aliases := object.get(ex, "rule_id_aliases", [])
  type_name(aliases) == "array"
  count([1 |
    alias := aliases[_]
    type_name(alias) == "string"
    trim_space(alias) != ""
  ]) == count(aliases)
}

valid_exception_commit_hash(ex) if {
  commit_hash := object.get(ex, "commit_hash", "")
  regex.match("^[a-fA-F0-9]{7,40}$", commit_hash)
}

valid_exception_dates(ex) if {
  request_date := object.get(ex, "request_date", "")
  expires_at := object.get(ex, "expires_at", "")
  request_ns := time.parse_rfc3339_ns(request_date)
  expires_ns := time.parse_rfc3339_ns(expires_at)
  request_ns <= time.now_ns()
  request_ns < expires_ns
}

valid_exception_approvals(ex) if {
  requested_by := lower(object.get(ex, "requested_by", ""))
  approved_by := lower(object.get(ex, "approved_by", ""))
  valid_email(requested_by)
  valid_email(approved_by)
  requested_by != approved_by
}

valid_exception_definition(ex) if {
  has_required_exception_fields(ex)
  valid_exception_tool(ex)
  valid_exception_primary_rule_id(ex)
  valid_exception_env_values(ex)
  valid_exception_max_severity(ex)
  valid_exception_resource_path(ex)
  valid_exception_rule_aliases(ex)
  valid_exception_commit_hash(ex)
  valid_exception_dates(ex)
  valid_exception_approvals(ex)
}

exception_env_match(ex) if {
  envs := object.get(ex, "environments", [])
  some i
  lower(envs[i]) == environment
}

exception_not_expired(ex) if {
  exp := object.get(ex, "expires_at", "")
  exp_ns := time.parse_rfc3339_ns(exp)
  time.now_ns() < exp_ns
}

resource_path_match(expected, actual) if {
  canonical_path(expected) == canonical_path(actual)
}

resource_path_match(expected, actual) if {
  suffix_segments_match(path_segments(expected), path_segments(actual))
}

exception_severity_allowed(ex, f) if {
  max_sev := upper(object.get(ex, "max_severity", "LOW"))
  finding_sev := upper(object.get(object.get(f, "severity", {}), "level", "LOW"))
  severity_rank[finding_sev] <= severity_rank[max_sev]
}

exception_matches_finding(ex, f) if {
  lower(object.get(ex, "tool", "")) == lower(object.get(object.get(f, "source", {}), "tool", ""))
  exception_rule_match(ex, f)
  resource_path_match(object.get(ex, "resource_path", ""), object.get(object.get(f, "resource", {}), "path", ""))
  exception_env_match(ex)
  exception_not_expired(ex)
  exception_severity_allowed(ex, f)
  valid_exception_definition(ex)
  object.get(ex, "enabled", false)
}

invalid_enabled_exception_ids[ex_id] if {
  ex := exceptions_store[_]
  object.get(ex, "enabled", false)
  not valid_exception_definition(ex)
  ex_id := object.get(ex, "id", "unknown")
}

prod_critical_exception_violation[ex_id] if {
  environment == "prod"
  ex := exceptions_store[_]
  upper(object.get(ex, "max_severity", "LOW")) == "CRITICAL"
  object.get(ex, "enabled", false)
  exception_env_match(ex)
  ex_id := object.get(ex, "id", "unknown")
}

applied_exception_ids[ex_id] if {
  f := failed_findings[_]
  ex := exceptions_store[_]
  exception_matches_finding(ex, f)
  ex_id := object.get(ex, "id", "unknown")
}

is_excepted_finding(f) if {
  ex := exceptions_store[_]
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
  upper(object.get(object.get(f, "severity", {}), "level", "LOW")) == "CRITICAL"
])

effective_high := count([f |
  f := effective_failed_findings[_]
  upper(object.get(object.get(f, "severity", {}), "level", "LOW")) == "HIGH"
])

effective_medium := count([f |
  f := effective_failed_findings[_]
  upper(object.get(object.get(f, "severity", {}), "level", "LOW")) == "MEDIUM"
])

effective_low := count([f |
  f := effective_failed_findings[_]
  upper(object.get(object.get(f, "severity", {}), "level", "LOW")) == "LOW"
])

effective_info := count([f |
  f := effective_failed_findings[_]
  upper(object.get(object.get(f, "severity", {}), "level", "LOW")) == "INFO"
])

invalid_threshold_keys["critical_max"] if {
  not is_non_negative_integer_value(critical_max_raw)
}

invalid_threshold_keys["high_max"] if {
  not is_non_negative_integer_value(high_max_raw)
}

scanner_not_run[name] if {
  name := required_scanners[_]
  scanner := object.get(scanners, name, {})
  object.get(scanner, "status", "NOT_RUN") == "NOT_RUN"
}

deny[msg] if {
  scanner_not_run[name]
  msg := sprintf("Scanner %s did not run or report is invalid", [name])
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
  invalid_threshold_keys[key]
  msg := sprintf("Invalid threshold configuration for %s: non-negative integer required", [key])
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
    "excepted_exception_ids": count(applied_exception_ids)
  },
  "thresholds": {
    "critical_max": critical_max,
    "high_max": high_max
  },
  "environment": environment,
  "exceptions": {
    "applied_ids": sort([id | applied_exception_ids[id]]),
    "applied_count": count(applied_exception_ids),
    "strict_prod_violations": sort([id | prod_critical_exception_violation[id]]),
    "invalid_enabled_ids": sort([id | invalid_enabled_exception_ids[id]])
  }
}
