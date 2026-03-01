package cloudsentinel.gate
import rego.v1
#rego 0.69.1

scanners := object.get(input, "scanners", {})
thresholds := object.get(object.get(input, "quality_gate", {}), "thresholds", {})
required_scanners := ["gitleaks", "checkov", "trivy"]
allowed_tools := {"gitleaks", "checkov", "trivy"}
environment := lower(object.get(object.get(input, "metadata", {}), "environment", "dev"))
execution_mode := lower(object.get(object.get(object.get(input, "metadata", {}), "execution", {}), "mode", "ci"))

is_local if {
  execution_mode == "local"
}
is_local if {
  execution_mode == "advisory"
}

default exceptions_store := []
exceptions_store := data.cloudsentinel.exceptions.exceptions

critical_max_raw := object.get(thresholds, "critical_max", 0)
high_max_raw := object.get(thresholds, "high_max", 2)

# Ensure fallback if inputs are missing or invalid type
critical_max := to_number(critical_max_raw)
high_max := to_number(high_max_raw)

severity_rank := {
  "INFO": 1,
  "LOW": 2,
  "MEDIUM": 3,
  "HIGH": 4,
  "CRITICAL": 5
}

failed_findings := [f |
  some i
  f := object.get(input, "findings", [])[i]
  object.get(f, "status", "") == "FAILED"
]

# Strict Matching Methods (Data is pre-normalized by Python)
finding_rule_id(f) := upper(trim_space(object.get(object.get(f, "source", {}), "id", "")))

exception_rule_match(ex, f) if {
  upper(trim_space(object.get(ex, "rule_id", ""))) == finding_rule_id(f)
}

exception_rule_match(ex, f) if {
  aliases := object.get(ex, "rule_id_aliases", [])
  type_name(aliases) == "array"
  target_rule := finding_rule_id(f)
  some alias in aliases
  upper(trim_space(alias)) == target_rule
}

# Core Presence Validation (Schema validation)
has_required_exception_fields(ex) if {
  object.get(ex, "id", "") != ""
  object.get(ex, "tool", "") != ""
  object.get(ex, "rule_id", "") != ""
  object.get(ex, "resource_path", "") != ""
  count(object.get(ex, "environments", [])) > 0
  object.get(ex, "max_severity", "") != ""
  object.get(ex, "approved_by", "") != ""
  object.get(ex, "expires_at", "") != ""
}

valid_exception_definition(ex) if {
  has_required_exception_fields(ex)
  
  # Ensure environments are correctly typed strings 
  envs := object.get(ex, "environments", [])
  count([env |
    env := lower(envs[_])
    env != "dev"
    env != "test"
    env != "staging"
    env != "prod"
  ]) == 0
  
  # Ensure max_severity is valid
  max_sev := upper(object.get(ex, "max_severity", ""))
  severity_rank[max_sev] >= 1
}

exception_env_match(ex) if {
  envs := object.get(ex, "environments", [])
  some i
  lower(envs[i]) == environment
}

resource_selector_match(ex, f) if {
  # Direct string equality (Shift-Left on Data)
  object.get(ex, "resource_path", "") == object.get(object.get(f, "resource", {}), "path", "")
}

exception_severity_allowed(ex, f) if {
  max_sev := upper(object.get(ex, "max_severity", "LOW"))
  finding_sev := upper(object.get(object.get(f, "severity", {}), "level", "LOW"))
  severity_rank[finding_sev] <= severity_rank[max_sev]
}

exception_matches_finding(ex, f) if {
  lower(object.get(ex, "tool", "")) == lower(object.get(object.get(f, "source", {}), "tool", ""))
  exception_rule_match(ex, f)
  resource_selector_match(ex, f)
  exception_env_match(ex)
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
    "critical_max": critical_max_raw,
    "high_max": high_max_raw
  },
  "environment": environment,
  "execution_mode": execution_mode,
  "exceptions": {
    "applied_ids": sort([id | applied_exception_ids[id]]),
    "applied_count": count(applied_exception_ids),
    "strict_prod_violations": sort([id | prod_critical_exception_violation[id]]),
    "invalid_enabled_ids": sort([id | invalid_enabled_exception_ids[id]])
  }
}
