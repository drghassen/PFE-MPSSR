package cloudsentinel.gate

import rego.v1

scanners := object.get(input, "scanners", {})
summary_global := object.get(object.get(input, "summary", {}), "global", {})
thresholds := object.get(object.get(input, "quality_gate", {}), "thresholds", {})
required_scanners := ["gitleaks", "checkov", "trivy"]
environment := lower(object.get(object.get(input, "metadata", {}), "environment", "dev"))

default exceptions_store := []

exceptions_store := data.cloudsentinel.exceptions.exceptions

critical_max := object.get(thresholds, "critical_max", 0)
high_max := object.get(thresholds, "high_max", 2)

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

finding_key(f) := sprintf("%s|%s|%s", [
  object.get(object.get(f, "source", {}), "tool", ""),
  object.get(object.get(f, "source", {}), "id", ""),
  object.get(object.get(f, "resource", {}), "path", "")
])

has_required_exception_fields(ex) if {
  object.get(ex, "id", "") != ""
  object.get(ex, "tool", "") != ""
  object.get(ex, "rule_id", "") != ""
  object.get(ex, "ticket", "") != ""
  object.get(ex, "approved_by", "") != ""
  object.get(ex, "expires_at", "") != ""
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
  expected == actual
}

resource_path_match(expected, actual) if {
  endswith(actual, expected)
}

resource_path_match(expected, actual) if {
  endswith(expected, actual)
}

exception_severity_allowed(ex, f) if {
  max_sev := upper(object.get(ex, "max_severity", "LOW"))
  finding_sev := upper(object.get(object.get(f, "severity", {}), "level", "LOW"))
  severity_rank[finding_sev] <= severity_rank[max_sev]
}

exception_matches_finding(ex, f) if {
  lower(object.get(ex, "tool", "")) == lower(object.get(object.get(f, "source", {}), "tool", ""))
  object.get(ex, "rule_id", "") == object.get(object.get(f, "source", {}), "id", "")
  resource_path_match(object.get(ex, "resource_path", ""), object.get(object.get(f, "resource", {}), "path", ""))
  exception_env_match(ex)
  exception_not_expired(ex)
  exception_severity_allowed(ex, f)
  has_required_exception_fields(ex)
  object.get(ex, "enabled", false)
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

effective_critical := count([f |
  f := effective_failed_findings[_]
  upper(object.get(object.get(f, "severity", {}), "level", "LOW")) == "CRITICAL"
])

effective_high := count([f |
  f := effective_failed_findings[_]
  upper(object.get(object.get(f, "severity", {}), "level", "LOW")) == "HIGH"
])

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
  ex_id := prod_critical_exception_violation[_]
  msg := sprintf("Exception %s is invalid for prod: max_severity CRITICAL is forbidden", [ex_id])
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
    "failed": count(effective_failed_findings),
    "excepted": count(applied_exception_ids)
  },
  "thresholds": {
    "critical_max": critical_max,
    "high_max": high_max
  },
  "environment": environment,
  "exceptions": {
    "applied_ids": sort([id | applied_exception_ids[id]]),
    "applied_count": count(applied_exception_ids),
    "strict_prod_violations": sort([id | prod_critical_exception_violation[id]])
  }
}
