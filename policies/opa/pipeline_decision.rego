package cloudsentinel.gate

import rego.v1

scanners := object.get(input, "scanners", {})
summary_global := object.get(object.get(input, "summary", {}), "global", {})
thresholds := object.get(object.get(input, "quality_gate", {}), "thresholds", {})
required_scanners := ["gitleaks", "checkov", "trivy"]

critical_max := object.get(thresholds, "critical_max", 0)
high_max := object.get(thresholds, "high_max", 2)

critical_count := object.get(summary_global, "CRITICAL", 0)
high_count := object.get(summary_global, "HIGH", 0)
total_failed := object.get(summary_global, "FAILED", 0)

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
  critical_count > critical_max
  msg := sprintf("CRITICAL findings (%d) exceed threshold (%d)", [critical_count, critical_max])
}

deny[msg] if {
  high_count > high_max
  msg := sprintf("HIGH findings (%d) exceed threshold (%d)", [high_count, high_max])
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
    "critical": critical_count,
    "high": high_count,
    "failed": total_failed
  },
  "thresholds": {
    "critical_max": critical_max,
    "high_max": high_max
  }
}
