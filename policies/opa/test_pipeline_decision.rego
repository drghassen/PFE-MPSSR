package cloudsentinel.gate

import rego.v1

test_allow_when_thresholds_respected if {
  result := decision with input as {
    "summary": {
      "global": {
        "CRITICAL": 0,
        "HIGH": 1,
        "FAILED": 1
      }
    },
    "quality_gate": {
      "thresholds": {
        "critical_max": 0,
        "high_max": 2
      }
    },
    "scanners": {
      "gitleaks": {"status": "PASSED"},
      "checkov": {"status": "FAILED"},
      "trivy": {"status": "PASSED"}
    }
  }

  result.allow
  count(result.deny) == 0
}

test_deny_on_critical_over_threshold if {
  result := decision with input as {
    "summary": {
      "global": {
        "CRITICAL": 1,
        "HIGH": 0,
        "FAILED": 1
      }
    },
    "quality_gate": {
      "thresholds": {
        "critical_max": 0,
        "high_max": 2
      }
    },
    "scanners": {
      "gitleaks": {"status": "PASSED"},
      "checkov": {"status": "PASSED"},
      "trivy": {"status": "PASSED"}
    }
  }

  not result.allow
  count(result.deny) == 1
  contains(result.deny[0], "CRITICAL findings")
}

test_deny_when_scanner_not_run if {
  result := decision with input as {
    "summary": {
      "global": {
        "CRITICAL": 0,
        "HIGH": 0,
        "FAILED": 0
      }
    },
    "quality_gate": {
      "thresholds": {
        "critical_max": 0,
        "high_max": 2
      }
    },
    "scanners": {
      "gitleaks": {"status": "PASSED"},
      "checkov": {"status": "NOT_RUN"},
      "trivy": {"status": "PASSED"}
    }
  }

  not result.allow
  count(result.deny) == 1
  contains(result.deny[0], "Scanner checkov")
}

test_scanner_not_run_set_contains_checkov if {
  not_run := scanner_not_run with input as {
    "summary": {
      "global": {
        "CRITICAL": 0,
        "HIGH": 0,
        "FAILED": 0
      }
    },
    "quality_gate": {
      "thresholds": {
        "critical_max": 0,
        "high_max": 2
      }
    },
    "scanners": {
      "gitleaks": {"status": "PASSED"},
      "checkov": {"status": "NOT_RUN"},
      "trivy": {"status": "PASSED"}
    }
  }

  not_run["checkov"]
}
