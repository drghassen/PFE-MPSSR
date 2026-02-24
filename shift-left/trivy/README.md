# CloudSentinel — Trivy Scanner

Enterprise-grade container & SCA security scanning module.

## Scope & Responsibility Matrix

| Concern | Tool | Location |
|---|---|---|
| Container vulnerability (OS + lib) | **Trivy** ✅ | `scan-image.sh` |
| SCA (language packages) | **Trivy** ✅ | `scan-fs.sh` |
| Dockerfile misconfigurations | **Trivy** ✅ | `scan-config.sh` |
| Secrets in image layers / source | **Trivy** ✅ | `scan-image.sh` + `scan-fs.sh` |
| IaC (Terraform) | **Checkov** ❌ out of scope | `shift-left/checkov/` |
| Secrets in git history / commits | **Gitleaks** ❌ out of scope | `shift-left/gitleaks/` |
| Enforcement (ALLOW / DENY) | **OPA** ❌ out of scope | `shift-left/opa/` |

> Trivy **never blocks** — exit-code is always `0`. The OPA Quality Gate is the enforcement layer.

## Architecture

```
shift-left/trivy/
├── configs/
│   ├── trivy.yaml            # Local advisory mode config
│   ├── trivy-ci.yaml         # CI mode config (no-progress, JSON output)
│   └── severity-mapping.json # Severity + category + SLA mapping for OPA
├── scripts/
│   ├── run-trivy.sh          # Orchestrator — dispatches + normalises to OPA
│   ├── scan-image.sh         # Container image: OS+lib vuln + embedded secrets
│   ├── scan-fs.sh            # Filesystem: SCA + secrets in source
│   └── scan-config.sh        # Dockerfile: misconfig (CIS Docker Benchmark)
├── tests/
│   ├── fixtures/
│   │   ├── images/
│   │   │   ├── Dockerfile.critical  # Triggers CRITICAL misconfigs
│   │   │   ├── Dockerfile.high      # Triggers HIGH findings
│   │   │   └── Dockerfile.clean     # Expects 0 findings
│   │   └── fs/
│   │       └── vulnerable-package.json  # Known-vulnerable npm deps
│   └── integration/
│       └── test-trivy.sh    # Integration tests (FS + config + OPA schema)
├── .trivyignore              # CVE allowlist (with justification + expiry)
└── README.md
```

## Usage

### Local Scan — Container Image
```bash
./scripts/run-trivy.sh alpine:3.18 image
```

### Local Scan — Filesystem / SCA
```bash
./scripts/run-trivy.sh ./src fs
```

### Local Scan — Dockerfile Misconfig
```bash
./scripts/run-trivy.sh ./Dockerfile config
# OR scan a directory containing Dockerfiles:
./scripts/run-trivy.sh ./app/ config
```

### CI Mode (automatic detection via `$CI`)
```bash
# CI environment is auto-detected — trivy-ci.yaml is used
bash ./scripts/run-trivy.sh ./src fs
```

## OPA Output Schema

`reports/opa/trivy_opa.json` — fed to OPA Quality Gate:

```json
{
  "tool": "trivy",
  "version": "7.0",
  "timestamp": "2026-02-20T00:00:00Z",
  "branch": "main",
  "commit": "abc123",
  "scan_type": "image",
  "target": "alpine:3.18",
  "stats": {
    "CRITICAL": 0,
    "HIGH": 2,
    "MEDIUM": 5,
    "LOW": 1,
    "TOTAL": 8,
    "by_type": { "vulnerability": 7, "secret": 0, "misconfig": 1 },
    "by_category": { "INFRASTRUCTURE": 3, "APPLICATION": 4, "CONFIGURATION": 1, "SECRET": 0 }
  },
  "remediation_sla": { "CRITICAL": "24h", "HIGH": "7d", "MEDIUM": "30d", "LOW": "90d" },
  "findings": [...]
}
```

## CVE Allowlist

`.trivyignore` — each entry requires:
- CVE/rule ID
- Justification (business/technical)
- Expiry date
- Approver (person or ticket ID)

## Integration Tests

```bash
bash ./tests/integration/test-trivy.sh
```
