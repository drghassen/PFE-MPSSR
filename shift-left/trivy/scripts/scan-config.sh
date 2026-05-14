#!/usr/bin/env bash
set -euo pipefail

################################################################################
# CloudSentinel - Trivy Config Scanner (disabled by design)
# Scope ownership:
#   - IaC/config scanning -> Checkov
#   - Secret scanning     -> Gitleaks
#   - Trivy               -> vulnerability/SCA only
################################################################################

echo "[CloudSentinel][Trivy][CONFIG][ERROR] Trivy config scanning is disabled by design. Use Checkov for IaC/config scanning." >&2
exit 2
