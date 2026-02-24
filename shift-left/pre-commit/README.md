# CloudSentinel Pre-Commit

## Overview
This hook runs Gitleaks on staged files, builds the golden report, and evaluates OPA in advisory mode (CLI forced).
In local-fast mode, Checkov/Trivy reports are ignored to avoid stale noise.
It never blocks the commit.

## Install
```bash
ln -sf ../../shift-left/pre-commit/pre-commit.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## Notes
- OPA CLI is preferred for local checks. The server is reserved for CI/CD.
- If the OPA CLI is not installed and no server is available, the hook will warn and continue.
