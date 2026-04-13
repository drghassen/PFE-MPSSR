# CloudSentinel Pre-Commit

## Overview
This hook runs Gitleaks on staged files, builds the golden report, and evaluates OPA in advisory mode.
OPA uses server-first with CLI fallback (or CLI forced by env).
In local-fast mode, Checkov/Trivy reports are ignored to avoid stale noise.
It never blocks the commit.

## Install
```bash
ln -sf ../../shift-left/pre-commit/pre-commit.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## Notes
- Local behavior is always advisory (`exit 0`) even when findings exist or OPA returns DENY.
- Set `OPA_LOCAL_MODE=cli` to force OPA CLI locally.
- Set `OPA_LOCAL_ADVISORY=false` to skip local OPA evaluation.
- If OPA server/CLI is unavailable, the hook warns and continues.
