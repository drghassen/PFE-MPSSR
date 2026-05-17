# CloudSentinel Pre-Commit

## Overview
This hook runs Gitleaks on staged files, builds the golden report, and evaluates OPA in advisory mode.
OPA uses server-first with CLI fallback (or CLI forced by env).
In local-fast mode, Checkov/Trivy reports are ignored to avoid stale noise.
It never blocks the commit.

## Install
```bash
make pre-commit-install
```

## Notes
- Local behavior is always advisory (`exit 0`) even when findings exist or OPA returns DENY.
- The hook enables `USE_BASELINE=true`; the Gitleaks baseline is used only when `shift-left/gitleaks/.gitleaks-baseline.json` exists.
- Set `OPA_LOCAL_MODE=cli` to force OPA CLI locally.
- Set `OPA_LOCAL_ADVISORY=false` to skip local OPA evaluation.
- If OPA server/CLI is unavailable, the hook warns and continues.
