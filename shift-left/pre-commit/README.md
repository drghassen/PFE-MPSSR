# CloudSentinel Pre-Commit

## Overview
This hook runs Gitleaks on staged files, builds the golden report, and evaluates OPA in advisory mode by default.
OPA uses server-first with CLI fallback (or CLI forced by env).
In local-fast mode, Checkov/Trivy reports are ignored to avoid stale noise.
By default it does not block the commit; local enforcement can be enabled when needed.

## Install
```bash
make pre-commit-install
```

## Notes
- Local behavior is advisory by default (`exit 0`) even when findings exist or OPA returns DENY.
- The hook enables `USE_BASELINE=true`; the Gitleaks baseline is used only when `shift-left/gitleaks/.gitleaks-baseline.json` exists.
- Set `CLOUDSENTINEL_PRECOMMIT_MODE=enforce` to make local pre-commit block like the CI OPA gate.
- Set `CLOUDSENTINEL_PRECOMMIT_SCAN_SCOPE=staged_history` to scan both the staged diff (`git add .`) and the full Git history. Only staged findings are treated as latest-change findings; history-only findings remain advisory, matching the CI full-history plus range model.
- Set `OPA_LOCAL_MODE=cli` to force OPA CLI locally.
- Set `OPA_LOCAL_ADVISORY=false` to skip local OPA evaluation.
- If OPA server/CLI is unavailable, the hook warns and continues.

## Important
`git add .` stages only files accepted by Git. Ignored files such as `.env`, `*.tfvars`, keys, or local runtime outputs are not scanned by the staged hook unless they are force-added.
