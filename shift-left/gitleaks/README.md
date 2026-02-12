# Gitleaks Security Component

## Overview
Gitleaks est un outil de scan de secrets (clés API, tokens, mots de passe) statique.

## Utilisation Locale (Pre-commit)
Pour activer le hook de sécurité :
```bash
ln -s ../../shift-left/gitleaks/pre-commit-hook.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## Configuration
Les règles sont définies dans [gitleaks.toml](./gitleaks.toml).
Les faux positifs peuvent être ajoutés dans [.gitleaksignore](./.gitleaksignore).

######
# Gitleaks - CloudSentinel Shift-Left

## Overview
Gitleaks is used to detect secrets before code reaches CI/CD pipelines.

## Pre-Commit Setup

```bash
ln -sf ../../shift-left/gitleaks/pre-commit-hook.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
