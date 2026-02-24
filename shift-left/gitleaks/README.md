# Gitleaks Security Component

## Overview
Gitleaks est un outil de scan de secrets (cles API, tokens, mots de passe).

## Pre-commit recommande
Utiliser le hook unifie CloudSentinel :
```bash
ln -sf ../../shift-left/pre-commit/pre-commit.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## Gitleaks seulement (optionnel)
```bash
ln -sf ../../shift-left/gitleaks/pre-commit-hook.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## Configuration
Les regles sont definies dans `shift-left/gitleaks/gitleaks.toml`.
Les faux positifs peuvent etre ajoutes dans `shift-left/gitleaks/.gitleaksignore`.
