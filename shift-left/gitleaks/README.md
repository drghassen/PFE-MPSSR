# 🔍 Gitleaks — Scanner de Secrets (Shift-Left)

> **Protégez vos credentials** : Arrête les clés d'API et mots de passe avant le commit, ou les intercepte dans la CI/CD si échappé.

Gitleaks est le composant le plus rapide du Shift-Left. Il opère en première ligne (Tier 1) pour scanner l'historique de Git à la recherche d'entropie (mots de passe) et de patterns (clés AWS, GCP, Azure, tokens personnels).

---

## 📐 Fonctionnement (Wrapper V5.0)

Dans le pattern de séparation de CloudSentinel, Gitleaks ne bloque jamais directement un pipeline.
Le script `run-gitleaks.sh` encapsule l'outil pour :
1.  Rediriger tous les résultats sécuremment (`--redact` activé obligatoirement).
2.  Normaliser et fusionner la sortie sous un format OPA-ready (`gitleaks_opa.json`).
3.  Toujours renvoyer un "exit 0" pour laisser le mot final au Policy Decision Point (OPA).

### Exécution Contextuelle
- **Mode CI** : Scanne par défaut le `commit-range` (`$CI_MERGE_REQUEST_TARGET_BRANCH_SHA..HEAD`) pour ne pas surcharger la pipeline avec tout l'historique. Fallback sur un "full repo scan" si le range échoue.
- **Mode Local** : Invoqué par le pre-commit hook pour scanner uniquement `git diff --staged`. Extrêmement rapide (< 0.5s).

---

## 🛠️ Configuration (`gitleaks.toml`)

Les règles par défaut de Gitleaks sont souvent trop bruyantes. CloudSentinel utilise un `gitleaks.toml` propriétaire :
*   `useDefault = false` (Contrôle total des expressions régulières).
*   17 règles spécifiques aux Cloud Providers.
*   Allowlisting massif sur fichiers (`vendor/`, `.terraform/`, `package-lock.json`, etc.)
*   Allowlisting regex (SHA256, localhost, variables d'environnements factices).

---

## 🚀 Utilisation

**En local (Développeur) :**
```bash
# S'exécute automatiquement via le Hook pre-commit
# Output visible dans le shell
```

**Pipeline Manuelle (Admin) :**
```bash
bash shift-left/gitleaks/run-gitleaks.sh
# Checkez .cloudsentinel/gitleaks_opa.json
```

---

## 📚 Bonnes Pratiques Gitleaks
1.  **Redaction** : Impossible de commiter `run-gitleaks.sh` sans le flag `--redact`. L'audit JSON ne doit contenir aucun secret en clair.
2.  **Baseline** : Si un vieux repostory hérite de secrets ineffaçables, générez un `gitleaks.baseline.json` et ajoutez `export GITLEAKS_BASELINE=".gitleaks.baseline.json"` dans le `.env`.
