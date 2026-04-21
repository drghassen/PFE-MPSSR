# Gitleaks — Scanner de Secrets (Shift-Left)

> **Protégez vos credentials** : Arrête les clés d'API et mots de passe avant le commit, ou les intercepte dans la CI/CD si échappé.

Gitleaks est le composant de première ligne (Tier 1) du Shift-Left. Il détecte les secrets hardcodés par analyse d'entropie et de patterns (clés AWS, GCP, Azure, tokens personnels, etc.).

---

## Fonctionnement

Dans le pattern de séparation de CloudSentinel, Gitleaks ne bloque jamais directement un pipeline.
OPA est le seul point de décision (`run-opa.sh --enforce` en CI, `--advisory` en local).

Le script `run-gitleaks.sh` encapsule l'outil pour :
1. Rediriger tous les résultats sécurisement (`--redact` activé sur tous les modes) et enrichir chaque finding avec `CloudSentinelSecretHash` (SHA-256 redacted-safe).
2. Toujours renvoyer un exit code permettant à OPA de décider.

---

## Configuration (`gitleaks.toml`)

- `useDefault = true` — modèle hybride : règles upstream Gitleaks (maintenues par la communauté) + règles custom Azure.
- Règles custom : Azure SAS tokens, Azure Storage connection strings, Azure AD credentials.
- Allowlist : `.terraform/`, `tests/fixtures/`, fichiers de lock, images binaires, IDs Terraform, connexions locales.

---

## Modes de scan

### CI — Scan principal (signal OPA / gate pipeline)

```bash
gitleaks detect --no-git --source <repo> --redact ...
```

- **Output** : `.cloudsentinel/gitleaks_raw.json`
- Scanne le snapshot complet du repository (fichiers présents dans le workspace CI).
- C'est le **seul signal OPA**. Ce fichier est la source de vérité pour la décision pipeline.

### CI — Scan range secondaire (enrichissement metadata, best-effort)

```bash
gitleaks detect --source <repo> --log-opts <range> --redact ...
```

- **Output** : `.cloudsentinel/gitleaks_range_raw.json`
- Enrichit les findings du scan principal avec les metadata git (commit, author, date) quand un matching par clé composite (RuleID, File, StartLine, SecretHash) est trouvé.
- **Jamais gating, jamais un signal OPA.**
- Absent ou invalide = ignoré silencieusement (best-effort).
- Range sélectionné automatiquement :
  - `CI_MERGE_REQUEST_TARGET_BRANCH_SHA..CI_COMMIT_SHA` si disponible (MR)
  - `CI_COMMIT_BEFORE_SHA..CI_COMMIT_SHA` si disponible (push)
  - `--max-count=200` sinon (fallback limité)

### Local — Protection pre-commit (staged)

```bash
gitleaks protect --staged --redact ...
```

- Invoqué automatiquement par le pre-commit hook.
- Scanne uniquement `git diff --staged`. Extrêmement rapide (< 0.5s).

### Local — Scan complet du repository

```bash
SCAN_TARGET=repo bash shift-left/gitleaks/run-gitleaks.sh
```

- Scanne l'ensemble du repository local.

---

## Bonnes pratiques

1. **Redaction** : `--redact` activé sur tous les modes. L'audit JSON ne contient aucun secret en clair.
2. **Baseline** : Si un repository hérite de secrets ineffaçables dans l'historique, générez un `gitleaks.baseline.json` et référencez-le dans `gitleaks.toml`.
3. **Fingerprint** : Non utilisé comme clé de matching entre le scan principal (`--no-git`) et le scan range (`--log-opts`) — incompatibles structurellement. La clé composite (RuleID, File, StartLine, SecretHash) est utilisée.
