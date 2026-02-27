# 🔒 Shift-Left — Stack de Sécurité Pré-Déploiement

> **Phase 1** : Détection exhaustive des vulnérabilités, normalisation des données, et prise de décision centralisée AVANT tout déploiement dans le pipeline CI/CD.

## 📐 Architecture Interne (Shift-Left)

Le dossier `shift-left/` contient tous les composants agissant avant le déploiement. L'architecture respecte strictement le pattern **PEP/PDP** (Policy Enforcement Point / Policy Decision Point). Aucun scanner ne prend de décision de blocage par lui-même.

```text
[ Gitleaks ]   [ Checkov ]   [ Trivy ]    <-- Phase de Scan (Parallèle, Advisory)
      \             |             /
       \            |            /
        v           v           v
    [ Normalizer (normalize.sh) ]         <-- Data Producer (Uniformisation JSON)
                    |
                    v (Golden Report)
    [ OPA Engine (pipeline_decision.rego) ] <-- Policy Decision Point (PDP)
                    |
                    v
    [ Quality Gate (run-opa.sh) ]         <-- Policy Enforcement Point (PEP)
           /                 \
        ALLOW                DENY (Bloque la CI)
```

## 🛠️ Composants et Responsabilités

### 1. Scanners (Les "Detectors")
Chaque outil est wrappé par un script (ex: `run-gitleaks.sh`) qui garantit une exécution robuste (`emit_not_run` en cas d'erreur) :
*   **`gitleaks/`** : Détecte les secrets en dur (fichiers de conf customisés `gitleaks.toml`).
*   **`checkov/`** : Détecte les misconfigurations de l'Infrastructure as Code (Terraform) via des règles spécifiques à CloudSentinel.
*   **`trivy/`** : Scanne les vulnérabilités CVE dans les images de conteneurs et dépendances.

### 2. Normalizer (`normalizer/`)
Le composant le plus critique de l'ETL de sécurité :
*   Ingère les rapports hétérogènes des scanners.
*   Génère un **Golden Report** JSON unique (`cloudsentinel_report.schema.json`).
*   Délègue explicitement la décision à OPA (`quality_gate: "NOT_EVALUATED"`).
*   Gère le mode "local-fast" pour le confort développeur en pre-commit.

### 3. Policy Engine (`opa/`)
Point d'exécution de la Quality Gate. Le script `run-opa.sh` évalue le Golden Report à travers les règles définies dans `policies/opa/`.
*   Support d'exécution "Advisory" (warning uniquement) ou "Enforce" (bloquant).
*   Interopérabilité API REST (OPA Server) avec fallback sur binaire OPA CLI.

### 4. Pre-commit (`pre-commit/`)
Garantit que le code ne quitte pas le poste développeur avec des secrets en clair.
*   Lance de manière ciblée Gitleaks sur les fichiers `staged`.
*   Consulte OPA en mode "advisory".

## 📁 Structure du Répertoire

```text
shift-left/
├── gitleaks/            # Outil d'analyse des secrets
├── checkov/             # Outil d'analyse statique IaC
├── trivy/               # Outil d'analyse des conteneurs/dépendances
│
├── normalizer/          # Engine de transformation de données
│   ├── normalize.sh     # Convertisseur en Golden Report
│   └── CONTRACT.md      # Documentation du contrat de données vers OPA
│
├── opa/                 # Scripts d'exécution du Policy Engine (PEP)
│   └── run-opa.sh       # Exécuteur local/CI pour OPA
│
└── pre-commit/          # Hooks locaux pour développeurs
```

## 🚀 Utilisation Courante

**Mode CI (Automatique)**
Géré par `.gitlab-ci.yml`, les scripts sont invoqués dans l'ordre :
1.  Scan (`bash shift-left/gitleaks/run-gitleaks.sh` etc.)
2.  Normalisation (`bash shift-left/normalizer/normalize.sh`)
3.  Décision (`bash shift-left/opa/run-opa.sh --enforce`)

**Mode Local (Déboguage)**
Depuis la racine du projet, pour simuler la pipeline entière :
```bash
export CLOUDSENTINEL_EXECUTION_MODE=local
bash shift-left/gitleaks/run-gitleaks.sh
bash shift-left/normalizer/normalize.sh
bash shift-left/opa/run-opa.sh --advisory
```

## 🔑 Rappels de Conception
*   **Ne jamais coder de logique de décision dans un wrapper de scan.**
*   Si un scanner plante, il doit émettre un statut `NOT_RUN` (JSON valide) pour que OPA puisse intercepter et bloquer pour "Scanner manquant".
*   Tout changement au format de sortie du normalizer doit être reflété dans le `CONTRACT.md`.
