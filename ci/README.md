# 🔄 CI/CD & Base Images (Supply Chain Security)

Ce répertoire centralise les outils d'orchestration pour le pipeline GitLab CI/CD ainsi que le code de construction des **images Docker immutables** utilisées par CloudSentinel.

> **Principe de conception** : Le pipeline GitLab (`.gitlab-ci.yml`) à la racine pilote les opérations. Le répertoire `ci/` garantit la sécurisation de la **Supply Chain** des outils sous-jacents.

---

## 📁 Structure

```text
ci/
├── README.md
├── libs/            # Logique contractuelle partagée CI/local
├── scripts/         # Wrappers CI minces (appelent libs + shift-left)
└── images/
    ├── opa/            # Image OPA durcie (pinning par digest)
    └── scan-tools/     # Image multi-outils optimisée (Alpine/Slim)
```

## 🛡️ Supply Chain Security (V5.0)

Pour éviter les attaques par empoisonnement de cache ou modification de tag (ex: `:latest`), CloudSentinel impose :

### 1. Pinning par Digest SHA256
Nos images de base (ex: OPA) ne sont pas tirées par un tag flottant (`1.13.1`), mais par leur **empreinte cryptographique stricte** :
```dockerfile
# Exemple extrait de ci/images/opa/Dockerfile
FROM openpolicyagent/opa:1.13.1-static@sha256:79dc887c32be886069d9429075a541c8b0e53326251856190b84572c44702a7a AS opa
```

### 2. Multi-Stage Builds & Bloat Reduction
L'image `scan-tools` regroupe Gitleaks, Trivy et Checkov.
Pour éviter les timeouts réseau (ex: "use of closed network connection" sur les gros layers Python), l'image utilise un build multi-stage propre, basculant de `python:bookworm` vers `python:slim` pour diviser la taille finale par 2 et assurer des push Docker fiables.

### 3. Contrôles d'Intégrité CLI
*   **Checkov Wheel** : Le binaire Python `.whl` est vérifié par `sha256sum` en CI avant `pip install`.
*   Un fail-fast UX ("Supply Chain Security Blocked") guide le développeur si la variable `CHECKOV_WHEEL_SHA256` est absente dans GitLab.

---

## 🚀 Build Local & Publication

### Build OPA
```bash
docker build -t registry.gitlab.com/votre-user/cloudsentinel/opa:1.13.1 ci/images/opa
docker push registry.gitlab.com/votre-user/cloudsentinel/opa:1.13.1
```

### Build Scan-Tools
```bash
docker build \
  --build-arg GITLEAKS_VERSION=8.21.2 \
  --build-arg CHECKOV_VERSION=3.2.502 \
  --build-arg TRIVY_VERSION=0.69.3 \
  -t registry.gitlab.com/votre-user/cloudsentinel/scan-tools:1.0 \
  ci/images/scan-tools
```

---

## 📋 Bonnes Pratiques CI (`.gitlab-ci.yml`)

1.  **Immuabilité** : Le `.gitlab-ci.yml` utilise la variable `OPA_IMAGE` pointant vers un digest (et non un tag).
2.  **Contrats & Tests OPA** : Les jobs `contract-test`, `opa-unit-tests` et `artifact-integrity-check` valident les contrats d'artefacts (détection/normalisation/décision), l'architecture Rego et l'intégrité des politiques avant `deploy`.
3.  **Factorisation** : Les validations de contrat (merge Trivy + schéma JSON) sont centralisées dans `ci/libs/cloudsentinel_contracts.py` et appelées par les wrappers `ci/scripts/*`.
