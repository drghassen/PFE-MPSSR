# 🔄 CI/CD Scripts

> Scripts d'orchestration pour GitLab CI/CD

## 📁 Structure

```
ci/
├── README.md
└── images/
    └── opa/            # Image OPA pin-able pour CI
```

---

## 🎯 Utilisation

Les scanners sont orchestrés directement par `.gitlab-ci.yml` (jobs `gitleaks-scan`, `checkov-scan`, `trivy-scan`, `normalize-reports`, `opa-decision`). Aucun script additionnel dans `ci/scripts/`.

---

## 📚 Documentation

Voir [../.gitlab-ci.yml](../.gitlab-ci.yml) pour la configuration complète.

## OPA CI Image (enterprise)

Pour éviter les téléchargements au runtime et garantir une version OPA identique partout, utilisez l'image dédiée.

### Build local (pour test)
```bash
# Remplacer par un tag local simple
docker build --build-arg OPA_VERSION=1.13.1 -t cloudsentinel/opa:local ci/images/opa
```

### Build en CI (GitLab Registry)
La variable `$CI_REGISTRY_IMAGE` est injectée automatiquement par GitLab.
```bash
docker build --build-arg OPA_VERSION=1.13.1 -t $CI_REGISTRY_IMAGE/opa:1.13.1 ci/images/opa
docker push $CI_REGISTRY_IMAGE/opa:1.13.1
```

### Contrôles CI recommandés
- Job `opa-image-smoke` dans `.gitlab-ci.yml` valide runtime OPA + outils.
- Utiliser un digest immutable pour `OPA_IMAGE` dans les variables CI/CD.
- Activer le scanning registry et une cleanup policy côté GitLab.
