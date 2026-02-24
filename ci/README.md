# 🔄 CI/CD Scripts

> Scripts d'orchestration pour GitLab CI/CD

## 📁 Structure

```
ci/
├── README.md
└── scripts/
    ├── run-scanners.sh        # Lance tous les scanners
    └── upload-to-defectdojo.sh # Upload findings
```

---

## 🎯 Utilisation

Ces scripts sont appelés automatiquement par `.gitlab-ci.yml`

### Localement

```bash
# Exécuter les scanners
./ci/scripts/run-scanners.sh

# Upload vers DefectDojo
./ci/scripts/upload-to-defectdojo.sh
```

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
