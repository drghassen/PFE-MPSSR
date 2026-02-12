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
