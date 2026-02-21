# 🧪 Tests - Échantillons & Validation

> Tests unitaires, échantillons vulnérables, tests end-to-end

## 📁 Structure

```
tests/
├── README.md
├── vulnerable-samples/          # Échantillons intentionnellement vulnérables
│   ├── README.md
│   ├── secrets.tf              # Fichier avec secrets hardcodés
│   ├── insecure-storage.tf     # Storage public
│   ├── open-ports.tf           # NSG trop permissif
│   └── Dockerfile.vulnerable   # Image avec CVE
│
├── opa-tests/                   # Tests policies OPA
│   ├── README.md
│   └── test-cases/
│
└── e2e/                        # Tests end-to-end
    ├── README.md
    └── test-full-pipeline.sh
```

---

## 🎯 Objectifs

1. **Valider les scanners** : S'assurer qu'ils détectent bien les vulnérabilités
2. **Tester les policies** : Vérifier les règles OPA et Custodian
3. **E2E** tests : Pipeline complet de bout en bout

---

## 🚀 Utilisation

### Tester avec échantillons vulnérables
```bash
make test-vulnerable-samples
```

### Tests OPA
```bash
make opa-test
```

### Test pipeline complet
```bash
cd tests/e2e
./test-full-pipeline.sh
```

---

## ⚠️ Important

Les fichiers dans `vulnerable-samples/` sont **INTENTIONNELLEMENT** vulnérables.  
**NE JAMAIS** les utiliser en production !

---

## 📚 Documentation

Voir [../docs/TESTING.md](../docs/TESTING.md) pour le guide complet.

### Test pipeline dev/prod
```bash
./tests/e2e/test-pipeline-dev-prod.sh
```
