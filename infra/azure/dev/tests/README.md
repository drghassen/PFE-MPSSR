# 🧪 Tests d'Intégration & Fixtures

Ce répertoire garantit que l'architecture DevSecOps CloudSentinel remplit ses objectifs, sans régression, tout au long de son développement.

---

## 📁 Structure V5.0

L'arbre des tests héberge des suites de tests End-to-End (E2E) ainsi que des "Mock objects" (Fixtures) pour provoquer le framework.

```text
tests/
├── README.md
├── checkov/
│   └── fixtures/       # Fichiers .tf délibérément vulnérables
│
├── e2e/                # Tests fonctionnels simulant toute la pipeline CI
│   ├── run_test.sh     # Orchestrateur de test E2E principal
│   ├── gitleaks.sh     # Test spécifique à l'interception de secrets
│   └── opa.sh          # Test que l'OPA coupe le flux sur des Criticals
└── ...
```

## 🎯 Méthodologie "Shift-Left Testing"

On ne teste pas uniquement si le **code** est vulnérable, on teste **si la pipeline de sécurité parvient bien à attraper le code vulnérable**.

1. **Fixtures Terraform** (`nsg_open_prefixes.tf`) : Nous fournissons un Security Group ouvert sur 0.0.0.0/0. Si Checkov ou OPA le laisse passer lors du run, le test échoue.
2. **Secrets Git Diff** (`e2e/gitleaks.sh`) : Simule un "git commit" contenant un faux Personal Access Token (PAT). Le CI test runner doit obligatoirement obtenir un `Exit Code 1` (DENY) depuis le Policy Engine.

---

## 🚀 Exécution

Gérée par notre `Makefile` racine (Ex: `make test`).
