# 🏗️ Infra — Infrastructure as Code (OpenTofu)

> **Cloud Resources Provisioning** : Code source Terraform configurant l'infrastructure CloudSentinel (Azure, Kubernetes, etc.) protégée et auditée par la pipeline DevOps.

Ce répertoire contient l'IaC qui déploie l'environnement applicatif et opérationnel, sécurisé de manière préventive (Shift-Left par Checkov) et monitoré au runtime (Cloud Custodian).

---

## 📁 Architecture

L'infrastructure est conçue par modules réutilisables, promus par environnement (`dev`, `staging`, `prod`) :

```text
infra/
├── README.md
├── modules/               # Composants réutilisables Terraform / OpenTofu
│   ├── network/           # VNETs, Subnets, NSGs
│   ├── storage/           # Storage Accounts (Blobs, Queues)
│   └── compute/           # AKS, VMs
│
└── azure/                 # Instanciations par environnement cloud
    ├── dev/               # Env de développement déployé sur push (Trunk-based)
    └── prod/              # Env de production (Protégée par MR stricte et OPA)
```

---

## 🔒 Intégration Sécurité (V5.0)

1.  **Shift-Left : Scanner de Misconfigurations (Checkov)**
    *   Tout le code `.tf` présent ici passe systématiquement par l'analyseur Checkov de CloudSentinel en CI.
    *   Une misconfiguration (Ex: `publicNetworkAccess = true` sur un composant sensible) sera bloquée par l'OPA Quality Gate **avant même l'application du `terraform plan`**.

2.  **Gestion des Exceptions Terraform**
    *   Les exemptions de sécurité **ne doivent pas** être écrites dans ce code via `#checkov:skip`.
    *   Elles doivent être actées par un comité de sécurité via l'enregistrement dans `policies/opa/exceptions.json`. Le code restera "vulnérable" mais sciemment toléré (et tracé).

---

## 🚀 Déploiement CI/CD

Le déploiement est orchestré par le job `tofu-deploy` dans `.gitlab-ci.yml`.
L'infrastructure n'est appliquée (`tofu apply`) **que si, et seulement si**, le stage précédent de décision OPA (`opa-decision`) a émis un `ALLOW`.

```bash
# Exemple standard d'initialisation locale (pour tests dry-run)
cd infra/azure/dev
tofu init
tofu plan
```
