# 🐳 Trivy — Sécurité Conteneurs et Dépendances

> **Vulnerability Scanner** : Identifie les failles de sécurité (CVEs) dans les images Docker, les dépendances OS, et les fichiers d'orchestration avant leur déploiement.

Trivy est le scanner de Tier-3 du pipeline Shift-Left CloudSentinel. Il couvre le spectre non géré par Gitleaks et Checkov, principalement orienté sur la matrice logicielle.

---

## 📐 Architecture du Wrapper (V5.0)

Comme tous les analyseurs CloudSentinel, Trivy est isolé derrière un script (`run-trivy.sh`) garantissant un output JSON robuste et interopérable avec le **Normalizer**.

1.  **Ciblage Dynamique** : Supporte différents types de scan via ses paramètres CLI (`config`, `image`, `fs`, `repository`).
2.  **Output Strict** : Exporte les rapports bruts vers `reports/raw/` et construit un résumé abstrait (`trivy_opa.json`) certifiant son exécution.
3.  **Advisory Focus** : Trivy n'interrompt **jamais** la CI (Exit 0 systématique). Toute la gouvernance sur l'acceptation d'une image avec des failles (ex: `CRITICAL` patchables vs non-patchables) est relayée à la Policy Decision OPA locale.
4.  **Format Unifié** : Le Normalizer convertit automatiquement les niveaux "HIGH" trivy vers l'échelle globale OPA (1-5).

---

## 🛠️ Configuration Principale

Trivy s'appuie sur la base de données AquaSecurity.
Les options de la ligne de commande (Timeout, Ignore-Unfixed, Format) sont imposées dans l'orchestrateur `.gitlab-ci.yml` :
*   `--no-progress` pour éviter de polluer les logs GitLab.
*   `--timeout 5m` pour sécuriser les resources.
*   `--severity HIGH,CRITICAL` (Optionnel) pour soulager la base DefectDojo.

---

## 🚀 Utilisation

**En Mode CI / Local Pipeline :**
```bash
# Scan complet du repository (root) en mode config
bash shift-left/trivy/scripts/run-trivy.sh "." "config"
```

## 🧩 OPA Integration
Actuellement, les CVEs critiques remontées par Trivy dans le `golden_report.json` subissent le même "Quality Gate" via `pipeline_decision.rego` :
- Un finding Trivy `CRITICAL` ajoute un +1 au compteur `effective_critical`.
- Peut faire l'objet d'exceptions OPA structurées (`exceptions.json`) via l'ID de la CVE.
