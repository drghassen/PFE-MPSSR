# 🧠 Normalizer (Data Transformation Engine)

> **Rôle** : L’Extract-Transform-Load (ETL) de la sécurité. Convertit le chaos des rapports scanners en un **Golden Report** standardisé pour OPA.

## 📐 Pourquoi Normaliser ?

Gitleaks, Checkov, et Trivy ont des formats JSON incompatibles :
*   Les niveaux de sévérité diffèrent (`high`, `HIGH`, `SEV4`, `Severity: 4`).
*   Les chemins de fichiers sont relatifs ou absolus.
*   Certains n'ont pas d'identifiants uniques stables (Fingerprints).

Le script `normalize.sh` **uniformise tout** à travers le schéma défini dans `schema/cloudsentinel_report.schema.json`.

---

## 🛠️ Composant Technique : `normalize.sh` (v5.0)

C'est un script Bash massif (600+ lignes) ultra-optimisé exploitant `jq` pour des performances maximales. Il réalise 5 tâches critiques :

1.  **Traçabilité (Traceability)** :
    *   Hache chaque rapport source via SHA256.
    *   Injecte les métadonnées Git (Commit, Branche, Auteur, Timestamp).
2.  **Lookup Tables (LUT)** :
    *   Conversion stricte des sévérités : Tout ce qui ressemble à `CRITICAL`, `SEV5`, ou `VERY_HIGH` devient `CRITICAL`.
3.  **Fingerprinting Stable** :
    *   Crée un `fingerprint` base64 robuste (ex: `Checkov_ID + path + ligne`) pour la déduplication et l'application des exceptions OPA.
4.  **Local-Fast Mode** :
    *   S'il reçoit `CLOUDSENTINEL_LOCAL_FAST=true` (Pre-commit hook), il ignore silencieusement Checkov et Trivy (qui sont lents) pour ne produire que les résultats Gitleaks sans faire planter la chaîne.
5.  **Délégation OPA** :
    *   Il compile les statistiques mais **ne prend aucune décision**.
    *   Il encode formellement : `"quality_gate": { "decision": "NOT_EVALUATED", "reason": "evaluation-performed-by-opa-only" }`.

---

## 📜 Contrat avec OPA (`CONTRACT.md`)

Le Normalizer est fortement couplé (par data-contract) à la `pipeline_decision.rego`.
Voir le détail de l'architecture de la charge utile (Payload) dans [CONTRACT.md](CONTRACT.md).

## 🚀 Exécution

**Dépendances** : `bash`, `jq`, `git`, (optionnel: `python` pour lint JSON Schema).

```bash
# Génère '.cloudsentinel/golden_report.json'
bash shift-left/normalizer/normalize.sh

# (Optionnel) Vérification stricte via JSONSchema
export CLOUDSENTINEL_SCHEMA_STRICT=true
bash shift-left/normalizer/normalize.sh
```

---

## 📊 Structure du Golden Report (Aperçu)

```json
{
  "schema_version": "1.1.0",
  "metadata": { ... traçabilité git & environnement ... },
  "scanners": {
     "gitleaks": { "status": "FAILED", "stats": {...} },
     "checkov":  { "status": "NOT_RUN", "stats": {...} }
  },
  "findings": [
    {
      "id": "CS-gitleaks-aws-access-key-id",
      "severity": { "level": "CRITICAL" },
      "category": "SECRETS",
      "status": "FAILED",
      "context": { "deduplication": { "fingerprint": "..." } }
    }
  ],
  "summary": { ... compteurs globaux ... },
  "quality_gate": { "decision": "NOT_EVALUATED" }
}
```
