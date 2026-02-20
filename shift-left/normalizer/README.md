# CloudSentinel Normalizer

Ce composant est le moteur de fusion et de normalisation du framework CloudSentinel. Il agrège les résultats des différents scanners de sécurité pour produire un rapport unique ("Golden Report") exploitable par OPA.

## Fonctionnement

Le script `normalize.sh` effectue les étapes suivantes :
1. **Extraction Git** : Récupère le contexte (branche, commit, auteur).
2. **Collecte des rapports** : Lit les fichiers JSON de Gitleaks, Checkov et Trivy.
3. **Résilience** : Si un rapport est absent, il est remplacé par un état `NOT_RUN`.
4. **Moteur JQ** :
   - Normalise le format des vulnérabilités.
   - Injecte les SLAs de remédiation basés sur la sévérité.
   - Génère des fingerprints pour la déduplication.
   - Calcule les statistiques globales et par outil.
5. **Quality Gate** : Évalue le rapport par rapport aux seuils définis (ex: 0 CRITICAL autorisé).

## Usage

```bash
# Rendre le script exécutable
chmod +x shift-left/normalizer/normalize.sh

# Exécuter la normalisation
./shift-left/normalizer/normalize.sh
```

## Structure du Rapport Final

Le rapport est généré dans `.cloudsentinel/golden_report.json`.

- `metadata` : Infos sur la génération et le contexte Git.
- `summary` : Vue d'ensemble des vulnérabilités.
- `scanners` : Détails bruts par outil.
- `findings` : Liste consolidée et normalisée de toutes les failles.
- `quality_gate` : Décision finale (PASSED/FAILED).

## Validation

Le rapport suit le schéma JSON défini dans `schema/cloudsentinel_report.schema.json`.
