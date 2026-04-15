# CloudSentinel Drift Engine (Shift-Right)

Batch job de détection de dérive (**configuration drift**) entre Terraform (IaC) et l’état réel des ressources Azure.

## Objectif

- Détecter les modifications manuelles ou non trackées (Portal/CLI/SDK) sur des ressources Azure gérées par Terraform
- Produire un rapport standard `drift-report.json` (OCSF-compatible + schéma CloudSentinel)
- Importer les findings dans **DefectDojo** (API v2) via `import-scan`

## Fonctionnement (Option 2 — Scheduled)

Commande cœur:

- `terraform plan -refresh-only -detailed-exitcode`

Codes de sortie du conteneur (CloudSentinel):

- `0` : aucun drift détecté
- `2` : drift détecté
- `1` : erreur (init/plan/API/DefectDojo…)

## Prérequis

- Terraform projet prêt (local state ou backend `azurerm`)
- Auth Azure via variables `ARM_*` (Service Principal) ou Managed Identity
- DefectDojo accessible + `ENGAGEMENT_ID` (obligatoire pour la traçabilité Shift-Right)

## Fichiers clés

- `drift-engine.py` : entrypoint du job
- `config/drift_config.yaml` : configuration (avec interpolation `${ENV}`)
- `templates/drift-report-template.j2` : template JSON du rapport
- `schemas/drift-report-schema.json` : schéma JSON (contrat CloudSentinel)

## Configuration Azure (Terraform)

Service Principal (Client Secret):

- `ARM_CLIENT_ID`
- `ARM_CLIENT_SECRET`
- `ARM_TENANT_ID`
- `ARM_SUBSCRIPTION_ID`

Managed Identity (fallback):

- `ARM_USE_MSI=true`
- `ARM_CLIENT_ID` (optionnel si user-assigned MI)
- `ARM_SUBSCRIPTION_ID` (recommandé)

## DefectDojo (obligatoire)

Variables:

- `DEFECTDOJO_URL`
- `DEFECTDOJO_API_KEY`
- `DOJO_ENGAGEMENT_ID_RIGHT` (ou `DEFECTDOJO_ENGAGEMENT_ID_RIGHT`)

Le moteur utilise `scan_type=Generic Findings Import` et peut fermer les anciens findings via `close_old_findings=true`.

## Construire l’image

Depuis la racine du repo:

```bash
docker build -t cloudsentinel-drift-engine:local shift-right/drift-engine
```

## Exécuter (Docker)

Exemple avec le projet Terraform sample `infra/azure/student-secure`:

```bash
mkdir -p shift-right/drift-engine/output
docker run --rm \
  --env-file shift-right/drift-engine/.env.example \
  -e ARM_CLIENT_ID=... -e ARM_CLIENT_SECRET=... -e ARM_TENANT_ID=... -e ARM_SUBSCRIPTION_ID=... \
  -e DEFECTDOJO_URL=... -e DEFECTDOJO_API_KEY=... -e DOJO_ENGAGEMENT_ID_RIGHT=... \
  -e TF_WORKING_DIR=/work/iac \
  -e TF_DATA_DIR=/tmp/cloudsentinel-tfdata \
  -e TF_LOCKFILE_MODE=readonly \
  -e DRIFT_OUTPUT_PATH=/work/output/drift-report.json \
  -v "$PWD/infra/azure/student-secure:/work/iac:ro" \
  -v "$PWD/shift-right/drift-engine/output:/work/output" \
  cloudsentinel-drift-engine:local
```

Le rapport est écrit dans `shift-right/drift-engine/output/drift-report.json` (ou selon `DRIFT_OUTPUT_PATH`).

## Exécuter (docker-compose)

```bash
cd shift-right/drift-engine
# Optionnel (recommandé): créer un .env pour injecter les variables (ARM_*, DefectDojo, etc.)
cp .env.example .env
# Optionnel: pointer vers un autre projet Terraform que ../../infra/azure/student-secure
# echo "TF_IAC_PATH=/chemin/vers/iac" >> .env
docker compose -f docker-compose.drift.yml up --build --abort-on-container-exit
```

Récupérer le rapport (volume nommé `drift_output`):

```bash
CONTAINER_ID="$(docker ps -a --filter name=drift-engine --format '{{.ID}}' | head -n 1)"
docker cp "${CONTAINER_ID}:/work/output/drift-report.json" ./drift-report.json
```

## Test local (sample IaC)

1) Créer un répertoire Terraform simple (ex: `./tmp-iac/`) avec:

- `main.tf` (exemple minimal)
  - `azurerm_resource_group`
  - `azurerm_storage_account` (ou toute ressource facile à modifier via Portal)

2) Appliquer une première fois:

```bash
cd ./tmp-iac
terraform init
terraform apply
```

3) Modifier manuellement une propriété dans Azure Portal (ex: forcer un paramètre de sécurité).

4) Lancer le Drift Engine avec `TF_WORKING_DIR=./tmp-iac` et vérifier:

- `exit code` = `1`
- `drift.items[].changed_paths` contient les attributs driftés

Exemple d'exécution locale (en indiquant explicitement le fichier de config):

```bash
python shift-right/drift-engine/drift-engine.py --config shift-right/drift-engine/config/drift_config.yaml --tf-dir ./tmp-iac
```

## Tests unitaires (sans Azure/Terraform)

```bash
cd shift-right/drift-engine
python3 -m unittest tests/test_drift_engine.py
```

## Sécurité

- Aucune clé n’est lue depuis des fichiers: uniquement variables d’environnement
- Le logger n’exporte jamais `ARM_CLIENT_SECRET` / `DEFECTDOJO_API_KEY`
- Les rapports n’incluent pas les valeurs *before/after*, uniquement des chemins d’attributs modifiés
