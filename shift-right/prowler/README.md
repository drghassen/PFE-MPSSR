# Prowler Azure (Local)

Ce module permet d'exécuter un scan **runtime Azure** en local avec Prowler, sans CI.

## Objectif

- Vérifier rapidement la posture cloud réelle (shift-right) depuis ton poste.
- Générer des rapports structurés (CSV / JSON-OCSF / HTML) dans `.cloudsentinel/prowler/output`.

## Prérequis

1. `prowler` installé (recommandé officiel: `pipx install prowler`).
2. `az` CLI installé.
3. Permissions Azure minimales:
   - `Reader` au scope subscription (minimum recommandé).
   - `ProwlerRole` uniquement si tu veux des checks avancés spécifiques (optionnel selon contrôles).

Références officielles:
- https://docs.prowler.com/getting-started/installation/prowler-cli
- https://docs.prowler.com/user-guide/providers/azure/getting-started-azure
- https://docs.prowler.com/user-guide/providers/azure/authentication

## Authentification supportée

### 1) Azure CLI (par défaut)

```bash
az login
az account set --subscription <subscription-id>
bash shift-right/prowler/run-prowler-azure.sh
```

### 2) Service Principal (env vars)

```bash
export PROWLER_AZURE_AUTH_MODE=sp-env
export PROWLER_AZURE_SUBSCRIPTION_ID="<subscription-id>"
export AZURE_CLIENT_ID="<client-id>"
export AZURE_TENANT_ID="<tenant-id>"
export AZURE_CLIENT_SECRET="<client-secret>"
bash shift-right/prowler/run-prowler-azure.sh
```

## Variables utiles

- `PROWLER_AZURE_AUTH_MODE`: `az-cli` (default) ou `sp-env`
- `PROWLER_AZURE_SUBSCRIPTION_ID`: override explicite du subscription scope
- `PROWLER_OUTPUT_DIR`: dossier de sortie (default: `.cloudsentinel/prowler/output`)
- `PROWLER_OUTPUT_FORMATS`: formats de sortie (default: `csv json-ocsf html`)
- `PROWLER_IGNORE_EXIT_CODE_3`: `true` (default, advisory local) ou `false` (strict, échoue si findings FAIL)

## Commande Make

```bash
make prowler-azure-local
```
