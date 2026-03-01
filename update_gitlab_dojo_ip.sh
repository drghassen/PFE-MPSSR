#!/bin/bash
# ==============================================================================
# Script: update_gitlab_dojo_ip.sh
# Rôle: Synchronise l'IP WSL dynamique avec les variables CI/CD GitLab
# ==============================================================================

set -e 

# 1. Configuration 
GITLAB_URL="https://gitlab.com" 
PROJECT_ID="79737879"     # ID extrait des logs : drghassen/pfe-cloud-sentinel
VAR_NAME="DOJO_URL"       # Nom attendu par le pipeline
PORT="8080"               

TOKEN_FILE="$HOME/.secrets/gitlab_dojo_token"

if [ ! -f "$TOKEN_FILE" ]; then
    echo "[Dojo-Sync] ❌ ERREUR : Fichier token introuvable ($TOKEN_FILE)"
    exit 1
fi

GITLAB_TOKEN=$(cat "$TOKEN_FILE")

# 2. Récupération de l'IP dynamique de WSL
WSL_IP=$(ip addr show eth0 | awk '/inet / {print $2}' | cut -d/ -f1 | head -n 1)

if [ -z "$WSL_IP" ]; then
    echo "[Dojo-Sync] ❌ ERREUR : Impossible de détecter l'IP WSL."
    exit 1
fi

NEW_URL="http://${WSL_IP}:${PORT}"

echo "[Dojo-Sync] Tentative de mise à jour de $VAR_NAME vers $NEW_URL..."

# 3. Requête API GitLab
# a. PUT
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --request PUT \
  --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  --form "value=$NEW_URL" \
  "$GITLAB_URL/api/v4/projects/$PROJECT_ID/variables/$VAR_NAME")

# b. POST si 404
if [ "$HTTP_STATUS" -eq 404 ]; then
    echo "[Dojo-Sync] Variable absente, création en cours..."
    HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --request POST \
      --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
      --form "key=$VAR_NAME" \
      --form "value=$NEW_URL" \
      --form "protected=false" \
      --form "masked=false" \
      "$GITLAB_URL/api/v4/projects/$PROJECT_ID/variables")
fi

# 4. Bilan
if [ "$HTTP_STATUS" -ge 200 ] && [ "$HTTP_STATUS" -lt 300 ]; then
    echo "[Dojo-Sync] ✅ OK : GitLab CI pointé vers $NEW_URL (Code $HTTP_STATUS)"
else
    echo "[Dojo-Sync] ❌ ÉCHEC : Erreur API GitLab (Code HTTP $HTTP_STATUS)"
    curl -s --header "PRIVATE-TOKEN: $GITLAB_TOKEN" "$GITLAB_URL/api/v4/projects/$PROJECT_ID/variables/$VAR_NAME"
fi
