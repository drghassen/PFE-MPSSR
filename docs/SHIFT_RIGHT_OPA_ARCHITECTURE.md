# Architecture Shift-Right : OPA comme Point de Décision

## Contexte
CloudSentinel implémente une approche "shift-left + shift-right". Le Shift-Right détecte les dérives entre l'état Terraform et l'infrastructure Azure réelle.

## Problème Initial
Le Drift Engine utilisait un dictionnaire Python hardcodé (`_SEVERITY_MAP`) pour classifier la sévérité des drifts, violant le principe architectural "OPA = unique point de décision".

## Solution Implémentée
Intégration complète d'OPA comme moteur de décision pour le Shift-Right, aligné avec l'architecture Shift-Left existante.

[... détails techniques ...]
