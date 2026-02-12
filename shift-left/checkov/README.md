# Checkov Security Component

## Overview
Checkov est un outil d'analyse statique pour l'Infrastructure as Code (IaC). Il scanne les fichiers Terraform pour y détecter des erreurs de configuration de sécurité.

## Utilisation Locale
Pour lancer un scan manuel :
```bash
checkov -d . --config-file shift-left/checkov/.checkov.yml
```

## Configuration
Le fichier de configuration [.checkov.yml](./.checkov.yml) définit les règles de scan.
Une attention particulière est portée aux standards CIS Benchmarks pour Azure.
