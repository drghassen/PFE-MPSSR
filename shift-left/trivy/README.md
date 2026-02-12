# Trivy Security Component

## Overview
Trivy est un scanner de sécurité polyvalent. Il est utilisé ici pour détecter :
1. Les vulnérabilités logicielle (CVE) dans le code source et les images Docker.
2. Les erreurs de configuration IaC (Terraform).
3. Les secrets exposés.

## Utilisation Locale
Pour scanner le système de fichiers :
```bash
trivy fs . --config shift-left/trivy/trivy.yaml
```

Pour scanner une image Docker (futur) :
```bash
trivy image <votre_image>
```

## Configuration
Le fichier [trivy.yaml](./trivy.yaml) définit les niveaux de sévérité et les types de scan activés.
