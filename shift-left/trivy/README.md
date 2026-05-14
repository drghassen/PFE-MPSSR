# Trivy - Vulnerability/SCA Scanner

Trivy est limite volontairement aux vulnerabilites/SCA CloudSentinel: packages OS et bibliotheques applicatives.

Ownership non negociable:
- Secrets: Gitleaks.
- IaC/config: Checkov.
- Vulnerabilites packages/images: Trivy.

---

## Architecture

Comme les autres analyseurs CloudSentinel, Trivy est isole derriere `run-trivy.sh`. Le scanner produit des rapports JSON bruts; le normalizer construit le `golden_report.json`; OPA reste le seul point de decision ALLOW/DENY.

Modes supportes:
- `fs`: scan SCA/vulnerabilites du repository.
- `image`: scan vulnerabilites d'image conteneur.

Le mode `config` est desactive par design. Il ne doit pas etre utilise pour scanner Dockerfile/IaC, car ce scope appartient a Checkov.

## Configuration Effective

- `shift-left/trivy/configs/trivy.yaml`: local/advisory.
- `shift-left/trivy/configs/trivy-ci.yaml`: CI.
- Les deux configs declarent `scan.scanners: [vuln]`.
- Les wrappers imposent aussi `--scanners vuln`.
- `.trivy-cache` est partage avec le job `trivy-db-warm`.
- `TRIVY_DB_REPOSITORIES` permet le fallback DB (`ghcr.io`, puis mirror GCR par defaut).
- `exit-code: 0` garde Trivy advisory; seuls les problemes techniques `rc > 1` stoppent le job de detection.

---

## Utilisation

```bash
# Repository SCA/vulnerabilites uniquement
bash shift-left/trivy/scripts/run-trivy.sh "." "fs"

# Image conteneur, vulnerabilites uniquement
bash shift-left/trivy/scripts/run-trivy.sh "alpine:3.18" "image"
```

## OPA Integration

Les CVE remontees par Trivy sont normalisees dans `golden_report.json` avec `finding_type=vulnerability`. Trivy ne bloque pas directement le pipeline; OPA applique les seuils, exceptions et decisions d'enforcement.
