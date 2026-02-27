# CloudSentinel Normalizer

Ce composant consolide les sorties de Gitleaks, Checkov et Trivy dans un Golden Report unique, consommable par OPA.

## Role

Le script `normalize.sh`:
1. Lit les 3 rapports scanner dans `.cloudsentinel/`.
2. Injecte un etat `NOT_RUN` si un rapport manque ou est invalide.
3. Normalise chaque finding vers un schema unique (severity, category, resource, fingerprint).
4. Genere les sections `summary`, `scanners`, `findings`, `quality_gate`.
5. Ajoute la tracabilite des sources (`metadata.normalizer.source_reports`) et la provenance des findings (`context.traceability`).

## Usage

```bash
bash shift-left/normalizer/normalize.sh
```

## Output

Le fichier final est:
- `.cloudsentinel/golden_report.json`

Sections principales:
- `metadata`: contexte git/execution + provenance des rapports source
- `scanners`: etat et erreurs par scanner
- `findings`: findings normalises et enrichis
- `summary`: agregation globale, par outil et par categorie
- `quality_gate`: seuils transmis a OPA (OPA reste le seul decisionnaire)

## Modes

- `CLOUDSENTINEL_EXECUTION_MODE=ci`
- `CLOUDSENTINEL_EXECUTION_MODE=local`
- `CLOUDSENTINEL_EXECUTION_MODE=advisory`

`CLOUDSENTINEL_LOCAL_FAST=true` permet d ignorer Checkov/Trivy en local pour un feedback rapide.
`CLOUDSENTINEL_SCHEMA_STRICT=true` force la validation schema (echoue si python/jsonschema indisponible).

## Schema

Le contrat est defini dans:
- `shift-left/normalizer/schema/cloudsentinel_report.schema.json`

Le smoke test dedie:
```bash
make normalizer-test
```
