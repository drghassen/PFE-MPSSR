# CloudSentinel

> Gouvernance securite cloud enterprise: shift-left, shift-right, exceptions et remediation runtime.

CloudSentinel separe explicitement detection, normalisation, decision et enforcement:

- Shift-left: Gitleaks, Checkov, Trivy et cloud-init scanner produisent des artefacts bruts.
- Normalizer: genere le Golden Report `.cloudsentinel/golden_report.json`.
- OPA: prend la decision centralisee via les packages `gate`, `drift`, `prowler` et `system.authz`.
- Shift-right: Drift Engine, Prowler, DefectDojo, Cloud Custodian, verification et ticket de reconciliation.

## Arborescence Reelle

```text
pfe-cloud-sentinel/
├── .gitlab-ci.yml                  # Includes shift-left et shift-right schedule
├── .gitlab-ci-image-factory.yml    # Build des images outillees
├── Makefile                        # Commandes locales alignees sur le depot
├── .env.template                   # Variables locales non secretes a copier vers .env
├── ci/
│   ├── pipelines/                  # Pipelines GitLab shift-left / shift-right
│   ├── scripts/                    # PEP CI, HMAC, upload, remediation, verification
│   ├── contracts/                  # Contrats d'integrite et d'artefacts
│   └── images/                     # Images pinnees par digest
├── config/
│   ├── opa/data/                   # Data OPA local/docker-compose
│   ├── prowler/                    # Mutelist / exclusions runtime
│   └── remediation-capabilities.json
├── infra/azure/
│   ├── envs/dev/                   # Environnement Terraform principal
│   └── modules/                    # Modules Azure reutilisables
├── observability/                  # Prometheus/Grafana/exporter local
├── policies/opa/                   # Rego: gate, drift, prowler, authz
├── shift-left/                     # Scanners, normalizer, fetch exceptions
├── shift-right/                    # Drift Engine, Prowler, Custodian
└── verification/                   # Verification post-remediation
```

## Commandes Utiles

```bash
cp .env.template .env
make opa-test
make test-python
make scan
make drift-detect
make dashboard-start
```

`DefectDojo` est traite comme service externe par defaut. Les jobs CI et scripts locaux utilisent `DOJO_URL`, `DOJO_API_KEY` et les IDs d'engagement declares dans `.env` ou dans les variables GitLab CI/CD.

## Documentation Par Domaine

- Shift-left: [shift-left/README.md](../shift-left/README.md)
- Normalizer: [shift-left/normalizer/README.md](../shift-left/normalizer/README.md)
- OPA: [policies/opa/README.md](../policies/opa/README.md)
- CI/CD et images: [ci/README.md](../ci/README.md)
- Drift Engine: [shift-right/drift-engine/README.md](../shift-right/drift-engine/README.md)
- Shift-right runtime: [shift-right/README.md](../shift-right/README.md)
- Analyse scanners: [docs/SHIFT_LEFT_SCANNERS_DEEP_ANALYSIS.md](SHIFT_LEFT_SCANNERS_DEEP_ANALYSIS.md)

## Contrats A Respecter

- Un scanner ne bloque pas directement une pipeline.
- Le normalizer ne prend pas de decision: `quality_gate.decision` reste `NOT_EVALUATED`.
- OPA est le PDP unique pour les decisions ALLOW/DENY et L0-L3.
- Custodian execute uniquement les remediations autorisees par OPA.
- DefectDojo reste le systeme d'audit et de gouvernance des exceptions.
