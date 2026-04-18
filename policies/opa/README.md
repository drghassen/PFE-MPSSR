# CloudSentinel OPA Gate

Ce dossier contient le moteur de décision OPA (PDP) de CloudSentinel.

## Modules `gate/` (`package cloudsentinel.gate`)

| Fichier | Contenu |
|---------|---------|
| `gate_context.rego` | Seuils, `metadata`, `failed_findings`, `db_ports` |
| `gate_helpers.rego` | `normalize_path`, `to_bool` |
| `gate_findings.rego` | Accesseurs `finding_*` |
| `gate_exceptions_fields.rego` | Accesseurs `exception_*`, scopes, TTL |
| `gate_exceptions_validate.rego` | `valid_exception_definition`, ensembles d’IDs |
| `gate_exceptions_match.rego` | Matching, effectifs, métriques, `scanner_not_run` |
| `gate_deny.rego` | Règles `deny` (seuils, scanners, gouvernance exceptions) |
| `gate_deny_intent.rego` | Règles intent non contournables |
| `gate_decision.rego` | `allow`, `decision` |

## Rôle dans le pipeline

1. Scanners (`gitleaks`, `checkov`, `trivy`) produisent des rapports.
2. `normalize.py` génère `golden_report.json`.
3. `fetch-exceptions.py` construit `.cloudsentinel/exceptions.json` (modèle enterprise v2).
4. `run-opa.sh` charge tous les `gate/*.rego` (même package).
5. CI fait l’enforcement (`--enforce`) ; local reste advisory (`--advisory`).

## Moteur d’exceptions enterprise

Le modèle v2 impose:

- `exception_id` (UUID), `scanner`, `rule_id`, `resource_id`
- `fingerprint`/`resource_hash` (matching prioritaire)
- `repo`, `branch_scope`, `scope_type` (`commit|branch|repo|global`)
- `severity`, `break_glass`, `approved_by_role`
- `requested_by`, `approved_by`, `justification`
- `created_at`, `expires_at`, `schema_version`

Schéma JSON: [shift-left/opa/schema/exceptions_v2.schema.json](/home/ghassen/pfe-cloud-sentinel/shift-left/opa/schema/exceptions_v2.schema.json)

## Logique de matching (OPA)

Ordre strict:

1. `fingerprint_exact`
2. `resource_id + rule_id + repo`
3. `scope_controlled` (commit/branch/repo/global avec restrictions)

Le matching basé uniquement sur fichier n’est pas autorisé en mode v2.

## Gouvernance sécurité

- Four-Eyes: `approved_by != requested_by`
- Break-glass:
  - `incident_id` obligatoire
  - TTL max 7 jours
  - rôle approbateur `APPSEC_L3+`
- Scope `global` réservé aux rôles AppSec autorisés
- Expiration automatique: exception expirée ignorée
- Compatibilité legacy temporaire via `legacy_compatibility.sunset_date`

## Audit et métriques

OPA expose:

- `exceptions.applied_audit[]` avec `exception_id`, `scope_type`, `commit_sha`, `matching_method`
- métriques de gouvernance:
  - exceptions actives par sévérité
  - break-glass actifs
  - exceptions expirées
  - temps moyen d’approbation

`run-opa.sh` écrit aussi des événements JSONL (`.cloudsentinel/decision_audit_events.jsonl`) pour l’audit de décision.

## Tests

```bash
opa test policies/opa -v
python3 -m unittest shift-left/opa/tests/test_fetch_exceptions.py
```
