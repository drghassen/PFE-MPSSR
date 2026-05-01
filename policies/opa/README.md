# CloudSentinel OPA Gate

Ce dossier contient le moteur de décision OPA (PDP) de CloudSentinel.

## Graphe de politiques & PDPs (`architecture/policy_graph.rego`)

Le package `cloudsentinel.architecture` documente **propriété**, **ports**, **chemins de données** et **limites connues** (pas une enforcement runtime sauf requête explicite vers `data.cloudsentinel.architecture.*`).

Points clés validés en revue :

| Sujet | État |
|-------|------|
| Isolation gate / drift | Deux packages distincts ; **aucune** référence Rego croisée entre `policies/opa/gate` et `policies/opa/drift` (vérifié par `ci/scripts/verify-opa-architecture.sh`). |
| Serveurs OPA | **8181** = gate + `exceptions.json` ; **8182** = drift + `drift_exceptions.json` ; même `system/authz.rego`, jetons distincts possibles via le même fichier config. En local docker-compose: `config/opa/data/*`. En CI: `.cloudsentinel/*`. |
| Divergence sémantique gate vs drift | **Volontaire** : le gate applique des seuils scanners / qualité ; le drift classe des `changed_paths` Terraform. Il n’existe pas aujourd’hui d’invariant automatique « gate severity ≥ drift » — à traiter au niveau produit / couche partagée si requis. |
| Exceptions dupliquées | `data.cloudsentinel.exceptions` vs `data.cloudsentinel.drift_exceptions` — **deux cycles de vie** ; consolidation « core » = chantier P0 futur. |
| Tests | CI exécute des **scopes séparés** (gate, drift, system) via `verify-opa-architecture.sh` pour éviter la confusion « un seul `opa test` = une seule vérité métier ». |

## Modules `drift/` (`package cloudsentinel.shiftright.drift`)

| Fichier | Contenu |
|---------|---------|
| `drift_context.rego` | Defaults fail-safe (`violations` / `compliant` vides) |
| `drift_deny.rego` | `deny` (mode dégradé, champs requis, hygiène exceptions) |
| `drift_lists.rego` | `violations`, `compliant` |
| `drift_evaluate.rego` | `evaluate_drift`, `_malformed_finding_decision` |
| `drift_severity.rego` | `determine_severity`, règles `is_*_drift` |
| `drift_action.rego` | `determine_action` |
| `drift_custodian.rego` | `get_custodian_policy` |
| `drift_reason.rego` | `build_reason` |
| `drift_exceptions_store.rego` | `_drift_exceptions_store` ← `data.cloudsentinel.drift_exceptions` |
| `drift_exceptions_fields.rego` | Wildcards, scopes, `valid_drift_exception` |
| `drift_exceptions_match.rego` | Matching, `effective_violations`, métriques |

Le serveur OPA shift-right (`opa-server-shiftright`) et `ci/scripts/opa-drift-decision.sh` chargent le répertoire `policies/opa/drift` (tous les `.rego` du même package). Les tests Rego restent dans `drift_decision_test.rego` à la racine `policies/opa/`.

Par défaut, les services OPA docker-compose démarrent **sans `--watch`** pour éviter les erreurs transitoires de compilation pendant les sauvegardes éditeur (fichiers momentanément vides). Pour préparer les data files compose, utiliser:

```bash
make opa-compose-bootstrap
make opa-up
make opa-up-shiftright
```

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

CI et `make opa-test` exécutent `bash ci/scripts/verify-opa-architecture.sh` (garde croisée gate/drift + `opa check` + tests par scope). En local :

```bash
make opa-test              # DB_PORTS + verify-opa-architecture (recommandé)
make opa-test-gate         # gate uniquement
make opa-test-drift        # drift uniquement
make opa-test-system       # system.authz uniquement
python3 -m unittest shift-left/opa/tests/test_fetch_exceptions.py
```
