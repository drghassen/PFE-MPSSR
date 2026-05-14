# CloudSentinel - Rapport d'analyse approfondie des scanners Shift-Left

Date d'analyse: 2026-05-14  
Perimetre: `shift-left/`, `ci/scripts/shift-left/`, `ci/pipelines/shift-left.yml`, `policies/opa/gate/`, `ci/contracts/artifact_contract.json`

## 1. Synthese executive

CloudSentinel implemente une architecture Shift-Left mature autour de quatre scanners de detection:

1. Gitleaks: detection de secrets dans le code et l'historique Git.
2. Checkov: detection de mauvaises configurations IaC Terraform/Kubernetes.
3. Trivy: detection SCA/vulnerabilites, Dockerfile misconfiguration et secrets d'image.
4. Cloud-init scanner: analyse statique specifique CloudSentinel des bootstraps VM et de l'intention runtime.

Le point fort principal est la separation nette entre detection, normalisation, decision et enforcement. Les scanners produisent des rapports bruts, le normalizer genere un `golden_report.json`, puis OPA est l'unique PDP/PEP de decision via `run-opa.sh`. C'est conforme a une architecture DevSecOps entreprise: les outils de scan restent advisory, les exceptions passent par un modele gouverne, et les artefacts critiques sont signes par HMAC en CI.

Le point faible principal est l'ecart entre certaines documentations et l'implementation actuelle, surtout autour de Gitleaks et Checkov. Le README Gitleaks parle encore d'un scan CI `--no-git`, alors que le script scanne volontairement l'historique complet. Le README Checkov parle d'un filtrage des checks dans `run-checkov.sh`, alors que le wrapper conserve aujourd'hui le JSON brut et laisse la normalisation/OPA gerer le signal. Ces ecarts ne cassent pas le pipeline, mais ils augmentent le risque d'erreur d'exploitation et d'audit.

## 2. Architecture observee

### 2.1 Flux technique

Le pipeline GitLab `ci/pipelines/shift-left.yml` suit ce modele:

1. Guard:
   - `policies-immutability`
   - `trivy-db-warm`
2. Scan:
   - `gitleaks-scan`
   - `checkov-scan`
   - `trivy-fs-scan`
   - `trivy-config-scan`
   - `cloudinit-scan`
3. Normalize:
   - `normalize-reports`
4. Contract:
   - `contract-test`
   - `opa-unit-tests`
5. Decide:
   - `opa-decision`
6. Report / Deploy:
   - upload DefectDojo
   - deploy infrastructure si OPA autorise

Le flux respecte le pattern enterprise:

```text
Scanners bruts -> Contract metadata + HMAC -> Normalizer -> Golden Report -> OPA -> Decision -> Deploy/Report
```

### 2.2 Separation des responsabilites

| Couche | Composants | Responsabilite |
|---|---|---|
| Detection | Gitleaks, Checkov, Trivy, cloudinit-scanner | Produire des signaux techniques bruts |
| Normalisation | `shift-left/normalizer/normalize.py` | Convertir les rapports heterogenes en schema commun |
| Decision | `policies/opa/gate/*.rego` | Calculer ALLOW/DENY/WARN, exceptions, seuils, intent rules |
| Enforcement | `shift-left/opa/run-opa.sh`, `ci/scripts/shift-left/opa-decision.sh` | Bloquer ou autoriser selon la decision OPA |
| Audit | HMAC, JSONL, DefectDojo | Tracabilite et preuve d'integrite |

Cette separation est saine. Aucun scanner ne devrait porter une logique metier de blocage. Le repo respecte majoritairement ce principe.

## 3. Scanner 1 - Gitleaks

### 3.1 Role

Gitleaks couvre la detection de secrets:

- secrets cloud AWS/GCP/Azure;
- tokens GitHub/GitLab/Azure DevOps;
- cles privees;
- SAS tokens Azure;
- chaines de connexion Azure Storage et Cosmos DB;
- secrets detectes par les regles upstream Gitleaks.

### 3.2 Configuration

Fichier principal: `shift-left/gitleaks/gitleaks.toml`

Caracteristiques importantes:

- Mode hybride: `[extend] useDefault = true`.
- Regles custom CloudSentinel orientees cloud.
- Severites explicites sur les regles custom.
- Allowlist par chemins et regex.
- Exclusion de fichiers binaires, lock files, outputs de scans et fixtures auditees.
- Commentaires ADR indiquant la decision de conserver les defaults upstream.

Ce design reduit le risque de blind spot. Les regles upstream couvrent l'evolution generale des formats de secrets, tandis que les regles CloudSentinel renforcent les cas Azure et SCM.

### 3.3 Logique d'execution

Wrapper local/CI: `shift-left/gitleaks/run-gitleaks.sh`  
Wrapper CI: `ci/scripts/shift-left/gitleaks-scan.sh`

Le script:

- force `git safe.directory` en CI pour eviter le probleme Git `dubious ownership`;
- impose `--redact`;
- produit `.cloudsentinel/gitleaks_raw.json`;
- verifie que le JSON est un tableau;
- enrichit chaque finding avec `CloudSentinelSecretHash` et `SecretHash`;
- utilise un hash stable base sur le secret si disponible, sinon sur la localisation;
- lance en CI un scan range secondaire `gitleaks_range_raw.json`;
- fusionne le range dans le rapport principal avec deduplication par `RuleID:File:StartLine:SecretHash`;
- signe l'artefact par HMAC si `CLOUDSENTINEL_HMAC_SECRET` est present.

### 3.4 Modes

| Mode | Commande effective | Objectif |
|---|---|---|
| Local repo | `gitleaks detect --source <repo>` | Audit complet local |
| Local staged | `gitleaks protect --staged` | Pre-commit advisory |
| CI principal | `gitleaks detect --source <repo>` | Scan complet avec historique Git |
| CI range | `gitleaks detect --log-opts <range>` | Enrichissement commit/auteur/date |

Point important: le code actuel scanne l'historique Git en CI. Le commentaire du script indique explicitement que `--no-git` est volontairement absent pour ne pas perdre les secrets supprimes d'anciens commits. C'est plus strict que la documentation README actuelle.

### 3.5 Normalisation

Le normalizer:

- accepte un rapport Gitleaks tableau ou objet legacy;
- convertit chaque finding en `finding_type=secret`;
- applique la severite issue de la config ou `HIGH` par defaut;
- propage `secret_hash`;
- enrichit `in_latest_push` depuis le scan range;
- considere les findings historiques hors latest push comme advisory via metadata, selon la logique OPA.

### 3.6 Points forts

- `--redact` systematique: pas de secret clair dans les artefacts.
- Hash stable redacted-safe: permet deduplication et exception sans exposer le secret.
- Scan historique CI: bon niveau de securite pour detecter les secrets supprimes mais encore presents dans Git.
- Gestion du range Git: utile pour differencier dette historique et introduction recente.
- Gouvernance `.gitleaksignore`: format `fingerprint:ticket:expiry:justification` et blocage si expiration depassee.
- HMAC des rapports: bonne protection contre substitution d'artefact.

### 3.7 Points faibles et risques

| Risque | Niveau | Analyse |
|---|---:|---|
| Documentation obsolete sur `--no-git` | Moyen | Le README indique que le scan CI principal utilise `--no-git`, ce qui contredit le script. En audit, cela peut creer une mauvaise comprehension du perimetre. |
| `USE_BASELINE` exporte mais non utilise | Faible/Moyen | Le pre-commit exporte `USE_BASELINE=true`, mais le wrapper Gitleaks ne lit pas cette variable. Cela donne une fausse impression de baseline active. |
| Allowlist large sur certains historiques/tests | Moyen | Certaines exclusions historiques sont justifiees, mais leur accumulation doit etre auditee regulierement. |
| Hash fallback par localisation | Moyen | Si le secret est redacte, le hash derive de la position. Un deplacement de ligne change l'identite du finding. |
| Dependance a Git history complet | Moyen | CI force `GIT_DEPTH=0` pour le job, ce qui est correct mais couteux sur de gros repos. |

### 3.8 Best practices recommandees

1. Corriger le README Gitleaks pour refleter le scan historique reel.
2. Supprimer ou implementer clairement `USE_BASELINE`.
3. Ajouter un test de gouvernance `.gitleaksignore` dans CI.
4. Produire un rapport mensuel des allowlists et commits exclus.
5. Conserver `--redact` comme invariant non negociable.
6. Garder Gitleaks advisory: OPA doit rester seul responsable du blocage.

## 4. Scanner 2 - Checkov

### 4.1 Role

Checkov couvre la securite IaC:

- Terraform Azure;
- Kubernetes selon configuration;
- policies built-in Checkov;
- 35 policies custom CloudSentinel Azure;
- categories: storage, identity, database, network, compute, logging, security, appservice, IAM.

### 4.2 Configuration

Fichiers principaux:

- `shift-left/checkov/.checkov.yml`
- `shift-left/checkov/policies/mapping.json`
- `shift-left/checkov/policies/azure/**`

La config Checkov:

- restreint les frameworks a `terraform` et `kubernetes`;
- force `output: json`, `quiet: true`, `compact: true`;
- active `soft-fail: true`;
- desactive `download-external-modules`;
- exclut les controles Docker pour eviter le chevauchement avec Trivy;
- documente des skip-checks justifies par contexte lab/student ou faux positifs.

### 4.3 Policies custom

Le repo contient 35 controles custom:

- Storage: public access, HTTPS only, CMK, TLS minimum.
- Identity/Key Vault: purge protection, soft delete, RBAC, expiration keys/secrets, role Owner/Contributor.
- Network: NSG flow logs, deny-all, RDP/SSH restricted.
- Compute: VM disk encryption, agent, managed disks.
- Database: SQL auditing/encryption/threat protection, MySQL/PostgreSQL SSL, backups, versions, no public access.
- Logging/Security/AppService: diagnostic settings, Defender, HTTPS/TLS/VNet/identity.

Ces policies combinent YAML et Python. Les checks Python sont utiles pour des controles plus expressifs, mais augmentent le cout de maintenance.

### 4.4 Logique d'execution

Wrapper: `shift-left/checkov/run-checkov.sh`  
Wrapper CI: `ci/scripts/shift-left/checkov-scan.sh`

Le script:

- verifie `checkov`, `jq`, `.checkov.yml`, policies custom;
- cible par defaut tout le repo (`.` en CI);
- charge les external checks via `--external-checks-dir`;
- applique `CHECKOV_SKIP_PATHS` si fourni;
- capture stdout dans `.cloudsentinel/checkov_raw.json`;
- capture stderr dans `.cloudsentinel/checkov_scan.log`;
- traite `rc >= 2` comme erreur technique;
- accepte `rc 0/1` comme scan execute;
- valide la structure JSON `object.results`;
- log les parsing errors sans les bloquer directement.

### 4.5 Normalisation

Le normalizer:

- lit `.cloudsentinel/checkov_raw.json`;
- extrait `results.failed_checks`;
- mappe severite/categorie depuis `mapping.json`;
- fallback severite `MEDIUM`;
- cree des findings `finding_type=misconfig`;
- preserve guideline/reference si presente.

### 4.6 Points forts

- Bon cadrage IaC: Docker exclu, Terraform/Kubernetes uniquement.
- Custom policies CloudSentinel bien categorisees.
- `mapping.json` separe la severite metier de l'ID Checkov.
- `soft-fail: true`: evite que Checkov devienne PEP.
- Pas de `--skip-check` CLI additionnel: le commentaire evite une erreur subtile ou la CLI remplace la liste de config.
- Detection de parsing errors.
- HMAC en CI.

### 4.7 Points faibles et risques

| Risque | Niveau | Analyse |
|---|---:|---|
| README inexact sur filtrage | Moyen | La doc dit que seuls `CKV2_CS_AZ_*`, `CKV_AZURE_*`, `CKV_K8S_*` sont conserves dans `run-checkov.sh`. Le script ne filtre pas. |
| `#checkov:skip` non interdit techniquement | Eleve | La README l'interdit, mais rien dans le wrapper ne bloque explicitement les suppressions inline dans Terraform. |
| Skip-checks dans `.checkov.yml` nombreux | Moyen | Certains skips sont legitimes, mais ils representent des decisions de risque permanentes hors DefectDojo/OPA. |
| Parsing errors seulement warning | Moyen | Un parsing error peut masquer des ressources non analysees. En CI enforcement, cela devrait devenir un signal OPA ou contract fail selon criticite. |
| External modules non telecharges | Moyen | Bon pour supply chain, mais peut reduire la couverture si la securite depend de modules distants non vendores. |

### 4.8 Best practices recommandees

1. Ajouter un guard CI qui bloque les `#checkov:skip` dans les fichiers IaC.
2. Aligner le README avec l'implementation reelle.
3. Classer les skip-checks en:
   - faux positifs documentes;
   - contraintes lab;
   - dettes production a migrer vers DefectDojo/OPA.
4. Faire remonter les parsing errors dans le Golden Report comme finding `HIGH` ou scanner degraded.
5. Ajouter un test qui verifie que chaque policy custom a une entree dans `mapping.json`.
6. Ajouter un test inverse: toute entree `CKV2_CS_AZ_*` du mapping doit correspondre a un fichier policy existant.

## 5. Scanner 3 - Trivy

### 5.1 Role

Trivy couvre trois surfaces:

- Filesystem/SCA: dependances OS et librairies detectees dans le repo.
- Dockerfile/config: misconfigurations Dockerfile.
- Image: vulnerabilites et secrets dans images, supporte localement et dans le normalizer, mais non orchestre comme job image dedie dans le pipeline actuel.

### 5.2 Configuration

Fichiers:

- `shift-left/trivy/configs/trivy.yaml`
- `shift-left/trivy/configs/trivy-ci.yaml`
- `shift-left/trivy/configs/severity-mapping.json`
- `shift-left/trivy/.trivyignore`

Configuration locale:

- scanners: `vuln`, `misconfig`, `secret`;
- severites: CRITICAL, HIGH, MEDIUM, LOW;
- timeout 10m;
- cache `.trivy-cache`;
- package types OS + library;
- misconfiguration limitee a Dockerfile;
- ignorefile `.trivyignore`;
- `exit-code: 0`.

Configuration CI:

- format JSON;
- timeout 15m;
- `db.no-progress=true`;
- meme separation: OPA reste l'enforcement.

### 5.3 Logique d'execution

Wrapper principal: `shift-left/trivy/scripts/run-trivy.sh`

Sous-wrappers:

- `scan-fs.sh`
- `scan-config.sh`
- `scan-image.sh`

Wrappers CI:

- `ci/scripts/shift-left/trivy-db-warm.sh`
- `ci/scripts/shift-left/trivy-fs-scan.sh`
- `ci/scripts/shift-left/trivy-config-scan.sh`

Le job `trivy-db-warm` chauffe la DB avec plusieurs repositories (`ghcr.io` et `mirror.gcr.io`), retries et fallback cache. C'est un bon controle de robustesse CI.

### 5.4 FS scan

`scan-fs.sh`:

- genere un SBOM CycloneDX;
- scanne en `--scanners vuln`;
- ignore `.trivyignore` en CI et impose DefectDojo/OPA pour les exceptions;
- supporte `TRIVY_SKIP_DIRS`;
- retry en CI avec `--skip-db-update` si l'update DB echoue;
- produit `trivy-fs-raw.json` et `trivy-fs.cdx.json`.

Design correct: les secrets source sont volontairement hors scope FS, car Gitleaks est le scanner canonique source/git.

### 5.5 Config scan

`scan-config.sh`:

- cible fichier Dockerfile ou dossier;
- utilise `trivy config`;
- ignore `.trivyignore` en CI;
- produit `trivy-config-raw.json`;
- compte les `Misconfigurations`.

Note: Terraform est volontairement hors scope Trivy config, car Checkov le couvre.

### 5.6 Image scan

`scan-image.sh`:

- scanne image container;
- genere SBOM image CycloneDX;
- active `--scanners vuln,secret`;
- gere auth registry GitLab si l'image cible appartient a `CI_REGISTRY`;
- produit `trivy-image-raw.json` ou un path override via `TRIVY_IMAGE_OUTPUT_PATH`.

Le normalizer supporte aussi une aggregation d'images dans `shift-left/trivy/reports/raw/image/trivy-image-*-raw.json`. En CI, `TRIVY_IMAGE_MIN_REPORTS` est positionne a `0`, ce qui rend l'image scan optionnel dans le pipeline actuel.

### 5.7 Normalisation

Le normalizer:

- exige les rapports FS et config;
- lit les `Vulnerabilities`, `Secrets`, `Misconfigurations`;
- mappe:
  - vuln -> `finding_type=vulnerability`;
  - secret -> `finding_type=secret`;
  - misconfig -> `finding_type=misconfig`;
- garde `FixedVersion`, CVSS, references;
- marque les misconfigs `PASS` comme `PASSED`.

### 5.8 Points forts

- Separation claire FS/config/image.
- SBOM CycloneDX genere pour FS et image.
- Cache DB et warm-up robuste.
- `.trivyignore` ignore en CI: bonne gouvernance, exceptions centralisees.
- Retry avec cache en cas de panne DB.
- HMAC des rapports.
- Image scan supporte dans les scripts et dans le normalizer.

### 5.9 Points faibles et risques

| Risque | Niveau | Analyse |
|---|---:|---|
| Image scan non orchestre en CI | Eleve | Les scripts existent, mais aucun job image scan dedie n'est present dans `ci/pipelines/shift-left.yml`. Risque majeur si des images applicatives sont deployees. |
| `TRIVY_IMAGE_MIN_REPORTS=0` | Moyen/Eleve | Cela evite les faux echecs, mais peut masquer l'absence de scan image en production. |
| `.trivyignore` local seulement | Faible | C'est bon en gouvernance, mais doit etre explique clairement aux devs. |
| Secrets image uniquement via image scan | Moyen | Si l'image scan n'est pas execute, les secrets dans layers ne sont pas couverts par Trivy. |
| SBOM non signe explicitement | Moyen | Le raw JSON est signe, mais le SBOM CycloneDX ne semble pas avoir de HMAC dedie dans le contrat. |

### 5.10 Best practices recommandees

1. Ajouter des jobs `trivy-image-scan-*` pour chaque image deployable.
2. En prod, mettre `TRIVY_IMAGE_MIN_REPORTS` au nombre exact d'images attendues.
3. Signer aussi les SBOMs ou les integrer au contrat d'artefacts.
4. Publier les SBOMs dans DefectDojo ou stockage immuable.
5. Ajouter un controle OPA: image deployable interdite si aucun scan image correspondant.
6. Conserver Trivy FS en `vuln only` pour eviter doublon secret avec Gitleaks.

## 6. Scanner 4 - Cloud-init scanner

### 6.1 Role

Le cloud-init scanner est un scanner custom CloudSentinel. Il couvre une surface que Gitleaks/Checkov/Trivy ne capturent pas correctement: l'intention runtime injectee dans les scripts de bootstrap VM.

Il analyse:

- ressources VM Terraform Azure/AWS/GCP;
- champs `custom_data`, `custom_data_base64`, `user_data`, `user_data_base64`, `metadata_startup_script`;
- templates `templatefile(...)`;
- `base64encode(...)`;
- locals HCL simples;
- YAML cloud-config.

### 6.2 Signaux detectes

Le scanner detecte:

- tag `cs:role` manquant;
- role spoofing: VM taggee web-server mais cloud-init installe des packages DB;
- remote execution:
  - `curl | bash`;
  - `wget | sh`;
  - `eval $(...)`;
  - process substitution `bash <(curl ...)`;
  - download puis execution;
  - verification TLS desactivee;
  - Python remote exec.
- security bypass:
  - injection SSH authorized_keys;
  - firewall disable;
  - chmod dangereux sur chemins critiques;
  - hardcoded credentials;
  - crontab injection.

### 6.3 Logique d'execution

Wrapper CI: `ci/scripts/shift-left/cloudinit-scan.sh`  
Scanner: `shift-left/cloudinit-scanner/cloudinit_scan.py`

Le wrapper:

- scanne `--terraform-dir .`;
- sort `.cloudsentinel/cloudinit_analysis.json`;
- passe `--default-env "${CI_ENVIRONMENT_NAME:-dev}"`;
- signe par HMAC.

Le rapport contient:

- `schema_version`;
- `scanner`;
- `scan_id`;
- `scan_status`;
- `resources_analyzed`;
- `summary`;
- metadata de scan.

### 6.4 Interaction OPA

Le normalizer fait deux choses importantes:

1. Convertit les violations cloud-init en findings first-class.
2. Preserve `resources_analyzed` dans le Golden Report pour les regles OPA multi-signal.

OPA applique des regles dediees dans `gate_deny_intent.rego`:

- `CS-CLOUDINIT-ROLE-TAG-MISSING`;
- `CS-CLOUDINIT-REMOTE-EXEC`;
- `CS-CLOUDINIT-SSH-KEY-INJECTION`;
- `CS-CLOUDINIT-FIREWALL-DISABLE`;
- `CS-CLOUDINIT-HARDCODED-CREDENTIALS`;
- `CS-ROLE-SPOOFING-INTENT`;
- `CS-MULTI-SIGNAL-ROLE-SPOOFING-V2`.

Les regles intent sont fortes: elles traitent staging/prod comme environnements enforce pour certains bypass, et elles peuvent correler cloud-init avec Checkov sur la meme ressource.

### 6.5 Points forts

- Tres bonne couverture d'un angle souvent oublie: bootstrap runtime.
- Analyse `templatefile` et `base64encode`, pas uniquement heredoc brut.
- Detection multi-signal avec OPA.
- Violations non-waivable pour les risques critiques.
- Tests unitaires presents pour plusieurs patterns remote exec et role spoofing.
- HMAC et contrat d'artefact.

### 6.6 Points faibles et risques

| Risque | Niveau | Analyse |
|---|---:|---|
| Expression HCL partiellement resolue | Moyen | Les expressions complexes Terraform ne sont pas toutes resolvables. Le scanner marque `cloud_init_unresolvable`, mais cela ne semble pas bloquant directement. |
| Regex remote exec contournables | Moyen | Les variantes obfusquees peuvent echapper aux regex. |
| Depend de tags `cs:role` | Moyen | Bon contrat de gouvernance, mais il faut garantir que tous les modules VM imposent ce tag. |
| Status `NOT_RUN` si aucune ressource | Faible/Moyen | Le normalizer marque cloudinit `NOT_RUN` quand `resources_analyzed` est vide. Selon OPA, un scanner required NOT_RUN peut bloquer; le pipeline actuel execute toujours le scanner, mais ce comportement doit etre surveille pour les repos sans VM. |
| Nom de scanner custom | Faible | Il faut documenter clairement que c'est le 4e scanner Shift-Left, car certains README parlent encore seulement de trois scanners. |

### 6.7 Best practices recommandees

1. Si `cloud_init_unresolvable=true` en staging/prod, creer un finding HIGH/CRITICAL.
2. Ajouter des tests d'obfuscation remote exec.
3. Imposer `cs:role` au niveau modules Terraform via variable validation ou policy Checkov.
4. Documenter officiellement cloud-init scanner dans `shift-left/README.md` et `docs/README.md`.
5. Ajouter des exceptions OPA tres limitees pour cloud-init: les bypass non-waivable doivent rester non exemptables.

## 7. Analyse transverse des controles de gouvernance

### 7.1 Artefacts et integrite

Le contrat `ci/contracts/artifact_contract.json` exige:

- JSON brut pour chaque scanner;
- sidecar `.hmac` pour chaque rapport brut;
- `golden_report.json` et HMAC;
- `exceptions.json`;
- `audit_events.jsonl`;
- decision OPA.

Le modele est solide: chaque consumer verifie l'integrite avant usage. C'est une bonne pratique Zero Trust CI.

Point a ameliorer: les SBOM Trivy ne sont pas dans le contrat d'artefacts requis. Pour une supply chain production, les SBOM doivent aussi etre immuables, signes, conserves et correlables a l'image.

### 7.2 Exceptions

Le design attendu est bon:

- exceptions depuis DefectDojo;
- schema v2;
- approbation;
- expiration;
- break-glass;
- roles approbateurs;
- matching prioritaire fingerprint/resource.

Point fort: le pipeline fail-closed si le fetch exceptions echoue, sauf override explicite `CLOUDSENTINEL_FAIL_CLOSED=false`.

Point a surveiller: toutes les suppressions locales des scanners doivent etre reduites au strict minimum. Les exceptions metier doivent vivre dans DefectDojo/OPA, pas dans `.checkov.yml`, `.trivyignore` CI ou `.gitleaksignore`.

### 7.3 OPA

Forces:

- separation gate/drift claire;
- `required_scanners := ["gitleaks", "checkov", "trivy", "cloudinit"]`;
- seuils clamps cote policy, non injectables librement;
- CRITICAL force a zero;
- HIGH plafonne a 5 maximum;
- MEDIUM/LOW en warning;
- exceptions gouvernees;
- tests OPA dedies;
- serveur OPA CI avec token auth + `system.authz`.

Risque:

- un scanner required avec rapport absent ou vide peut bloquer. C'est voulu fail-closed, mais il faut documenter les cas repo sans VM/cloud-init.

## 8. Matrice des points forts

| Domaine | Niveau | Justification |
|---|---:|---|
| Separation detection/decision | Fort | OPA centralise l'enforcement |
| Secret scanning | Fort | Defaults + custom + redact + hash |
| IaC scanning | Fort | 35 policies Azure custom + built-ins |
| SCA / vuln scanning | Bon | FS/config robuste, image supporte mais pas orchestre |
| Cloud-init intent scanning | Fort | Scanner custom pertinent et integre OPA |
| Artefact integrity | Fort | HMAC distribue et contract tests |
| Exceptions governance | Fort | DefectDojo + schema + OPA |
| Documentation | Moyen | Plusieurs ecarts avec le code |
| Tests | Bon | OPA/tests unitaires/smoke, mais manque coverage mapping/guards |
| Production readiness | Bon | Base solide, image scan CI et docs a renforcer |

## 9. Matrice des faiblesses prioritaires

| Priorite | Sujet | Impact | Recommendation |
|---:|---|---|---|
| P0 | Image scan non orchestre en CI | Images deployees sans scan layer/CVE/secret | Ajouter jobs `trivy-image-scan-*` et fixer `TRIVY_IMAGE_MIN_REPORTS` |
| P0 | `#checkov:skip` non bloque | Exceptions locales non gouvernees | Ajouter guard CI anti-inline skip |
| P1 | Docs Gitleaks/Checkov obsoletes | Risque audit/exploitation | Aligner README avec scripts |
| P1 | Parsing errors Checkov non bloquants | Couverture IaC incomplete | Remonter en finding ou scanner degraded |
| P1 | Cloud-init unresolvable non bloquant | Payload critique potentiellement invisible | Bloquer ou warning fort en staging/prod |
| P1 | SBOM non signe | Supply chain incomplete | Ajouter HMAC et retention SBOM |
| P2 | Mapping custom non teste | Drift policies/severites | Test mapping bidirectionnel |
| P2 | `.gitleaksignore` gouvernance limitee | Suppression durable possible | Audit periodique + CI test |

## 10. Recommandations production

### 10.1 Enforcement

1. Garder OPA comme unique decision maker.
2. Ne jamais utiliser les exit codes scanners pour bloquer directement.
3. Fail-closed si un rapport required est absent, invalide ou non signe.
4. Interdire les suppressions inline non gouvernees:
   - `#checkov:skip`;
   - `.trivyignore` en CI;
   - `.gitleaksignore` sans ticket/expiry.

### 10.2 Couverture

1. Ajouter scan image obligatoire avant deploy.
2. Lier chaque image scannee au digest deploye.
3. Verifier que le digest deploye correspond au digest scanne.
4. Integrer SBOM dans DefectDojo et/ou stockage immutable.
5. Ajouter controle OPA sur absence de SBOM ou absence de scan image.

### 10.3 Gouvernance

1. Centraliser les exceptions metier dans DefectDojo.
2. Limiter `.checkov.yml skip-check` aux faux positifs techniques documentes.
3. Revoir trimestriellement toutes les allowlists.
4. Exiger owner, ticket, expiration et justification pour toute suppression.
5. Produire des evenements audit JSONL pour:
   - scanner absent;
   - exception appliquee;
   - exception rejetee;
   - parsing error;
   - rapport non signe.

### 10.4 Tests

Ajouter ces tests:

1. `test_checkov_no_inline_skip`: bloque `#checkov:skip`.
2. `test_checkov_mapping_complete`: chaque `CKV2_CS_AZ_*` a mapping.
3. `test_checkov_mapping_no_orphans`: pas de mapping sans policy.
4. `test_trivy_image_required_in_prod`: OPA deny si image scan absent en prod.
5. `test_sbom_hmac_required`: contrat d'artefact inclut SBOM + HMAC.
6. `test_cloudinit_unresolvable_prod`: deny/warn fort si payload non resolu.
7. `test_gitleaks_docs_contract`: smoke sur hash + range metadata.

## 11. Conclusion

CloudSentinel a une architecture Shift-Left solide, proche d'un standard entreprise: scanners advisory, normalisation canonique, OPA comme PDP, enforcement centralise, exceptions gouvernees et artefacts signes. Le systeme est deja plus mature qu'un pipeline DevSecOps classique base uniquement sur des exit codes d'outils.

Les corrections prioritaires ne sont pas des refontes: elles concernent surtout la couverture image Trivy, l'interdiction effective des suppressions locales Checkov, le traitement fail-closed des signaux incomplets, et l'alignement de la documentation avec le code. Ces points sont importants pour passer d'une plateforme PFE robuste a une posture production audit-ready.
