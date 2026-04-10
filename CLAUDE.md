CLOUDSENTINEL — AUDIT ULTRA-DÉTAILLÉ
Sécurité, Architecture & DevSecOps — Niveau Entreprise
Auditeur : Senior DevSecOps & Cloud Security Architect
Date : Avril 2026
Repository : github.com/drghassen/PFE-MPSSR

1. ANALYSE DÉTAILLÉE PAR OUTIL

1.1 GITLEAKS
A. Logique interne
Gitleaks est un outil de détection de secrets basé sur un moteur de matching par expressions régulières (Regex + entropy analysis). Il fonctionne en deux modes dans CloudSentinel :

Mode git-log : scanne l'historique complet des commits (GIT_DEPTH: "0") — chaque diff de chaque commit est passé au moteur regex
Mode pre-commit hook : scanne uniquement le diff staged avant commit

Données consommées : objets git (blobs), contenu des fichiers trackés, métadonnées de commit.
Données produites : tableau JSON d'objets {RuleID, Description, Match, Secret, File, StartLine, EndLine, Author, Date, Email, Fingerprint, Commit}.
Types de risques détectés : credentials hardcodés (API keys, tokens, passwords), clés de service cloud (Azure SAS, AWS Access Keys, GCP SA keys), certificats privés embarqués.
B. Implémentation dans CloudSentinel
ci/scripts/gitleaks-scan.sh
  → shift-left/gitleaks/run-gitleaks.sh
    → gitleaks detect --config gitleaks.toml --report-format json --report-path .cloudsentinel/gitleaks_raw.json
Configuration : mode hybride useDefault = true + règles custom Azure. L'allowlist est correctement définie avec exclusion de .terraform/, tests/fixtures/, fichiers de lock, et images binaires.
Intégration CI : job gitleaks-scan dans le stage scan, parallèle avec Checkov et Trivy. GIT_DEPTH: "0" assure que l'historique complet est scanné — c'est la bonne pratique (un secret supprimé dans un commit récent reste dans l'historique).
C. Valeur sécurité
Couvert : Secrets dans les fichiers versionnés, secrets dans l'historique git, credentials Azure hardcodés dans le code IaC.
Non couvert :

Variables CI GitLab (ARM_CLIENT_SECRET, DEFECTDOJO_API_KEY) — stockées hors git
Secrets injectés au runtime via env vars dans les containers
Secrets dans les artefacts de pipeline (.cloudsentinel/terraform_outputs_student_secure.json pourrait contenir des outputs Terraform sensibles)
Secrets dans les images Docker (Trivy secret scanner couvre partiellement cela, mais uniquement pour alpine:3.21 dans l'état actuel)

D. Points forts

Mode hybride (defaults + custom) avec justification ADR documentée
Allowlist précise évitant les faux positifs sur fixtures et lock files
Full history scan (GIT_DEPTH: "0")
Mapping de sévérité depuis le TOML (_gitleaks_mapping()) avec fallback sur tags
Pre-commit hook disponible pour advisory local

E. Points faibles

Pas de baseline commit-range : sur un projet mature avec historique long, chaque pipeline scanne tout l'historique. Performance O(n) sur le nombre de commits.
Gitleaks raw output = tableau JSON : si aucun secret trouvé, Gitleaks retourne [] ou null. Le normalizer gère les deux cas mais c'est fragile.
La sévérité custom est portée par les tags TOML — pas validée par un schéma formel.

F. Cycle de vie dans le pipeline
Stage: scan (parallèle avec checkov, trivy-*)
Input:  git repository (full history)
Output: .cloudsentinel/gitleaks_raw.json
Consommé par: normalize-reports → golden_report.json → OPA
Lifecycle complet : si Gitleaks ne produit pas de rapport valide, normalize.py marque le scanner status: NOT_RUN, OPA déclenche deny["Scanner gitleaks did not run or report is invalid"] → pipeline bloqué. Fail-closed correct.

1.2 CHECKOV
A. Logique interne
Checkov est un analyseur statique IaC (Infrastructure-as-Code). Il parse les fichiers Terraform en un AST (Abstract Syntax Tree) via son propre parser, puis évalue chaque ressource contre un catalogue de règles (built-in + custom YAML/Python). Il n'exécute jamais Terraform — il raisonne sur la configuration déclarée, pas sur l'état réel.
Limitation fondamentale de cette approche : Checkov voit les attributs Terraform tels qu'écrits, pas tels que résolus. Si un attribut est var.admin_allowed_cidr, Checkov voit une référence à variable, pas "*". C'est la cause directe de la faille NSG SSH décrite dans l'audit précédent.
Données consommées : fichiers .tf, .tfvars, policies YAML custom.
Données produites : JSON {results: {passed_checks: [...], failed_checks: [...], skipped_checks: [...], parsing_errors: [...]}}.
B. Implémentation dans CloudSentinel
ci/scripts/checkov-scan.sh
  → shift-left/checkov/run-checkov.sh <scan_target>
    → checkov --directory infra/azure/student-secure
              --config-file .checkov.yml
              --external-checks-dir shift-left/checkov/policies/
              --soft-fail
soft-fail: true dans .checkov.yml signifie que Checkov retourne toujours exit code 0 ou 1 (jamais 2 pour findings). Le script gère RC >= 2 comme erreur technique. OPA est le point de décision, pas Checkov — c'est architecturalement correct.
Policies custom : 28 policies YAML couvrant storage, network, compute, database, identity, logging, appservice, security. Convention de nommage : CKV2_CS_AZ_XXX_nom_descriptif.
C. Valeur sécurité
Couvert : Mauvaises configurations IaC avant déploiement (pre-deploy). Alignement partiel CIS Azure Benchmark. Custom policies étendent la couverture vers des contrôles spécifiques Azure.
Non couvert :

Valeurs résolues des variables (faille structurelle de l'analyse statique Terraform)
Ressources créées par des modules externes non inclus dans le scan
Configurations dérivées (locals calculés dynamiquement)
IAM/RBAC (azurerm_role_assignment) — absence totale de politique
Configurations runtime (ce qui est déployé peut différer si les tfvars sont overridés en CI)

Vérification critique : La custom policy CKV2_CS_AZ_021_ssh_restricted.yaml est censée bloquer SSH ouvert. Il faut vérifier si elle évalue source_address_prefix == "*" directement ou si elle cherche l'attribut admin_allowed_cidr. Si la policy cherche l'attribut par nom et non par valeur résolue, elle passera le check sur la NSG défectueuse.
D. Points forts

Séparation claire des policies par domaine Azure (network/, compute/, storage/, etc.)
Exclusion des frameworks Docker (délégué à Trivy) : bonne séparation des responsabilités
download-external-modules: false : pas de résolution de modules externes — bonne pratique sécurité
Locked skip paths : les chemins exclus sont hardcodés dans le script, non surchargeables par des variables d'environnement

E. Points faibles

Scan target hardcodé : readonly DEFAULT_SCAN_TARGET="infra/azure/student-secure". Non-paramétrable, non-scalable.
Checkov voit les références Terraform, pas les valeurs résolues : limitation architecturale fondamentale.
Absence de politique IAM : zéro couverture sur azurerm_role_assignment.
soft-fail: true : si une policy lève une exception Python interne, elle est silencieusement ignorée au lieu de bloquer.
Pas d'alignement formel déclaré avec CIS Azure Benchmark ou NIST — les IDs custom ne mappent pas vers un standard.

F. Cycle de vie dans le pipeline
Stage: scan (parallèle)
Input:  infra/azure/student-secure/*.tf
Output: .cloudsentinel/checkov_raw.json + .cloudsentinel/checkov_scan.log
Consommé par: normalize-reports → golden_report.json → OPA

1.3 TRIVY
A. Logique interne
Trivy est un scanner multi-cibles. Dans CloudSentinel, trois modes sont utilisés :

trivy fs (filesystem scan) : SCA (Software Composition Analysis) + secrets dans le filesystem. Analyse les manifestes de dépendances (requirements.txt, package.json, go.mod, etc.) et cherche des CVE dans la Trivy DB (base offline téléchargée). Produit également un SBOM (Software Bill of Materials) en format CycloneDX.
trivy config (misconfig scan) : Analyse des Dockerfiles pour misconfigurations. Équivalent léger de Checkov pour les containers.
trivy image (image scan) : Scan des layers d'une image Docker. Analyse les packages OS installés + bibliothèques applicatives. Détecte aussi les secrets dans les layers.

B. Implémentation dans CloudSentinel — DÉFAUT CRITIQUE
Le défaut le plus grave du projet, déjà identifié :
bash# ci/scripts/trivy-image-scan.sh
readonly DEFAULT_TRIVY_IMAGE_TARGET="alpine:3.21"
Les images réellement utilisées dans le pipeline ne sont jamais scannées :

registry.gitlab.com/drghassen/pfe-cloud-sentinel/scan-tools@sha256:f2f6...
registry.gitlab.com/drghassen/pfe-cloud-sentinel/opa@sha256:740e...
registry.gitlab.com/drghassen/pfe-cloud-sentinel/deploy-tools@sha256:f333...

Ces images exécutent respectivement : tous les scanners, OPA (avec accès au golden_report et aux exceptions), et OpenTofu avec les credentials Azure ARM. Si l'une d'elles est compromise via supply chain, le pipeline entier est compromis sans détection.
La configuration Trivy CI est correcte (trivy-ci.yaml) : scanners vuln+misconfig+secret, format JSON, exit-code 0 (OPA décide), .trivyignore désactivé en CI. Le problème est uniquement la cible hardcodée.
Cache : clé trivy-db-${CI_PROJECT_ID}-${TRIVY_VERSION}, pull-push sur trivy-fs-scan (qui télécharge la DB) et pull uniquement sur trivy-config-scan et trivy-image-scan. Pattern correct pour éviter les téléchargements multiples et les contention de cache.
C. Valeur sécurité
Couvert : CVE dans les dépendances Python/Node/Go du projet, misconfigurations Dockerfile, secrets dans le filesystem.
Non couvert :

Les images CI réelles (bug critique)
Runtime vulnerabilities (Trivy ne fait que du static analysis)
CVE dans l'OS de base des VMs Azure déployées
Bibliothèques chargées dynamiquement au runtime

D. Points forts

Trois modes de scan couvrant différentes surfaces
SBOM généré (CycloneDX) — piste d'audit des dépendances
Cache DB correctement géré avec versioning
Séparation claire : Trivy pour containers, Checkov pour IaC

E. Points faibles

trivy-image-scan scanne alpine:3.21 — défaut critique, fausse assurance
Pas de scan des images CI avant leur utilisation dans le pipeline
trivy config scanne uniquement les Dockerfiles — overlap partiel avec Checkov

F. Cycle de vie dans le pipeline
Stage: scan (3 jobs parallèles)
  trivy-fs-scan     → shift-left/trivy/reports/raw/trivy-fs-raw.json (+ SBOM)
  trivy-config-scan → shift-left/trivy/reports/raw/trivy-config-raw.json
  trivy-image-scan  → shift-left/trivy/reports/raw/trivy-image-raw.json (+ SBOM)
Consommé par: normalize-reports → golden_report.json → OPA

1.4 OPA (Open Policy Agent)
A. Logique interne
OPA est un moteur de policy générique qui évalue des règles Rego (langage fonctionnel déclaratif) contre un document JSON d'input. Dans CloudSentinel, OPA est utilisé comme PDP (Policy Decision Point) en mode serveur REST avec fallback CLI.
Architecture PDP/PEP :

PDP : OPA server (opa run --server) avec la policy pipeline_decision.rego et exceptions.json comme data
PEP : run-opa.sh qui poste le golden_report.json via HTTP POST et interprète la décision

B. Implémentation dans CloudSentinel
OPA server est démarré en background dans opa-decision.sh :
bashopa run --server --addr=127.0.0.1:8181 \
  --log-level=info --log-format=json \
  --set=decision_logs.console=true \
  policies/opa/pipeline_decision.rego \
  .cloudsentinel/exceptions.json
Les exceptions sont chargées comme données statiques au démarrage du serveur — ce qui signifie qu'elles ne peuvent pas être rechargées à chaud. Pour un déploiement production avec OPA en daemon persistant, il faudrait utiliser les bundles OPA avec rechargement périodique.
La policy pipeline_decision.rego est le composant le plus sophistiqué du projet. Analyse détaillée :
rego# Architecture de la décision :
failed_findings          # toutes les findings FAILED non-dupliquées
  → is_excepted_finding? # la finding est-elle couverte par une exception valide ?
    → effective_failed_findings  # findings non-exceptées
      → effective_critical/high  # compteurs par sévérité
        → deny rules             # conditions de blocage
          → allow = count(deny) == 0
Validation des exceptions — valid_exception_definition/1 vérifie :

ID au format SHA256 hex-64 (^[a-f0-9]{64}$)
Tool dans la liste autorisée (allowed_tools)
Pas de wildcards dans le resource path
requested_by != approved_by (four-eyes principle)
source == "defectdojo" forcé
status == "approved" forcé
Timestamps RFC3339 valides avec approved_at <= now < expires_at
Pas d'exception CRITICAL en prod (prod_critical_exception_violation)

Scope-aware matching — L'exception doit matcher sur repo + environment + branch. Si la liste est vide → match universel (comportement correct pour les exceptions globales).
partial_mismatch_reasons — Diagnostic précis quand une exception aurait pu s'appliquer mais ne s'applique pas à cause d'un mismatch de chemin ou de scope. Génère des messages comme "Resource path mismatch: exception='infra/main.tf' finding='infra/azure/main.tf'". C'est une fonctionnalité de debugging enterprise rare.
C. Valeur sécurité
Couvert : Décision centralisée et auditée, gouvernance des exceptions avec traçabilité, fail-closed sur scanners manquants, protection contre retry abuse (via retry-guard séparé), immutabilité des policies.
Non couvert :

Aucune décision sur le shift-right (drift findings)
Les thresholds (critical_max, high_max) viennent du golden_report (injectable via variables CI)
Pas de politique sur la fréquence d'exception (un finding pourrait être re-exempté indéfiniment)

D. Points forts

PDP unique, séparé des outils de scan
Exception governance niveau entreprise (SHA256 ID, four-eyes, expiration, source forcée)
partial_mismatch_reasons : debugging avancé
Fail-closed sur scanner non-exécuté
Policy immutability guard (protège le .rego contre modification non-autorisée)
Mode server + fallback CLI : résilience
Decision audit log en JSONL : traçabilité

E. Points faibles
Thresholds contournables via variables CI :
yaml# shift-left.yml
variables:
  CRITICAL_MAX: "0"
  HIGH_MAX: "2"
Un maintainer GitLab peut modifier ces variables dans l'interface, override le golden_report, et réduire la sévérité d'enforcement. Ces seuils devraient être des constantes Rego, pas des inputs.
avg_approval_time_hours := 0 et active_break_glass_count := 0 hardcodés. Ces métriques apparaissent dans le rapport de décision comme si elles étaient calculées, alors qu'elles sont statiques.
Pas de rotation des exceptions automatique. Une exception expirée génère un deny mais rien ne notifie le propriétaire avant expiration.
Exceptions chargées en data statique. En mode server, si exceptions.json change, le serveur doit être redémarré. Pas de bundle hot-reload.
F. Cycle de vie dans le pipeline
Stage: contract (smoke tests OPA image + contract test JSON schema)
  ↓
Stage: decide
  Input:  .cloudsentinel/golden_report.json + .cloudsentinel/exceptions.json
  OPA server démarré (background) + run-opa.sh --enforce
  Output: .cloudsentinel/opa_decision.json + decision_audit_events.jsonl
  Exit code: 0 (allow) ou 1 (deny → pipeline bloqué)
  ↓
Stage: deploy (conditionné par opa-decision)

1.5 DEFECTDOJO
A. Logique interne
DefectDojo est une plateforme de gestion des vulnérabilités (vulnerability management). Elle centralise les findings de différents outils, gère le cycle de vie des vulnérabilités (new → active → mitigated → accepted), et fournit des APIs pour le Risk Acceptance management.
Dans CloudSentinel, DefectDojo remplit deux rôles distincts :

Récepteur de raw reports : les scans bruts (gitleaks, checkov, trivy-fs) sont uploadés via leurs parsers natifs
Source de vérité pour les exceptions : les Risk Acceptances DefectDojo sont transformées en exceptions OPA via fetch-exceptions.py

B. Implémentation dans CloudSentinel
Upload des raw reports (upload-to-defectdojo.sh) :
needs: [gitleaks-scan, checkov-scan, trivy-fs-scan]  ← pas trivy-config ni trivy-image
when: always
allow_failure: false
Les rapports sont uploadés avec leurs formats natifs (Gitleaks JSON, Checkov JSON, Trivy JSON) pour utiliser les parsers natifs DefectDojo — décision architecturale correcte qui évite la perte d'information lors de la normalisation OPA.
Fetch des exceptions (fetch-exceptions.py → fetch_exceptions/) :
python# fetch_mapping.py : _build_ci_scope()
scope = {
    "repos": [CI_PROJECT_PATH],
    "branches": [CI_COMMIT_REF_NAME],
    "environments": [ENVIRONMENT]
}
Le scope est injecté depuis les variables CI — ce qui signifie que si une Risk Acceptance existe dans DefectDojo, elle ne sera valide que pour le bon repo/branch/env. C'est du scope-binding correct.
DEFECTDOJO_URL et DEFECTDOJO_API_KEY comme variables CI masquées — correct.
C. Valeur sécurité
Couvert : Traçabilité des findings, cycle de vie des vulnérabilités, Risk Acceptance avec approbation double, corrélation entre runs.
Non couvert :

DefectDojo est un point de défaillance unique pour les exceptions. Si DefectDojo est down pendant le fetch, les exceptions sont perdues → tous les findings avec exception valide deviennent bloquants.
Pas de cache local des exceptions pour la résilience.
L'upload ne couvre pas trivy-config ni trivy-image — gap de traçabilité.

D. Points forts

Upload raw (non normalisé) vers DefectDojo : parsers natifs, pas de perte d'information
Risk Acceptance transformée en exception OPA avec SHA256 ID déterministe (stable_exception_id)
Résolution des user IDs DefectDojo en usernames via API /api/v2/users/{id}/
Audit trail dans audit_events.jsonl pour chaque exception transformée

E. Points faibles

allow_failure: false + when: always : si DefectDojo est down, le pipeline échoue même si OPA autorise. Bloquer un déploiement urgent à cause d'un reporter indisponible est une décision de priorité inversée.
Upload partiel : trivy-config et trivy-image ne sont pas uploadés.
Pas de déduplication côté CloudSentinel — défectDojo gère la dédup mais seulement si les parsers la supportent correctement.

F. Cycle de vie dans le pipeline
Stage: report (parallèle avec deploy)
  when: always (runs even if OPA denies)
  Input:  gitleaks_raw.json, checkov_raw.json, trivy-fs-raw.json
  Output: .cloudsentinel/dojo-responses/ (réponses API)

  Séparément, dans normalize-reports (stage normalize) :
  fetch-exceptions.py → .cloudsentinel/exceptions.json
    → Chargé par OPA server au stage decide

1.6 DRIFT ENGINE
A. Logique interne
Le Drift Engine est un batch job Python qui exécute :
terraform init (backend azurerm)
  → terraform plan -refresh-only -detailed-exitcode -out=tfplan
    → terraform show -json tfplan
      → parse resource_drift + resource_changes
        → classify_drift_severity()
          → generate drift-report.json
            → push to DefectDojo (optionnel)
-refresh-only : Terraform interroge l'API Azure pour récupérer l'état réel de chaque ressource managée, puis compare avec le state Terraform (.tfstate). Il ne génère PAS de plan de déploiement — uniquement un plan de rafraîchissement.
Exit codes sémantiques de terraform plan -detailed-exitcode :

0 : pas de différence (aucun drift)
1 : erreur Terraform
2 : différences détectées (drift)

B. Implémentation dans CloudSentinel
Le drift engine est containerisé (Dockerfile dans shift-right/drift-engine/) et exécuté via Docker-in-Docker dans le pipeline scheduled :
yaml# shift-right-drift.yml
image: docker:26.1.4
services:
  - name: docker:26.1.4-dind
    alias: docker
variables:
  DOCKER_TLS_CERTDIR: ""   ← DinD sans TLS
L'image est rebuildée à chaque run (docker build -t "cloudsentinel-drift-engine:${CI_PIPELINE_ID}"). Pas d'image registry, pas de caching Docker layer. Sur un réseau lent ou avec une image lourde, le build initial consomme plusieurs minutes de scheduled pipeline.
C. Angles morts du Drift Engine
1. Shadow IT total. Toute ressource Azure créée hors Terraform est invisible. Le drift engine compare uniquement les ressources que Terraform a créées et dont il a le state. Une VM créée manuellement, un Storage Account ajouté par un développeur, un NSG rule ajouté en urgence via portail : aucune détection.
2. IAM/RBAC drift. Si le state Terraform ne gère pas azurerm_role_assignment, un Owner ajouté manuellement sur la subscription est invisible.
3. Multi-subscription. Le drift engine est configuré pour une seule subscription (ARM_SUBSCRIPTION_ID). Dans un tenant Azure enterprise avec plusieurs subscriptions, seule l'une est couverte.
4. Pas d'OPA. Les findings de drift passent directement à DefectDojo sans policy OPA. Aucune règle de sévérité uniforme, aucune exception gérée de façon cohérente avec le shift-left.
5. Remédiation placeholder.
bash# custodian-remediate
- echo "Drift detected -> trigger Cloud Custodian remediation here"
Cloud Custodian est une excellent choix architectural pour la remédiation, mais l'implémentation est absente. C'est à documenter honnêtement.
D. Points forts

Architecture Python + Pydantic pour la config typée (AppConfig, TerraformConfig, etc.)
_diff_paths() : diff structurel JSON des before/after Terraform sans exposer les valeurs sensibles (data plane redaction)
Gestion correcte des exit codes Terraform (rc=2 = drift, rc=1 = erreur)
TF_PLAN_TIMEOUT_S configurable
lockfile=readonly quand le répertoire IaC est monté en read-only

E. Points faibles

DinD sans TLS (DOCKER_TLS_CERTDIR: "")
Image rebuildée à chaque run (pas de registry)
Scope limité aux ressources Terraform-managed
Pas d'OPA pour les décisions de drift
defectdojo.enabled: false par défaut dans drift_config.yaml — le reporting vers DefectDojo est désactivé par défaut


2. ANALYSE ULTRA-APPROFONDIE DU SHIFT-LEFT
2.1 Flux de données complet
[Git Repo]
    │
    ├─── gitleaks detect → gitleaks_raw.json  (array JSON)
    ├─── checkov --directory → checkov_raw.json  (object JSON)
    ├─── trivy fs → trivy-fs-raw.json  (object JSON)
    ├─── trivy config → trivy-config-raw.json  (object JSON)
    └─── trivy image → trivy-image-raw.json  (object JSON)
         [alpine:3.21 — défaut critique]
                │
                ▼ normalize.py
    .cloudsentinel/golden_report.json
    {
      schema_version, metadata, summary,
      scanners: {gitleaks, checkov, trivy},
      findings: [...],
      quality_gate: {thresholds}
    }
                │
                ├── fetch-exceptions.py → exceptions.json
                │        (DefectDojo Risk Acceptances → exceptions OPA)
                │
                ▼ OPA (pipeline_decision.rego)
    opa_decision.json
    {allow: bool, deny: [...], metrics: {...}, exceptions: {...}}
                │
          ┌─────┴─────┐
          ▼           ▼
      exit 0        exit 1
      DEPLOY      PIPELINE BLOCKED
2.2 Est-ce un vrai mécanisme de sécurité ?
Partiellement. Le shift-left de CloudSentinel est un mécanisme de sécurité pré-déploiement solide, mais avec des limitations intrinsèques importantes.
Ce qui en fait un vrai mécanisme :

OPA est le seul point de décision (pas de logique dispersée)
Fail-closed sur scanner manquant
Exceptions gouvernées avec traçabilité
Normalisation unifiée (un seul document d'input pour OPA)
Policy immutability (les règles ne peuvent pas être modifiées par n'importe qui)

Ce qui en fait du "scanning" plutôt que de la sécurité réelle :

Checkov analyse l'IaC statiquement mais ne voit pas les valeurs résolues
Le scan image ne couvre pas les vraies images CI
Aucune couverture runtime
Les résultats sont corrélés (via OPA) mais pas causalement liés entre outils
Aucune détection de configuration drift post-déploiement dans le shift-left

2.3 Angles morts du Shift-Left
DomaineCouvert ?OutilLimitationSecrets dans le code✅GitleaksPas les variables CIIaC misconfig⚠️CheckovValeurs variables non résoluesCVE dépendances✅Trivy FSContainer vulns❌Trivy ImageAlpine:3.21 hardcodéIAM/RBAC❌—Aucun outilNetwork exposure⚠️CheckovNSG variable non résolueSensitive data exposure❌—Pas de DLPRuntime security❌—Hors scope shift-leftSBOM✅TrivyCycloneDX généré

3. ANALYSE DES POLITIQUES
3.1 Politiques Gitleaks
Modèle hybride : règles upstream Gitleaks (maintenues par la communauté) + règles custom CloudSentinel Azure (Azure SAS tokens, Azure Storage connection strings, Azure AD credentials).
Pertinence : Les règles upstream couvrent ~160 types de secrets connus (AWS, GCP, GitHub, Slack, etc.). Les règles custom étendent vers les patterns Azure spécifiques. C'est le bon approach.
Risque faux positifs : L'allowlist regex inclut des patterns comme ^id_[a-z0-9]{10,}$ (évite les faux positifs sur des IDs Terraform) et les connexions locales (localhost, 127.0.0.1). Bien calibré.
Risque faux négatifs : Les secrets obfusqués (base64, rotation de caractères) ne seront pas détectés. Les secrets très courts (tokens < 8 chars) peuvent passer sous les seuils d'entropy.
3.2 Politiques Checkov
28 policies custom, organisées par domaine. Alignement non déclaré mais observable :
DomainePoliciesAlignementStorageCKV2_CS_AZ_001/002/005/006CIS Azure 3.xNetworkCKV2_CS_AZ_007/008/017/021CIS Azure 6.xComputeCKV2_CS_AZ_010/011/019CIS Azure 7.xKey VaultCKV2_CS_AZ_003/014/015/029/030CIS Azure 8.xDatabaseCKV2_CS_AZ_004/012/018CIS Azure 4.xLoggingCKV2_CS_AZ_013/016/020CIS Azure 5.xSecurityCKV2_CS_AZ_023/024Microsoft Defender
Gap critique : aucune politique sur azurerm_role_assignment. C'est le vecteur d'escalade de privilèges le plus fréquent dans Azure.
3.3 Politiques OPA
OPA est le PDP unique pour le shift-left. La logique de décision est intégralement dans pipeline_decision.rego — pas de décision dispersée dans les scripts bash ou Python. C'est l'architecture correcte.
Inputs OPA :

input = golden_report.json (findings normalisés + metadata CI + quality_gate)
data.cloudsentinel.exceptions.exceptions = liste des exceptions valides

Seuils contournables (défaut confirmé) :
regocritical_max_raw := object.get(thresholds, "critical_max", 0)
Les thresholds viennent du quality_gate du golden_report, lui-même construit à partir des variables CI CRITICAL_MAX / HIGH_MAX. Un maintainer GitLab peut les modifier.
Architecture recommandée :
rego# Thresholds figés dans la policy, non injectables
critical_max := 0
high_max := 2

# Override possible uniquement pour des environnements spécifiques
critical_max := 5 if { environment == "dev" }

4. ANALYSE DU SHIFT-RIGHT
(Voir section 1.6 — Drift Engine pour l'analyse technique complète.)
Complément : Comparaison des approches de drift detection
ApprocheCloudSentinelAzure Security Center / Defender CSPMSource de véritéTerraform stateAzure Resource GraphShadow IT❌ Non couvert✅ Inventaire completIAM drift❌ Hors scope✅ RBAC analysisScheduled✅ GitLab schedule✅ ContinuRemédiation⚠️ Placeholder✅ Defender + AutomationCustom policy✅ Cloud Custodian (prévu)✅ Azure Policy
CloudSentinel Drift Engine est une approche "terraform-aware drift detection" — un outil de cohérence IaC, pas un CSPM complet.

5. ANALYSE DES PIPELINES CI/CD
5.1 Design des stages et enforcement
guard   → fail-closed    ✅ (retry-guard + immutability : allow_failure: false)
scan    → advisory       ✅ (scanners exitent 0, OPA décide)
normalize → fail-closed  ✅ (manque = NOT_RUN → OPA deny)
contract → fail-closed   ✅ (contract-test + opa-image-smoke)
decide  → fail-closed    ✅ (opa-decision exit 1 si deny)
report  → when: always   ⚠️ (allow_failure: false = dépendance défectDojo)
deploy  → conditionné    ✅ (needs: opa-decision)
5.2 Points d'enforcement
Contournement potentiel #1 : variables CI override
yamlvariables:
  CRITICAL_MAX: "0"
  HIGH_MAX: "2"
Un maintainer peut modifier ces valeurs dans l'interface GitLab UI → Settings → CI/CD → Variables.
Contournement potentiel #2 : OPA_PREFER_CLI=true
bash# run-opa.sh
OPA_PREFER_CLI="${OPA_PREFER_CLI:-false}"
Cette variable peut être injectée en CI pour forcer le mode CLI au lieu du serveur. En mode CLI, les exceptions sont chargées différemment. Impact à évaluer.
Protection correcte : images pinnées par digest
yamlimage: "registry.gitlab.com/.../scan-tools@sha256:f2f6..."
Les digests SHA256 garantissent que l'image utilisée correspond exactement à celle testée. Pas de tag-mutable attack possible. C'est du niveau production.
Protection correcte : immutability guard
Le script enforce-policies-immutability.sh compare les fichiers modifiés dans le diff git avec une liste de fichiers protégés (policies Rego, scripts CI, configs scanners). Si un fichier protégé est modifié par un utilisateur non-autorisé, le pipeline bloque.
5.3 Analyse du flux report/deploy
Problème architectural identifié :
yamlupload-to-defectdojo:
  needs: [gitleaks-scan, checkov-scan, trivy-fs-scan]  ← PAS opa-decision
  when: always
  allow_failure: false  ← BLOQUANT
yamldeploy-infrastructure:
  needs: [opa-decision]  ← correct
  rules:
    - if: '$CI_COMMIT_BRANCH =~ /^(main|develop)$/'
Si DefectDojo est down :

upload-to-defectdojo fail → pipeline fail
deploy-infrastructure ne s'exécute pas (même si OPA a dit allow)
Bloquer un déploiement à cause d'un reporter, pas d'une décision sécurité = priorité inversée

Solution architecturale :
yamlupload-to-defectdojo:
  allow_failure: true  # Non-bloquant
  # + alerte Slack/PagerDuty sur failure séparée

6. SÉCURITÉ RÉELLE VS SÉCURITÉ PIPELINE
Répartition estimée
CouchePourcentageJustificationPipeline security~72%Gitleaks+Checkov+Trivy+OPA = pre-deploy static analysisCloud runtime security~28%Drift engine (tf-aware) + Checkov IaC coverage post-deploy
72% du système sécurise le pipeline lui-même (les artefacts CI, le processus de déploiement, les configurations IaC avant qu'elles soient appliquées). 28% seulement touche la sécurité du cloud réel post-déploiement, et cette couverture est limitée aux ressources Terraform-managed.
Manques cloud réels
IAM/RBAC : Aucun outil ne vérifie qui a accès à quoi dans Azure à runtime. Pas de az role assignment list dans le drift engine. Les Conditional Access Policies Azure AD sont invisibles.
Network security runtime : Les NSG Flow Logs sont définis en IaC (module monitoring) mais leur contenu n'est jamais analysé par CloudSentinel. Un port ouvert détecté par Checkov en pre-deploy sera également invisible en post-deploy si la VM est reconfigurée manuellement.
Data protection : Le Storage Account a du CMK (Customer-Managed Key) via Key Vault — c'est bien. Mais aucune analyse des accès aux données (audit logs Storage, Entra ID sign-in logs).
Monitoring/Logging : Le module Terraform déploie des azurerm_monitor_diagnostic_setting et des NSG Flow Logs. Mais ces logs vont dans un Storage Account — ils ne sont pas consommés par CloudSentinel pour de la détection en temps réel.
Runtime protection : Zéro couverture. Pas de Microsoft Defender for Servers, pas d'analyse comportementale des workloads.

7. GARANTIE DE SÉCURITÉ
"Si le pipeline est 100% vert, l'infrastructure est-elle réellement sécurisée ?"
RÉPONSE : NON
Justification technique détaillée
Raison 1 : NSG SSH ouvert à Internet
La règle NSG dans network/main.tf utilise source_address_prefix = "*" au lieu de var.admin_allowed_cidr. Checkov peut passer cette vérification car il voit var.admin_allowed_cidr comme attribut (non "*"). Pipeline vert → VM Azure avec port 22 accessible depuis 0.0.0.0/0.
Raison 2 : Images CI non scannées
Trivy scanne alpine:3.21. Les images réelles (scan-tools, deploy-tools) ne sont jamais vérifiées. Une compromission supply chain de ces images = accès aux credentials Azure ARM dans l'environnement d'exécution. Pipeline vert → images potentiellement backdoorées.
Raison 3 : Shadow IT
Un développeur crée un Storage Account public via portail Azure pendant le weekend. Le lundi, le pipeline tourne normalement et est vert. Le Storage Account public est invisible à tous les outils.
Raison 4 : Post-deployment config changes
La VM déployée via OpenTofu a un NSG correct à T+0. À T+2h, un ops modifie la règle NSG via portail pour "debug temporaire" et oublie de la remettre. Le prochain pipeline est vert (il scanne l'IaC, pas l'infra réelle). Le drift engine détectera ce changement uniquement au prochain scheduled run (ex: 24h plus tard).
Raison 5 : Credential dans les artefacts
yaml# deploy-infrastructure
artifacts:
  paths:
    - .cloudsentinel/terraform_outputs_student_secure.json
Les outputs Terraform peuvent contenir des IPs, des noms de ressources, des connection strings. Ces artefacts sont stockés dans GitLab CI pendant 30 jours avec expire_in: 30 days. Tout utilisateur ayant accès au projet GitLab peut les télécharger.
Scénarios d'attaque concrets malgré pipeline vert
Scénario A — Exploitation SSH publique :
1. shodan.io → port 22 ouvert sur IP Azure (NSG bug)
2. SSH brute-force ou CVE sshd récent
3. Accès VM → env vars runner → ARM credentials
4. az resource create → infrastructure parallèle malveillante
→ Pipeline : vert ✅ | Infrastructure : compromise ❌

Scénario B — Supply chain CI :
1. Compromission du GitLab Registry via PAT leaked
2. Nouveau push sur l'image scan-tools:latest (même digest si rebuild)
3. Backdoor exfiltre ARM_CLIENT_SECRET pendant le pipeline
→ Pipeline : vert ✅ | Credentials : volés ❌

Scénario C — Lateral movement post-deploy :
1. CVE dans une lib Python du projet (pas dans les deps Trivy scannées)
2. Execution code dans le container applicatif
3. IMDS Azure (http://169.254.169.254) → MSI token
4. Accès Key Vault → secrets
→ Pipeline : vert ✅ | Données : exfiltrées ❌

8. POSITIONNEMENT DU PROJET
CloudSentinel est-il un pipeline DevSecOps ou un outil CSPM ?
CloudSentinel est un pipeline DevSecOps avec une composante CSPM embryonnaire.
CritèrePipeline DevSecOpsCSPMCloudSentinelScan pre-commit✅❌✅Scan CI/CD✅❌✅Policy-as-Code✅✅✅ (OPA)Inventaire cloud complet❌✅❌Drift detection❌✅⚠️ (tf-aware)Runtime security❌✅❌Remédiation automatique❌✅⚠️ (placeholder)IAM analysis❌✅❌Continuous monitoring❌✅⚠️ (scheduled)
Positionnement marché comparatif :

vs Prisma Cloud / Wiz : CloudSentinel couvre le shift-left (comparable), mais zéro runtime, zéro inventaire cloud, zéro CIEM (Cloud Infrastructure Entitlement Management). Prisma/Wiz sont des CNAPP (Cloud-Native Application Protection Platform) full-stack.
vs Checkov Cloud / Bridgecrew : Overlap fort sur le scanning IaC. CloudSentinel ajoute la couche OPA de décision centralisée et la gouvernance des exceptions — c'est sa différenciation.
vs Microsoft Defender CSPM : Pas de comparaison possible — Defender CSPM est un service managé Azure avec accès à l'Azure Resource Graph. CloudSentinel est un framework open-source DevSecOps.

La juste caractérisation académique : CloudSentinel est un framework DevSecOps open-source orienté Shift-Left/Shift-Right avec un moteur de décision OPA centralisé et une intégration native Azure. Il n'est pas un CSPM mais implémente certaines de ses fonctions de façon partielle.

9. SÉPARATION DES RESPONSABILITÉS
Architecture réelle
CoucheComposantResponsabilitéCorrect ?DétectionGitleaksSecrets✅DétectionCheckovIaC misconfig✅DétectionTrivyCVE + misconfig✅Normalisationnormalize.pyUnification JSON✅Normalisationfetch-exceptions.pyExceptions DefectDojo → OPA✅Décisionpipeline_decision.regoAllow/Deny✅Enforcementrun-opa.sh (PEP)Exit code pipeline✅Reportingupload-to-defectdojo.shTraçabilité✅Guardretry-guard.shAbus retry✅Guardimmutability.shProtection policies✅
La séparation des responsabilités est l'un des points les plus forts de CloudSentinel. Chaque composant a un rôle clair et unique. OPA est le seul décideur. Les scanners ne décident pas, ils détectent.
Violations identifiées
Violation mineure #1 : normalize.py calcule les thresholds (critical_max, high_max) depuis les variables d'environnement CI et les écrit dans le quality_gate du golden_report. OPA lit ces thresholds depuis l'input. Techniquement, la normalisation porte des paramètres de décision — ce n'est pas une violation grave, mais les thresholds devraient idéalement être des constantes Rego.
Violation mineure #2 : fetch-exceptions.py est invoqué dans le stage normalize (via normalize-reports.sh), pas dans un stage fetch dédié. Mélange fonctionnel normalisation/fetch dans un même job.

10. UTILISATION RÉELLE DES OUTILS
Gitleaks
Utilisation correcte. Mode detect sur full history, config hybride, output JSON pour normalisation. Pré-commit hook disponible. Seul manque : scan des variables CI.
Checkov
Utilisation correcte mais avec limitation structurelle. Bien configuré, bonne séparation des frameworks, policies custom pertinentes. La limitation intrinsèque (valeurs variables non résolues) n'est pas contournable sans terraform plan préalable.
Amélioration possible : Exécuter terraform plan -out=tfplan puis terraform show -json tfplan et passer le plan JSON à Checkov via --file tfplan.json — Checkov supporte les plans Terraform JSON et voit les valeurs résolues. C'est une évolution architecturale significative qui résoudrait la faille NSG.
Trivy
Utilisation partiellement incorrecte. FS scan et config scan : correct. Image scan : target hardcodée sur alpine:3.21 = non-utilisation effective.
OPA
Utilisation avancée. OPA est utilisé comme un vrai PDP enterprise, pas comme un simple script de validation. La policy est structurée, testée (test_pipeline_decision.rego), et couvre des cas edge complexes (scope-aware exceptions, partial mismatch diagnostics). C'est l'utilisation la plus sophistiquée du projet.
DefectDojo
Utilisation correcte pour le reporting, non-optimale pour la résilience. L'upload de raw reports avec parsers natifs est le bon pattern. Le allow_failure: false créé une fragilité non-nécessaire.
Drift Engine (Terraform)
Utilisation correcte de terraform plan -refresh-only. C'est la méthode officielle pour la détection de drift Terraform. La limitation est dans le scope (tf-aware uniquement), pas dans l'usage de l'outil.

11. POINTS FORTS / POINTS FAIBLES
Points forts

OPA comme PDP unique : architecture PEP/PDP correctement séparée, policy robuste, exception governance niveau enterprise avec SHA256 IDs, four-eyes principle, scope-aware matching
Images CI pinnées par digest SHA256 : protection supply chain sur les images CI elles-mêmes
Policy immutability guard : protection des fichiers de sécurité contre modification non-autorisée
Normalisation unifiée : golden_report.json comme contrat unique entre détection et décision
partial_mismatch_reasons : diagnostic d'exceptions avancé, rare même en production enterprise
Fail-closed sur scanner manquant : scanner_not_run → deny
Retry guard : protection contre l'abus de pipeline retry pour contourner les blocages
Audit trail complet : audit_events.jsonl + decision_audit_events.jsonl
Architecture modulaire : séparation claire des responsabilités entre composants
Tests OPA : test_pipeline_decision.rego (couverture à évaluer)

Points faibles critiques

NSG SSH ouvert à Internet (source_address_prefix = "*" au lieu de var.admin_allowed_cidr)
Trivy image scan hardcodé sur alpine:3.21 — les images CI réelles ne sont jamais scannées
Drift Engine sans OPA — decisions de drift non-gouvernées
Thresholds OPA injectables via variables CI — contournable par un maintainer GitLab
APPSEC_ALLOWED_USERS avec compte personnel (drghassen) en production potentielle
upload-to-defectdojo allow_failure: false — dépendance reporting sur le chemin critique
Scan IAM Azure absent — zéro couverture azurerm_role_assignment
Checkov analyse statique — valeurs variables Terraform non résolues
DinD sans TLS dans le drift pipeline
Shadow IT invisible — drift engine limité aux ressources Terraform-managed


12. VERDICT FINAL
Résumé exécutif
CloudSentinel est un framework DevSecOps académique de qualité supérieure à la moyenne des projets PFE/Master. L'architecture conceptuelle est correcte, la séparation des responsabilités est respectée, et la couche OPA est remarquablement avancée. Cependant, trois défauts critiques bloquent sa qualification production, et la couverture cloud réelle reste insuffisante pour prétendre à un statut CSPM.
Niveau de maturité
ComposantMaturitéArchitecture OPA / PDP⭐⭐⭐⭐⭐ Niveau enterpriseShift-left pipeline⭐⭐⭐⭐ Solide avec gapsGovernance des exceptions⭐⭐⭐⭐⭐ AvancéInfrastructure Terraform⭐⭐⭐ Correct mais bug NSGDrift Detection⭐⭐⭐ Partiel (tf-aware only)Runtime security⭐ AbsentCSPM coverage⭐ EmbryonnaireGlobal⭐⭐⭐ Solide pré-production
Top 5 risques

NSG SSH → Internet : exploitation directe, accès VM → credentials ARM
Images CI non scannées : supply chain attack sur les outils de sécurité eux-mêmes
Thresholds override possible : contournement de la gate OPA via variables CI
Pas d'OPA pour drift : findings shift-right non gouvernés
Artefacts Terraform avec données sensibles : outputs stockés 30 jours accessibles aux membres du projet

Focus réel : Pipeline vs Cloud
72% Pipeline / 28% Cloud. CloudSentinel sécurise principalement son propre pipeline de déploiement et l'IaC en pre-deploy. La sécurité cloud réelle (runtime, IAM, data plane, network flows) est presque entièrement hors scope dans l'implémentation actuelle.
Recommandations architecture (5 prioritaires)

Corriger le NSG SSH : var.admin_allowed_cidr dans la règle + Checkov sur plan JSON (valeurs résolues)
Scanner les images CI par digest : pipeline de validation des images avant usage
Thresholds dans la Rego policy : constantes non-injectables, override possible uniquement par la policy elle-même par environnement
OPA pour shift-right : normaliser les findings drift vers le golden_report schema, passer par OPA avant DefectDojo
upload-to-defectdojo allow_failure: true : découpler le reporting du chemin critique de déploiement

Verdict

NON PRODUCTION-READY dans l'état actuel.

Trois défauts critiques bloquants :

Faille sécurité infra (NSG SSH)
Fausse assurance de sécurité (Trivy alpine:3.21)
Gouvernance incomplète (drift sans OPA)


PRODUCTION-READY après correctifs P0 (NSG + Trivy cibles réelles + APPSEC_ALLOWED_USERS externalisé) et implémentation partielle du drift OPA.


Pour la soutenance académique : Le projet démontre une maîtrise réelle des concepts DevSecOps avancés (PEP/PDP, exception governance, policy immutability, audit trail). Les limitations doivent être présentées honnêtement comme un scope délibérément borné au shift-left/shift-right IaC-aware, distinct d'un CSPM complet. C'est la posture académique correcte.