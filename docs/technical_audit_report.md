# Audit Technique de l'Architecture CloudSentinel (Shift-Left to Deployment)

## 1. Executive Summary
L'architecture de CloudSentinel démontre une forte maturité DevSecOps. L'intégration de scanners spécialisés (Checkov, Gitleaks, Trivy) harmonisés via une **couche de normalisation métier** robuste et couplée à un moteur de décision centralisé (**Policy Decision Point - OPA**) représente un pattern de niveau entreprise ("State of the Art").

L'approche de conception est explicitement **Fail-Closed**, **Zero-Trust**, et impose des **Separations of Duties (SoD)** natives en tant que code. CloudSentinel est validé comme étant une architecture orientée production, malgré quelques ajustements d'implémentation recommandés pour parfaire sa sécurité globale.

---

## 2. Architecture Assessment

L'architecture s'établit sur une **Séparation des Responsabilités structurée** :
1. **Detection (Decouplée)** : L'exécution asynchrone / parallèle des wrappers de scan (Trivy, Gitleaks, Checkov).
2. **Normalization (Contract-driven)** : `normalize.py` standardise la donnée, assure un fingerprinting de déduplication, et valide le tout contre un schéma JSON local, assurant l'intégrité du Payload pour le moteur OPA.
3. **Decision & Governance (Policy as Code)** : OPA (`pipeline_decision.rego`) impose un `default allow := false` et s'appuie sur des règles métier complexes (gestion de cycle de vie des exceptions, interdiction stricte de production).
4. **Enforcement (PEP)** : Le script `run-opa.sh` agit en Policy Enforcement Point et refuse silencieusement de continuer (code de retour `1`) si aucune autorisation explicite n'émane d'OPA.
5. **Continuous Deployment** : Le déploiement (OpenTofu) est subordonné au succès strict du check OPA via le graphe de dépendance CI GitLab (`needs: [opa-decision]`).

---

## 3. Strengths (Points Forts Majeurs)

- **Paradigme "Fail-Closed" Strict** : Le framework normaliseur inclut la détection d'états d'erreur (`NOT_RUN`, JSON invalide, timeout). Si OPA identifie qu'un scanner requis manque (règle `scanner_not_run`), la gate échoue. Il n'y a pas de contournement par omission ("Bypass by missing dependency").
- **Gouvernance des Exceptions Intransigeante** : 
  - *Segregation of Duties* : Les politiques OPA exigent contractuellement que `requested_by != approved_by`.
  - *Contrôle Temporel strict* : Expiration validée dynamiquement contre `time.now_ns()`.
  - *Environnemental* : Les vulnérabilités "CRITICAL" acceptées sont re-bloquées dynamiquement pour le déploiement sur l'environnement de "Prod" (`prod_critical_exception_violation`).
- **Tolérance aux pannes du moteur de décision** : Le PEP (`run-opa.sh`) privilégie un serveur OPA (REST API) performant mais inclut intelligemment un *fallback* (OPA CLI `opa eval`) avec normalisation locale `jq`.
- **Infrastructure As Code Sécurisée** : L'utilisation d'OpenTofu dans `deploy-infrastructure.sh` manipule les états Terraform / Tofu avec une identité Azure Active directory et prohibe l'accès par token longue durée natif (`ARM_USE_AZUREAD=true`).

---

## 4. Weaknesses & Technical Debt

- **Endettement Cryptographique dans le Déploiement** : Le script de déploiement `deploy-infrastructure.sh` impose statiquement un format de clé SSH via une expression régulière stricte : `^ssh-rsa[[:space:]]+...`. Sachant que `ssh-rsa` est déprécié (vulnérabilités de l'algorithme SHA-1 par défaut sous plusieurs OS) au profit de clés plus robustes de type `ssh-ed25519`.
- **Couverture SAST/DAST Limitée** : CloudSentinel excelle pour les Configurations et Secret Scanning, et SCA/Conteneurs avec Trivy. Il manque l'analyse SAST approfondie sur l'applicatif de base pour être un véritable pipeline de Bout-en-Bout.
- **Cartographie Statique Checkov** : Dans `normalize.py`, l'outil effectue un mapping statique : `self.root / "shift-left" / "checkov" / "policies" / "mapping.json"`. La maintenance de de dictionnaire JSON risque de dévier des versions de Checkov, causant potentiellement un skew dans les assignations des niveaux de vulnérabilité.

---

## 5. Security Risks

- **RISQUE MOYEN - Intégrité du Pipeline Artifacts (`exceptions.json`)** : Bien que les étapes CI soient séquencées, les fichiers temporaires et les artéfacts `.cloudsentinel/exceptions.json` sont passés de job en job sans signature cryptographique intra-job (ex. via sigstore ou in-toto attestations). Un agent/runner GitLab compromis ou mal configuré pourrait injecter ou manipuler cet objet, bypassant la gouvernance intrinsèque sans être détecté.
- **RISQUE MOYEN/FAIBLE - Cryptographie de clé Publique obsolète** : Bloquer les développeurs sur une `ssh-rsa` pénalise la posture et pousse à utiliser une norme de signature asymétrique potentiellement sujette à risques cryptanalytiques.
- **RISQUE FAIBLE - Injection par "Fingerprint Collision"** : Le dictionnaire de déduplication asseoit un hachage asynchrone ; cela est mature, mais une attention doit être prêtée à l'intégrité du champ "Resource path" en amont (`_norm_path` purifie les `..` mais un path traversal malicieux depuis Gitleaks pourrait masquer le hachage).

---

## 6. Recommendations (Production-grade)

### Hardening de l'Architecture (Immédiat)
1. **Corriger le PEP CI Infra** : Modifiez l'expression régulière du script `deploy-infrastructure.sh` pour supporter explicitement `ssh-ed25519` : `grep -Eq '^(ssh-rsa|ssh-ed25519)[[:space:]]+...'`. Promouvoir par défaut Ed25519.
2. **Immutabilité via Signatures des Payload CI** : Signez cryptographiquement les artéfacts (tel que `golden_report.json` et `exceptions.json`) via la fonctionnalité GitLab CI (Sigstore / Cosign - on observe d'ailleurs que `cosign version` existe dans le conteneur). OPA doit idéalement valider cette signature (via un provider attestations in OPA) avant la décision.

### Évolutivité & DevSecOps (Court-Moyen Terme)
3. **Optimiser le Mapping Normalisateur** : Déplacer la logique statique Checkov et le fichier `gitleaks.toml` en tant que gestion dynamique avec support API au-dessus de OPA, ou garantir une mise à jour automatisée de ces configs `mapping.json`.
4. **Intégration exhaustive SAST** : Instanciez un Scanner SAST (SonarQube, Snyk Code) pour un spectre DevSecOps complet, normalisez sa sortie sous l'objet _golden_report_ et exigez le via le tableau `required_scanners` dans `pipeline_decision.rego`.

---

## 7. Final Verdict

**Production-Ready : ✅ OUI (Avec conditions mineures)**.

Le framework respecte intégralement les principes d'une sécurité intégrée "By Design". L'architecture dissocie proprement le capteur (Scanner) du vérificateur (OPA/Rego) pour centraliser la sécurité déclarative et asseoir une gouvernance anti-fraudes des exceptions.
L'implémentation est un excellent exemple de *Shift-Left CI* standardisée, prête à être déployable face à des tests d'audit externes, de compliance et de soutien académique. Il est attendu du DevOps de relâcher les contraintes limitatives cryptographiques (RSA vs Ed25519) avant le grand déploiement.
