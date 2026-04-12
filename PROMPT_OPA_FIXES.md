CONTEXTE
Tu interviens sur le projet CloudSentinel, un framework DevSecOps open-source.
Repository : gitlab.com/drghassen/pfe-cloud-sentinel
Un audit expert OPA a identifié 9 bugs sur la policy shift-right drift_decision.rego :

5 CRITIQUES (comportement FAIL-OPEN, crash silencieux, gaps architecturaux)
2 LOW (formatage, copy-paste)
2 COSMÉTIQUES

SCOPE STRICT : Tu ne touches QU'AUX fichiers shift-right.
INTERDIT : Toute modification sur pipeline_decision.rego, pipeline_decision_test.rego, ou tout fichier shift-left. Cette phase est validée et verrouillée.

RÈGLES D'INTERVENTION

AUCUNE modification shift-left. pipeline_decision.rego et ses tests sont VERROUILLÉS. Si tu identifies un besoin de modification shift-left, signale-le en commentaire mais ne touche à rien.
Ne casse AUCUN test existant. Avant toute modification, lance opa test sur le répertoire shift-right et confirme l'état initial.
Chaque fix doit être atomique — un commit logique par correction ou groupe de corrections liées.
Respecte le style existant — indentation, nommage, conventions du fichier cible.
Fail-closed PARTOUT — toute ambiguïté doit résulter en violation, jamais en pass silencieux.
Documente chaque correction avec un commentaire inline # FIX: <bug_id> — <description courte>.
Après chaque fix, relance opa test pour confirmer la non-régression.
Ne modifie PAS la logique métier existante sauf là où le bug l'exige explicitement.


ÉTAPE 0 — EXPLORATION
Avant de commencer, exécute :
bash# Localiser les fichiers shift-right
find . -path "*/shift-right*" -name "*.rego" -o -path "*drift*" -name "*.rego" | head -20

# Vérifier la structure actuelle
cat drift_decision.rego  # (adapter le chemin trouvé)

# Lancer les tests existants (s'il y en a)
opa test ./chemin/shift-right/ -v 2>&1 || echo "Aucun test existant"
Adapte TOUS les chemins dans les corrections ci-dessous à la structure réelle trouvée.

PHASE P0 — CORRECTIONS CRITIQUES
P0.1 — Ajouter les defaults pour éliminer le FAIL-OPEN
Bug : Si input.findings est absent ou null, violations et compliant deviennent undefined. OPA retourne {"result": {}} sans ces clés. Le client Python fait .get("violations", []) → interprète comme "aucune violation" → FAIL-OPEN.
Correction :
rego# FIX: P0.1 — Defaults fail-safe pour éviter FAIL-OPEN sur input manquant
default violations := []
default compliant := []
Place ces deux lignes avant les définitions de violations et compliant.
Vérification : Un appel OPA avec input: {} (sans clé findings) doit retourner :
json{"result": {"violations": [], "compliant": []}}
et NON {"result": {}}.

P0.2 — Ajouter les null-checks sur les champs finding dans evaluate_drift()
Bug : evaluate_drift(finding) accède directement à finding.address, finding.type, finding.provider_name sans vérification. Si un champ est absent, toute la règle devient undefined → le finding est silencieusement ignoré.
Correction :
Remplace la fonction evaluate_drift par deux clauses — une nominale avec guards, une fallback pour findings malformés :
rego# FIX: P0.2 — Null-safety sur les champs obligatoires du finding
evaluate_drift(finding) := decision if {
    # Guard : tous les champs obligatoires doivent exister
    finding.address
    finding.type
    finding.provider_name

    severity := determine_severity(finding)
    action := determine_action(severity, finding)
    custodian := get_custodian_policy(finding)

    decision := {
        "resource_id": finding.address,
        "resource_type": finding.type,
        "provider": finding.provider_name,
        "severity": severity,
        "action_required": action,
        "custodian_policy": custodian,
        "changed_paths": object.get(finding, "changed_paths", []),
        "reason": build_reason(severity, finding),
    }
}

# FIX: P0.2 — Fallback pour findings malformés (champs manquants)
evaluate_drift(finding) := decision if {
    not finding.address
    decision := _malformed_finding_decision(finding)
}

evaluate_drift(finding) := decision if {
    not finding.type
    decision := _malformed_finding_decision(finding)
}

evaluate_drift(finding) := decision if {
    not finding.provider_name
    decision := _malformed_finding_decision(finding)
}

_malformed_finding_decision(finding) := {
    "resource_id": object.get(finding, "address", "UNKNOWN"),
    "resource_type": object.get(finding, "type", "UNKNOWN"),
    "provider": object.get(finding, "provider_name", "UNKNOWN"),
    "severity": "LOW",
    "action_required": "manual_review",
    "custodian_policy": null,
    "changed_paths": object.get(finding, "changed_paths", []),
    "reason": "Finding with missing mandatory fields — requires manual review",
}
Justification architecturale : Un finding malformé ne doit JAMAIS être ignoré. Le classer LOW avec manual_review garantit qu'il apparaît dans violations[] et sera traité par un humain.

P0.3 — Fallback LOW pour ressources non classifiées (éliminer INFO par défaut)
Bug : Tout type de ressource absent de la liste de classification (azurerm_virtual_network, azurerm_app_service, azurerm_function_app, etc.) est classifié INFO = compliant. Un drift RÉEL sur ces ressources est silencieusement ignoré.
Correction :
Ajoute une règle is_low_drift comme catch-all après toutes les autres règles is_*_drift :
rego# FIX: P0.3 — Fallback LOW pour tout drift non classifié (élimine FAIL-OPEN via INFO)
# Toute ressource avec un drift actif mais non classifiée explicitement
# est au minimum LOW — jamais INFO (qui signifie "compliant")
is_low_drift(finding) if {
    count(object.get(finding, "changed_paths", [])) > 0
    not is_critical_drift(finding)
    not is_high_drift(finding)
    not is_medium_drift(finding)
}
Et modifie la chaîne determine_severity pour intégrer ce fallback :
rego# AVANT (FAIL-OPEN) :
# else := "INFO"

# APRÈS (FAIL-SAFE) :
determine_severity(finding) := "LOW" if {
    is_low_drift(finding)
} else := "INFO" if {
    # INFO uniquement si aucun changed_path → pas de drift réel détecté
    count(object.get(finding, "changed_paths", [])) == 0
} else := "LOW"  # FIX: P0.3 — Ultime fallback conservatif
Vérification : Un finding avec type: "azurerm_virtual_network" et changed_paths: ["address_space"] doit retourner severity: "LOW", PAS "INFO".

PHASE P1 — CORRECTIONS POUR SOUTENANCE
P1.1 — Créer drift_decision_test.rego (minimum 15 cas de test)
Fichier à créer : drift_decision_test.rego (même répertoire que drift_decision.rego)
Package : doit correspondre au package de drift_decision.rego (probablement package cloudsentinel.shiftright.drift)
Cas de test OBLIGATOIRES :
# ──────────────────────────────────────────────────
# Groupe 1 — Defaults et fail-safe (valide P0.1)
# ──────────────────────────────────────────────────
test_empty_input_returns_empty_violations        # input: {} → violations: []
test_null_findings_returns_empty_violations       # input: {findings: null} → violations: []
test_empty_findings_returns_empty_violations      # input: {findings: []} → violations: []

# ──────────────────────────────────────────────────
# Groupe 2 — Classification de sévérité
# ──────────────────────────────────────────────────
test_nsg_security_rule_drift_is_critical          # azurerm_network_security_group + security_rule → CRITICAL
test_nsg_rule_access_drift_is_critical            # azurerm_network_security_rule + access → CRITICAL
test_vm_admin_password_drift_is_critical          # azurerm_linux_virtual_machine + admin_password → CRITICAL
test_sql_server_password_drift_is_critical        # azurerm_sql_server + administrator_login_password → CRITICAL
test_keyvault_access_policy_drift_is_high         # azurerm_key_vault + access_policy → HIGH
test_storage_tls_drift_is_high                    # azurerm_storage_account + min_tls_version → HIGH
test_diagnostic_setting_drift_is_medium           # azurerm_monitor_diagnostic_setting + enabled_log → MEDIUM
test_log_analytics_retention_drift_is_low         # azurerm_log_analytics_workspace + retention_in_days → LOW

# ──────────────────────────────────────────────────
# Groupe 3 — Fallback et null-safety (valide P0.2, P0.3)
# ──────────────────────────────────────────────────
test_unknown_resource_type_drift_is_low_not_info  # azurerm_virtual_network + changed_paths → LOW (PAS INFO)
test_finding_missing_address_returns_low_manual    # finding sans .address → LOW + manual_review
test_finding_missing_type_returns_low_manual       # finding sans .type → LOW + manual_review

# ──────────────────────────────────────────────────
# Groupe 4 — Actions
# ──────────────────────────────────────────────────
test_critical_drift_action_is_immediate_review    # CRITICAL → immediate_review
test_high_storage_drift_action_is_auto_remediate  # HIGH + storage → auto_remediate
test_low_drift_action_is_monitor                  # LOW → monitor

# ──────────────────────────────────────────────────
# Groupe 5 — Custodian mapping
# ──────────────────────────────────────────────────
test_storage_tls_has_custodian_policy             # storage + min_tls_version → "enforce-storage-tls"
test_storage_public_blob_has_custodian_policy     # storage + allow_blob_public_access → "deny-public-storage"
test_nsg_has_custodian_policy                     # NSG + security_rule → "enforce-nsg-no-open-inbound" (après P1.3)
test_unknown_type_has_null_custodian_policy       # type inconnu → custodian_policy = null
Chaque test doit suivre ce pattern :
regotest_nsg_security_rule_drift_is_critical if {
    result := evaluate_drift({
        "address": "azurerm_network_security_group.test",
        "type": "azurerm_network_security_group",
        "provider_name": "registry.terraform.io/hashicorp/azurerm",
        "changed_paths": ["security_rule"],
    })
    result.severity == "CRITICAL"
}

test_finding_missing_address_returns_low_manual if {
    result := evaluate_drift({
        "type": "azurerm_storage_account",
        "provider_name": "registry.terraform.io/hashicorp/azurerm",
        "changed_paths": ["min_tls_version"],
    })
    result.severity == "LOW"
    result.action_required == "manual_review"
}
Après création, lance : opa test <chemin_shift_right>/ -v et confirme 100% pass.

P1.2 — Implémenter un mécanisme d'exceptions drift (simplifié)
Gap architectural : Aucun mécanisme d'exception n'existe côté shift-right. En production, cela garantit l'alert fatigue — les mêmes drifts légitimes (scaling d'urgence, maintenance) remontent chaque run sans possibilité d'exemption.
Implémentation (version Phase 1 pour soutenance) :
rego# FIX: P1.2 — Exception handling pour drift (Phase 1 simplifiée)
# Inspiré de pipeline_decision.rego (shift-left) mais scope réduit
# Phase 2 (post-soutenance) : aligner sur les 12 critères complets du shift-left

import data.cloudsentinel.drift_exceptions as drift_exceptions

# ── Validation d'une exception drift ──
valid_drift_exception(ex) if {
    # Source vérifiée (seul DefectDojo peut émettre des exceptions)
    ex.source == "defectdojo"
    # Status approuvé
    ex.status == "approved"
    # Four-eyes principle
    ex.requested_by != ex.approved_by
    # Temporalité : approuvée et non expirée
    time.parse_rfc3339_ns(ex.approved_at) <= time.now_ns()
    time.now_ns() < time.parse_rfc3339_ns(ex.expires_at)
    # Resource type obligatoire (pas de wildcard)
    ex.resource_type != ""
}

# ── Matching exception ↔ finding ──
drift_exception_matches(ex, finding) if {
    ex.resource_type == finding.resource_type
    ex.resource_id == finding.resource_id
}

# ── Findings effectifs = violations non exceptées ──
effective_violations := [v |
    some v in violations
    not _is_excepted_violation(v)
]

_is_excepted_violation(v) if {
    some ex in object.get(drift_exceptions, "exceptions", [])
    valid_drift_exception(ex)
    drift_exception_matches(ex, v)
}

# ── Métriques d'exceptions pour audit ──
drift_exception_summary := {
    "total_exceptions_loaded": count(object.get(drift_exceptions, "exceptions", [])),
    "valid_exceptions": count([ex |
        some ex in object.get(drift_exceptions, "exceptions", [])
        valid_drift_exception(ex)
    ]),
    "excepted_violations": count(violations) - count(effective_violations),
}
IMPORTANT :

Ne touche PAS aux violations existantes — effective_violations est un layer supplémentaire.
Le client Python consultera violations (brut) ou effective_violations (post-exceptions) selon le contexte.
Ajoute un commentaire en tête de section : # LIMITATION SCOPE : Phase 1 — 6 critères. Phase 2 alignera sur les 12 critères du shift-left (SHA256 ID, tool whitelist, no wildcard resource, severity rank map, etc.)


P1.3 — Mapper custodian_policy pour les types manquants
Bug : Seul azurerm_storage_account a des policies Custodian mappées (2/9 types). Les 7 autres retournent null.
Correction — ajouter les mappings suivants :
rego# FIX: P1.3 — Custodian policies pour types critiques et high
# NOTE: Les fichiers YAML Custodian correspondants seront créés en Phase P2 (post-soutenance).
# Ces identifiants servent de référence pour le mapping OPA → Cloud Custodian.

# NSG — CRITICAL
get_custodian_policy(finding) := "enforce-nsg-no-open-inbound" if {
    finding.type == "azurerm_network_security_group"
    "security_rule" in object.get(finding, "changed_paths", [])
}

get_custodian_policy(finding) := "enforce-nsg-rule-deny-all" if {
    finding.type == "azurerm_network_security_rule"
    "access" in object.get(finding, "changed_paths", [])
}

# VM — CRITICAL
get_custodian_policy(finding) := "enforce-vm-no-password-auth" if {
    finding.type == "azurerm_linux_virtual_machine"
    "admin_password" in object.get(finding, "changed_paths", [])
}

# SQL — CRITICAL
get_custodian_policy(finding) := "enforce-sql-password-rotation" if {
    finding.type == "azurerm_sql_server"
    "administrator_login_password" in object.get(finding, "changed_paths", [])
}

# Key Vault — HIGH
get_custodian_policy(finding) := "enforce-keyvault-access-policy" if {
    finding.type == "azurerm_key_vault"
    "access_policy" in object.get(finding, "changed_paths", [])
}

get_custodian_policy(finding) := "enforce-keyvault-network-acls" if {
    finding.type == "azurerm_key_vault"
    "network_acls" in object.get(finding, "changed_paths", [])
}
Placement : Insère ces règles avant le else := null existant de get_custodian_policy, pour que le fallback null ne s'applique qu'aux types réellement non couverts.

P1.4 — Fix cosmétique : build_reason() avec json.marshal()
Bug : %v dans sprintf produit une représentation Go-style des arrays. json.marshal() est plus propre.
rego# FIX: P1.4 — Utiliser json.marshal() pour les arrays dans les raisons
# AVANT : build_reason(severity, finding) := sprintf("Critical drift on %s: %v", [finding.type, finding.changed_paths])
# APRÈS :
build_reason(severity, finding) := sprintf("%s drift on %s: %s", [
    severity,
    object.get(finding, "type", "UNKNOWN"),
    json.marshal(object.get(finding, "changed_paths", [])),
])

CHECKLIST FINALE
Après toutes les corrections, vérifie :

 AUCUN fichier shift-left modifié — git diff ne montre AUCUN changement sur pipeline_decision.rego ou pipeline_decision_test.rego
 opa test <chemin_shift_right>/ -v → tous les tests passent (15+ tests, 100% pass)
 drift_decision.rego contient default violations := [] et default compliant := []
 drift_decision.rego contient les null-checks avec fallback _malformed_finding_decision
 drift_decision.rego contient le fallback is_low_drift (plus de INFO pour drift réel avec changed_paths)
 drift_decision.rego contient le mécanisme d'exceptions simplifié avec effective_violations
 drift_decision.rego contient les 6 nouveaux mappings Custodian
 drift_decision.rego contient build_reason avec json.marshal()
 drift_decision_test.rego existe avec minimum 15 cas couvrant les 5 groupes
 Chaque fix a son commentaire # FIX: P0.x / P1.x
 Aucun # TODO ou # FIXME laissé sans commentaire explicatif


FICHIERS CONCERNÉS (SCOPE STRICT)
# MODIFIABLE :
drift_decision.rego             # Toutes corrections P0 + P1

# À CRÉER :
drift_decision_test.rego        # P1.1 — 15+ tests

# VERROUILLÉ — NE PAS TOUCHER :
pipeline_decision.rego          # ❌ INTERDIT
pipeline_decision_test.rego     # ❌ INTERDIT

Adapte les chemins à la structure réelle du repo. Explore d'abord avec find . -name "*drift*" -name "*.rego".


RAPPEL ARCHITECTURAL
CloudSentinel Shift-Right — Flux de décision

Prowler (détection)
  → json_normalizer.py (normalisation)
    → drift_decision.rego (DÉCISION — ce fichier)
      → opa_client.py (enforcement / alerting)
        → DefectDojo (traçabilité)

OPA est le PDP (Policy Decision Point).
Il ne détecte rien, il ne remédie rien.
Il DÉCIDE sur la base d'un input normalisé.

Cloud Custodian = PEP (Policy Enforcement Point) — Phase 2.
Les custodian_policy retournées par OPA sont des RÉFÉRENCES
vers des policies Custodian à implémenter post-soutenance.
Si tu identifies un besoin de modification sur json_normalizer.py, opa_client.py ou tout fichier hors scope, signale-le dans un commentaire mais ne le modifie pas sans confirmation.