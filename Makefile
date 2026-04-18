# ============================================================================
# CloudSentinel - Makefile
# Commandes pratiques pour le développement et l'exploitation
# ============================================================================

.PHONY: help setup scan test clean deploy dashboard opa-test opa-test-gate opa-test-drift opa-test-system

# Couleurs pour l'affichage
GREEN  := $(shell tput -Txterm setaf 2)
YELLOW := $(shell tput -Txterm setaf 3)
WHITE  := $(shell tput -Txterm setaf 7)
RESET  := $(shell tput -Txterm sgr0)

# Configuration
ENV_FILE := .env
VENV := venv
GITLEAKS_VERSION ?= 8.21.2
CHECKOV_VERSION ?= 3.2.502
TRIVY_VERSION ?= 0.69.3
OPA_VERSION ?= 1.13.1

##@ Aide

help: ## Afficher cette aide
	@echo ''
	@echo '$(GREEN)CloudSentinel - Commandes Disponibles:$(RESET)'
	@echo ''
	@awk 'BEGIN {FS = ":.*##"; printf "\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  $(YELLOW)%-20s$(RESET) %s\n", $$1, $$2 } /^##@/ { printf "\n$(WHITE)%s$(RESET)\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
	@echo ''

##@ Setup & Installation

setup: ## Installation complète de l'environnement
	@echo "$(GREEN)🔧 Installation de l'environnement CloudSentinel...$(RESET)"
	@$(MAKE) install-tools
	@$(MAKE) config
	@echo "$(GREEN)✅ Setup terminé$(RESET)"

install-tools: ## Installer les outils de sécurité (Gitleaks, Checkov, Trivy, OPA)
	@echo "$(GREEN)📦 Installation des outils de sécurité...$(RESET)"
	@if ! command -v gitleaks >/dev/null 2>&1 || ! gitleaks version 2>/dev/null | grep -q "$(GITLEAKS_VERSION)"; then \
		echo "Installing Gitleaks $(GITLEAKS_VERSION)..."; \
		wget -q "https://github.com/gitleaks/gitleaks/releases/download/v$(GITLEAKS_VERSION)/gitleaks_$(GITLEAKS_VERSION)_linux_x64.tar.gz"; \
		tar -xzf "gitleaks_$(GITLEAKS_VERSION)_linux_x64.tar.gz"; \
		sudo mv gitleaks /usr/local/bin/; \
		rm -f "gitleaks_$(GITLEAKS_VERSION)_linux_x64.tar.gz"; \
	fi
	@if ! command -v checkov >/dev/null 2>&1 || ! checkov --version 2>/dev/null | grep -q "$(CHECKOV_VERSION)"; then \
		echo "Installing Checkov $(CHECKOV_VERSION)..."; \
		pip install "checkov==$(CHECKOV_VERSION)"; \
	fi
	@if ! command -v trivy >/dev/null 2>&1 || ! trivy --version 2>/dev/null | grep -q "$(TRIVY_VERSION)"; then \
		echo "Installing Trivy $(TRIVY_VERSION)..."; \
		wget -q "https://github.com/aquasecurity/trivy/releases/download/v$(TRIVY_VERSION)/trivy_$(TRIVY_VERSION)_Linux-64bit.tar.gz"; \
		tar -xzf "trivy_$(TRIVY_VERSION)_Linux-64bit.tar.gz"; \
		sudo mv trivy /usr/local/bin/; \
		rm -f "trivy_$(TRIVY_VERSION)_Linux-64bit.tar.gz"; \
	fi
	@if ! command -v opa >/dev/null 2>&1 || ! opa version 2>/dev/null | grep -q "$(OPA_VERSION)"; then \
		echo "Installing OPA $(OPA_VERSION)..."; \
		wget -q "https://openpolicyagent.org/downloads/v$(OPA_VERSION)/opa_linux_amd64_static" -O opa; \
		chmod +x opa; \
		sudo mv opa /usr/local/bin/; \
	fi
	@echo "$(GREEN)✅ Outils installés$(RESET)"

config: ## Créer le fichier .env depuis le template
	@if [ ! -f $(ENV_FILE) ]; then \
		cp .env.template $(ENV_FILE); \
		echo "$(YELLOW)⚠️  Fichier .env créé - Veuillez le configurer avec vos credentials$(RESET)"; \
	else \
		echo "$(GREEN)✅ Fichier .env existe déjà$(RESET)"; \
	fi

##@ Shift-Left (Sécurité Pré-Déploiement)

scan: ## Exécuter tous les scanners (Gitleaks, Checkov, Trivy)
	@echo "$(GREEN)🔍 Exécution du pipeline Shift-Left...$(RESET)"
	@bash scripts/verify-student-secure.sh infra/azure/student-secure alpine:3.21

scan-secrets: ## Scanner uniquement les secrets (Gitleaks)
	@echo "$(GREEN)🔐 Scan des secrets...$(RESET)"
	@gitleaks detect --source=infra/azure/student-secure --report-path=reports/gitleaks.json --no-git --exit-code=0

scan-iac: ## Scanner uniquement l'IaC (Checkov)
	@echo "$(GREEN)🏗️  Scan IaC...$(RESET)"
	@bash shift-left/checkov/run-checkov.sh infra/azure/student-secure

checkov-smoke: ## Smoke test des policies Checkov sur fixtures internes
	@echo "$(GREEN)🧪 Smoke Checkov (fixtures)...$(RESET)"
	@bash shift-left/checkov/tests/smoke.sh

gitleaks-test: ## Smoke test Gitleaks sur fixtures (positif + négatif)
	@echo "$(GREEN)🧪 Smoke test Gitleaks...$(RESET)"
	@bash shift-left/gitleaks/tests/smoke.sh

precommit-test: ## Smoke test pre-commit (advisory non-bloquant)
	@echo "$(GREEN)🧪 Smoke test pre-commit...$(RESET)"
	@bash shift-left/pre-commit/pre-commit.sh || true

normalizer-test: ## Smoke test normalizer (contrat schema + traçabilité)
	@echo "$(GREEN)🧪 Smoke test normalizer...$(RESET)"
	@bash shift-left/normalizer/tests/smoke.sh

gitleaks-update-baseline: ## Régénérer la baseline Gitleaks (faux positifs connus)
	@echo "$(YELLOW)⚠️  Régénération baseline Gitleaks — tous les findings actuels seront ignorés.$(RESET)"
	@read -p "Confirmez-vous ? (y/N) " confirm && [ $$confirm = y ] || exit 1
	@gitleaks detect \
		--source=. \
		--config=shift-left/gitleaks/gitleaks.toml \
		--report-format=json \
		--report-path=shift-left/gitleaks/.gitleaks-baseline.json \
		--exit-code=0 \
		--redact
	@echo "$(GREEN)✅ Baseline mise à jour : shift-left/gitleaks/.gitleaks-baseline.json$(RESET)"
	@echo "$(YELLOW)→ Revue et commit obligatoires avant push.$(RESET)"

scan-vulns: ## Scanner uniquement les vulnérabilités (Trivy)
	@echo "$(GREEN)🐛 Scan vulnérabilités...$(RESET)"
	@bash shift-left/trivy/scripts/run-trivy.sh infra/azure/student-secure config

trivy-test: ## Tests d'intégration Trivy (FS + config + contrat OPA)
	@echo "$(GREEN)🧪 Tests Trivy...$(RESET)"
	@bash shift-left/trivy/tests/integration/test-trivy.sh

opa-test: ## Tester les policies OPA (DB_PORTS + isolation gate/drift + opa check + tests scopés)
	@echo "$(GREEN)⚖️  Vérification DB_PORTS / db_ports...$(RESET)"
	@bash ci/scripts/verify-db-ports-sync.sh
	@bash ci/scripts/verify-opa-architecture.sh

opa-test-gate: ## Tests OPA uniquement shift-left gate (+ pipeline_decision_test)
	@opa test policies/opa/gate policies/opa/pipeline_decision_test.rego policies/opa/test_pipeline_decision.rego -v

opa-test-drift: ## Tests OPA uniquement shift-right drift (+ drift_decision_test)
	@opa test policies/opa/drift policies/opa/drift_decision_test.rego -v

opa-test-system: ## Tests OPA system.authz
	@opa test policies/opa/system/authz.rego policies/opa/system/authz_test.rego -v

opa-eval: ## Évaluer la décision OPA (Golden Report → cloudsentinel.gate.decision)
	@echo "$(GREEN)⚖️  Évaluation OPA...$(RESET)"
	@bash -c 'opa eval \
		--input .cloudsentinel/golden_report.json \
		--data .cloudsentinel/exceptions.json \
		--format pretty \
		"data.cloudsentinel.gate.decision" \
		$$(find policies/opa/gate -maxdepth 1 -name "*.rego" -type f | sort)'

##@ Shift-Right (Monitoring Runtime)

prowler: ## Exécuter un audit Prowler (CIS Benchmarks)
	@echo "$(GREEN)🔍 Audit Prowler Azure...$(RESET)"
	@cd shift-right/prowler && ./run-prowler.sh

custodian-dryrun: ## Exécuter Cloud Custodian en mode dry-run
	@echo "$(GREEN)☁️  Cloud Custodian (Dry-Run)...$(RESET)"
	@custodian run -s custodian-output/ policies/custodian/azure/ --dryrun

custodian-run: ## Exécuter Cloud Custodian (RÉEL - ATTENTION)
	@echo "$(YELLOW)⚠️  Cloud Custodian - Exécution RÉELLE$(RESET)"
	@read -p "Êtes-vous sûr ? (y/N) " confirm && [ $$confirm = y ] || exit 1
	@custodian run -s custodian-output/ policies/custodian/azure/

drift-detect: ## Détecter les drifts de configuration
	@echo "$(GREEN)🔄 Détection de drift...$(RESET)"
	@cd shift-right/drift-engine && python detect-drift.py

fetch-drift-exceptions: ## Récupérer les exceptions drift depuis DefectDojo (shift-right OPA)
	@echo "$(GREEN)📥 Fetch drift exceptions from DefectDojo...$(RESET)"
	@python shift-right/scripts/fetch_drift_exceptions.py \
		--output .cloudsentinel/drift_exceptions.json \
		--environment $${DRIFT_ENVIRONMENT:-production}
	@echo "$(GREEN)✅ drift_exceptions.json mis à jour$(RESET)"

##@ Infrastructure

terraform-init: ## Initialiser Terraform
	@echo "$(GREEN)🏗️  Terraform init...$(RESET)"
	@cd infra/azure/student-secure && terraform init

terraform-plan: ## Planifier le déploiement Terraform
	@echo "$(GREEN)📋 Terraform plan...$(RESET)"
	@cd infra/azure/student-secure && terraform plan

terraform-apply: ## Déployer l'infrastructure Terraform
	@echo "$(YELLOW)⚠️  Déploiement infrastructure$(RESET)"
	@cd infra/azure/student-secure && terraform apply

terraform-destroy: ## Détruire l'infrastructure Terraform
	@echo "$(YELLOW)⚠️  DESTRUCTION infrastructure$(RESET)"
	@read -p "Êtes-vous VRAIMENT sûr ? (y/N) " confirm && [ $$confirm = y ] || exit 1
	@cd infra/azure/student-secure && terraform destroy

##@ DefectDojo & Gouvernance

defectdojo-start: ## Démarrer DefectDojo (Docker)
	@echo "$(GREEN)📊 Démarrage DefectDojo...$(RESET)"
	@cd defectdojo && docker-compose up -d
	@echo "$(GREEN)✅ DefectDojo disponible sur http://localhost:8080$(RESET)"

defectdojo-stop: ## Arrêter DefectDojo
	@echo "$(YELLOW)📊 Arrêt DefectDojo...$(RESET)"
	@cd defectdojo && docker-compose down

defectdojo-setup: ## Configurer DefectDojo (products, engagements)
	@echo "$(GREEN)⚙️  Configuration DefectDojo...$(RESET)"
	@cd defectdojo && python setup-engagements.py

defectdojo-import: ## Importer les findings dans DefectDojo
	@echo "$(GREEN)📤 Import findings...$(RESET)"
	@cd defectdojo && python import-findings.py

##@ Monitoring & Dashboard

dashboard-start: ## Démarrer Grafana + Prometheus
	@echo "$(GREEN)📈 Démarrage dashboard...$(RESET)"
	@cd monitoring && docker-compose up -d
	@echo "$(GREEN)✅ Grafana: http://localhost:3000$(RESET)"
	@echo "$(GREEN)✅ Prometheus: http://localhost:9090$(RESET)"

dashboard-stop: ## Arrêter Grafana + Prometheus
	@echo "$(YELLOW)📈 Arrêt dashboard...$(RESET)"
	@cd monitoring && docker-compose down

##@ Tests

test: ## Exécuter tous les tests
	@echo "$(GREEN)🧪 Tests...$(RESET)"
	@make opa-test
	@echo "$(GREEN)✅ Tous les tests passés$(RESET)"

test-vulnerable-samples: ## Tester avec échantillons vulnérables
	@echo "$(GREEN)🧪 Test avec échantillons vulnérables...$(RESET)"
	@gitleaks detect --source=tests/vulnerable-samples --no-git --exit-code=0
	@checkov -d tests/vulnerable-samples
	@echo "$(GREEN)✅ Échantillons testés$(RESET)"

##@ Maintenance

clean: ## Nettoyer les artifacts et rapports
	@echo "$(GREEN)🧹 Nettoyage...$(RESET)"
	@rm -rf reports/*.json
	@rm -rf custodian-output/
	@rm -rf infra/azure/student-secure/.terraform
	@rm -rf infra/azure/student-secure/terraform.tfstate*
	@echo "$(GREEN)✅ Nettoyage terminé$(RESET)"

clean-all: clean ## Nettoyage complet (y compris Docker)
	@echo "$(YELLOW)🧹 Nettoyage complet...$(RESET)"
	@cd defectdojo && docker-compose down -v
	@cd monitoring && docker-compose down -v
	@echo "$(GREEN)✅ Nettoyage complet terminé$(RESET)"

logs: ## Afficher les logs Docker (DefectDojo + Monitoring)
	@docker-compose -f defectdojo/docker-compose.yml logs -f

##@ Développement

pre-commit-install: ## Installer le hook Git pre-commit
	@echo "$(GREEN)🪝 Installation pre-commit hook...$(RESET)"
	@cp shift-left/pre-commit/pre-commit.sh .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "$(GREEN)✅ Hook pre-commit installé$(RESET)"

validate: ## Valider la configuration (Terraform, OPA, etc.)
	@echo "$(GREEN)✅ Validation de la configuration...$(RESET)"
	@cd infra/azure/student-secure && terraform validate
	@cd policies/opa && opa check .
	@echo "$(GREEN)✅ Configuration valide$(RESET)"

docs: ## Générer la documentation (si applicable)
	@echo "$(GREEN)📚 Documentation disponible dans docs/$(RESET)"
	@echo "Voir docs/README.md pour l'index complet"

##@ Status

status: ## Afficher l'état des services
	@echo "$(GREEN)📊 État des services:$(RESET)"
	@echo ""
	@echo "DefectDojo:"
	@docker-compose -f defectdojo/docker-compose.yml ps 2>/dev/null || echo "  ❌ Arrêté"
	@echo ""
	@echo "Monitoring:"
	@docker-compose -f monitoring/docker-compose.yml ps 2>/dev/null || echo "  ❌ Arrêté"
	@echo ""

version: ## Afficher les versions des outils
	@echo "$(GREEN)🔧 Versions des outils:$(RESET)"
	@echo "Gitleaks:  $$(gitleaks version 2>/dev/null || echo 'Non installé')"
	@echo "Checkov:   $$(checkov --version 2>/dev/null || echo 'Non installé')"
	@echo "Trivy:     $$(trivy --version 2>/dev/null | head -n1 || echo 'Non installé')"
	@echo "OPA:       $$(opa version 2>/dev/null | head -n1 || echo 'Non installé')"
	@echo "Terraform: $$(terraform version 2>/dev/null | head -n1 || echo 'Non installé')"
	@echo "Custodian: $$(custodian version 2>/dev/null || echo 'Non installé')"


##@ Réseau & Sync

sync-ip: ## Synchroniser l'IP WSL avec les variables CI/CD GitLab
	@echo "$(GREEN)🔄 Synchronisation de l'IP WSL avec GitLab...$(RESET)"
	@/bin/bash ./update_gitlab_dojo_ip.sh

check-ip: ## Afficher l'IP actuelle de WSL
	@echo "$(GREEN)📍 IP WSL actuelle :$(RESET) $$(ip addr show eth0 | awk '/inet / {print $$2}' | cut -d/ -f1 | head -n 1)"