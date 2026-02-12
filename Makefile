# ============================================================================
# CloudSentinel - Makefile
# Commandes pratiques pour le développement et l'exploitation
# ============================================================================

.PHONY: help setup scan test clean deploy dashboard

# Couleurs pour l'affichage
GREEN  := $(shell tput -Txterm setaf 2)
YELLOW := $(shell tput -Txterm setaf 3)
WHITE  := $(shell tput -Txterm setaf 7)
RESET  := $(shell tput -Txterm sgr0)

# Configuration
ENV_FILE := .env
VENV := venv

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
	@./scripts/setup-dev-env.sh
	@echo "$(GREEN)✅ Setup terminé$(RESET)"

install-tools: ## Installer les outils de sécurité (Gitleaks, Checkov, Trivy, OPA)
	@echo "$(GREEN)📦 Installation des outils de sécurité...$(RESET)"
	@command -v gitleaks >/dev/null 2>&1 || (echo "Installing Gitleaks..." && wget -q https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz && tar -xzf gitleaks_8.18.0_linux_x64.tar.gz && sudo mv gitleaks /usr/local/bin/ && rm gitleaks_8.18.0_linux_x64.tar.gz)
	@command -v checkov >/dev/null 2>&1 || (echo "Installing Checkov..." && pip install checkov)
	@command -v trivy >/dev/null 2>&1 || (echo "Installing Trivy..." && wget -q https://github.com/aquasecurity/trivy/releases/download/v0.48.0/trivy_0.48.0_Linux-64bit.tar.gz && tar -xzf trivy_0.48.0_Linux-64bit.tar.gz && sudo mv trivy /usr/local/bin/ && rm trivy_0.48.0_Linux-64bit.tar.gz)
	@command -v opa >/dev/null 2>&1 || (echo "Installing OPA..." && wget -q https://openpolicyagent.org/downloads/v0.60.0/opa_linux_amd64 -O opa && chmod +x opa && sudo mv opa /usr/local/bin/)
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
	@cd scripts && ./run_prod_pipeline.sh

scan-secrets: ## Scanner uniquement les secrets (Gitleaks)
	@echo "$(GREEN)🔐 Scan des secrets...$(RESET)"
	@gitleaks detect --source=infra/azure/dev --report-path=reports/gitleaks.json --no-git --exit-code=0

scan-iac: ## Scanner uniquement l'IaC (Checkov)
	@echo "$(GREEN)🏗️  Scan IaC...$(RESET)"
	@checkov -d infra/azure/dev -o json > reports/checkov.json

scan-vulns: ## Scanner uniquement les vulnérabilités (Trivy)
	@echo "$(GREEN)🐛 Scan vulnérabilités...$(RESET)"
	@trivy config infra/azure/dev -f json > reports/trivy.json

opa-test: ## Tester les policies OPA
	@echo "$(GREEN)⚖️  Tests OPA...$(RESET)"
	@cd policies/opa && opa test . -v

opa-eval: ## Évaluer la décision OPA
	@echo "$(GREEN)⚖️  Évaluation OPA...$(RESET)"
	@opa eval -i reports/opa_input.json -d policies/opa/pipeline_decision.rego "data.ci.security" --format pretty

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

##@ Infrastructure

terraform-init: ## Initialiser Terraform
	@echo "$(GREEN)🏗️  Terraform init...$(RESET)"
	@cd infra/azure/dev && terraform init

terraform-plan: ## Planifier le déploiement Terraform
	@echo "$(GREEN)📋 Terraform plan...$(RESET)"
	@cd infra/azure/dev && terraform plan

terraform-apply: ## Déployer l'infrastructure Terraform
	@echo "$(YELLOW)⚠️  Déploiement infrastructure$(RESET)"
	@cd infra/azure/dev && terraform apply

terraform-destroy: ## Détruire l'infrastructure Terraform
	@echo "$(YELLOW)⚠️  DESTRUCTION infrastructure$(RESET)"
	@read -p "Êtes-vous VRAIMENT sûr ? (y/N) " confirm && [ $$confirm = y ] || exit 1
	@cd infra/azure/dev && terraform destroy

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
	@rm -rf infra/azure/dev/.terraform
	@rm -rf infra/azure/dev/terraform.tfstate*
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
	@cp shift-left/gitleaks/pre-commit-hook.sh .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "$(GREEN)✅ Hook pre-commit installé$(RESET)"

validate: ## Valider la configuration (Terraform, OPA, etc.)
	@echo "$(GREEN)✅ Validation de la configuration...$(RESET)"
	@cd infra/azure/dev && terraform validate
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
