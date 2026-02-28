#!/bin/bash
# ============================================================================
# CloudSentinel - Development Environment Setup
# Goal: Automate tool installation and version consistency for developers.
# ============================================================================

set -euo pipefail

# ANSI Color Codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  CloudSentinel — Professional Setup & Onboarding${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"

# 1. Path Management
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# 2. Version Definitions (Synced with .gitlab-ci.yml)
OPA_VERSION="1.13.1"
CHECKOV_VERSION="3.2.502"
TRIVY_VERSION="0.69.1"
GITLEAKS_VERSION="8.21.2"
TFLINT_VERSION="0.55.0"

check_tool() {
    local tool_name=$1
    local version_cmd=$2
    if command -v "$tool_name" >/dev/null 2>&1; then
        echo -e "[CHECK] $tool_name : ${GREEN}INSTALLED${NC} ($(eval "$version_cmd" | head -n1))"
        return 0
    else
        echo -e "[CHECK] $tool_name : ${RED}MISSING${NC}"
        return 1
    fi
}

echo -e "\n${YELLOW}[Step 1/4] Checking System Dependencies...${NC}"
check_tool "docker" "docker --version"
check_tool "jq" "jq --version"
check_tool "curl" "curl --version"
check_tool "git" "git --version"
check_tool "python3" "python3 --version"

echo -e "\n${YELLOW}[Step 2/4] Checking Cloud Security Tools...${NC}"
check_tool "opa" "opa version" || echo -e "  ${YELLOW}Tip: Install OPA via 'curl -L -o opa https://openpolicyagent.org/downloads/v${OPA_VERSION}/opa_linux_amd64 && chmod +x opa'${NC}"
check_tool "checkov" "checkov --version" || echo -e "  ${YELLOW}Tip: Install via 'pip3 install checkov==${CHECKOV_VERSION}'${NC}"
check_tool "trivy" "trivy --version" || echo -e "  ${YELLOW}Tip: Install via 'brew install trivy' or official deb/rpm repo.${NC}"
check_tool "gitleaks" "gitleaks version" || echo -e "  ${YELLOW}Tip: Install via 'brew install gitleaks' or GitHub releases.${NC}"

echo -e "\n${YELLOW}[Step 3/4] Configuring Git Hooks (Pre-commit)...${NC}"
# Use python3 -m pre_commit to be independent of PATH issues
if ! python3 -m pre_commit --version >/dev/null 2>&1; then
    echo -e "[HOOKS] pre-commit tool not found. ${YELLOW}Installing via pip...${NC}"
    pip3 install pre-commit --quiet || echo -e "${RED}Failed to install pre-commit automatically.${NC}"
fi

if [ -f "$REPO_ROOT/.pre-commit-config.yaml" ]; then
    cd "$REPO_ROOT"
    # Resolve core.hooksPath conflict
    if git config --get core.hooksPath >/dev/null 2>&1; then
        echo -e "[HOOKS] Detected 'core.hooksPath' conflict. ${YELLOW}Unsetting local hook path...${NC}"
        git config --unset core.hooksPath
    fi
    python3 -m pre_commit install
    echo -e "[HOOKS] ${GREEN}Git Hooks installed successfully.${NC}"
else
    echo -e "[HOOKS] ${RED}No .pre-commit-config.yaml found.${NC}"
fi

echo -e "\n${YELLOW}[Step 4/4] Validating Local Engine (OPA Server)...${NC}"
if docker compose ps | grep -q "cloudsentinel-opa-server.*Up"; then
    echo -e "[ENGINE] OPA Server : ${GREEN}RUNNING${NC}"
    HEALTH=$(curl -s "http://127.0.0.1:8181/health") || HEALTH="connection failed"
    if [[ "$HEALTH" == "{}" ]]; then
        echo -e "[ENGINE] OPA Health : ${GREEN}OK${NC}"
    else
        echo -e "[ENGINE] OPA Health : ${RED}FAILED ($HEALTH)${NC}"
    fi
else
    echo -e "[ENGINE] OPA Server : ${RED}STOPPED${NC}"
    echo -e "  ${YELLOW}Action: Run 'docker compose up -d' at the repo root.${NC}"
fi

echo -e "\n${BLUE}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Setup Analysis Complete! Check warnings above.${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
