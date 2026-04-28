#!/bin/bash
# ============================================================================
# secops-squad installer
# Usage: curl -fsSL https://raw.githubusercontent.com/x3nc0n/secops-squad/master/install.sh | bash
# ============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

REPO_URL="https://github.com/x3nc0n/secops-squad.git"
INSTALL_DIR="${SECOPS_SQUAD_DIR:-$HOME/secops-squad}"

print_banner() {
  echo ""
  echo -e "${CYAN}${BOLD}  ┌─────────────────────────────────────┐"
  echo -e "  │       secops-squad installer         │"
  echo -e "  │  AI SecOps team for Microsoft        │"
  echo -e "  │  Security stack                      │"
  echo -e "  └─────────────────────────────────────┘${RESET}"
  echo ""
}

check_command() {
  local cmd="$1"
  local name="$2"
  local install_url="$3"
  local required="$4"

  if command -v "$cmd" &>/dev/null; then
    local version
    version=$($cmd --version 2>&1 | head -1)
    echo -e "  ${GREEN}✅ ${name}: ${version}${RESET}"
    return 0
  else
    if [ "$required" = "true" ]; then
      echo -e "  ${RED}❌ ${name} not found${RESET}"
      echo -e "     ${DIM}Install: ${install_url}${RESET}"
      return 1
    else
      echo -e "  ${YELLOW}⚠️  ${name} not found (optional)${RESET}"
      echo -e "     ${DIM}Install: ${install_url}${RESET}"
      return 0
    fi
  fi
}

check_node_version() {
  if ! command -v node &>/dev/null; then
    echo -e "  ${RED}❌ Node.js not found${RESET}"
    echo -e "     ${DIM}Install Node.js 18+: https://nodejs.org${RESET}"
    return 1
  fi

  local version
  version=$(node -v)
  local major
  major=$(echo "$version" | sed 's/v//' | cut -d. -f1)

  if [ "$major" -ge 18 ]; then
    echo -e "  ${GREEN}✅ Node.js ${version} (>= 18 required)${RESET}"
    return 0
  else
    echo -e "  ${RED}❌ Node.js ${version} — version 18+ required${RESET}"
    echo -e "     ${DIM}Upgrade: https://nodejs.org${RESET}"
    return 1
  fi
}

main() {
  print_banner

  echo -e "${BOLD}Checking prerequisites...${RESET}\n"

  local failed=0

  check_node_version || failed=1
  check_command "git" "Git" "https://git-scm.com" "true" || failed=1
  check_command "gh" "GitHub CLI" "https://cli.github.com" "false"
  check_command "az" "Azure CLI" "https://aka.ms/installazurecli" "false"

  echo ""

  if [ "$failed" -eq 1 ]; then
    echo -e "${RED}${BOLD}Prerequisites check failed.${RESET}"
    echo -e "${DIM}Install the missing tools above and re-run this script.${RESET}\n"
    exit 1
  fi

  echo -e "${GREEN}✅ All required prerequisites met.${RESET}\n"

  # Clone or update the repository
  if [ -d "$INSTALL_DIR" ]; then
    echo -e "${CYAN}Updating existing installation at ${INSTALL_DIR}...${RESET}"
    cd "$INSTALL_DIR"
    git pull --quiet origin main 2>/dev/null || git pull --quiet origin master 2>/dev/null || true
  else
    echo -e "${CYAN}Cloning secops-squad to ${INSTALL_DIR}...${RESET}"
    git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
  fi

  # Install dependencies
  echo -e "${CYAN}Installing dependencies...${RESET}"
  npm install --production --quiet 2>/dev/null || true

  # Make CLI executable
  chmod +x cli/index.js 2>/dev/null || true

  # Add to PATH hint
  echo ""
  echo -e "${GREEN}${BOLD}✅ secops-squad installed!${RESET}"
  echo ""
  echo -e "${BOLD}To use the CLI, either:${RESET}"
  echo ""
  echo -e "  ${CYAN}1.${RESET} Add to PATH:"
  echo -e "     ${DIM}echo 'export PATH=\"${INSTALL_DIR}/cli:\$PATH\"' >> ~/.bashrc${RESET}"
  echo -e "     ${DIM}source ~/.bashrc${RESET}"
  echo ""
  echo -e "  ${CYAN}2.${RESET} Or run directly:"
  echo -e "     ${DIM}node ${INSTALL_DIR}/cli/index.js${RESET}"
  echo ""
  echo -e "${BOLD}Getting started:${RESET}"
  echo -e "  ${CYAN}cd ${INSTALL_DIR}${RESET}"
  echo -e "  ${CYAN}node cli/index.js init${RESET}"
  echo -e "  ${CYAN}node cli/index.js doctor${RESET}"
  echo ""
}

main "$@"
