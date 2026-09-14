#!/bin/bash

set -euo pipefail

# color
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# mount sta

PASS_COUNT=0
WARN_COUNT=0
RISK_COUNT=0

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS_COUNT++)) || true; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN_COUNT++)) || true; }
log_risk() { echo -e "${RED}[RISK]${NC} $1"; ((RISK_COUNT++)) || true; }
log_info() { echo -e "${CYAN}[INFO]${NC} $1"; }

header() {
	echo -e "\n${BOLD}=============================================================================="
	echo -e "${BOLD} $1${NC}"
	echo -e "${BOLD}================================================================================"
}

# detect os firewall
  
check_firewall() {
	header "1.Firewall status detect"

	if [ "$EUID" -ne 0 ]; then 
		log_warn "Now use normal user exec,some firewall rule need root premission can read"
	fi

	if command -v ufw &>/dev/null; then
		local ufw_status
		ufw_status=$(sudo -n ufw status 2>/dev/null || ufw status 2>/dev/null || echo "need_root")



