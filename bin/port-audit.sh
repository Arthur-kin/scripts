#!/bin/bash
# ==============================================================================
# Script Name : security-port-audit.sh
# Description : Host security baseline, listening ports & vulnerability audit
# ==============================================================================
set -euo pipefail

# color
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# count stats
PASS_COUNT=0
WARN_COUNT=0
RISK_COUNT=0

# log helper functions
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS_COUNT++)) || true; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN_COUNT++)) || true; }
log_risk() { echo -e "${RED}[RISK]${NC} $1"; ((RISK_COUNT++)) || true; }
log_info() { echo -e "${CYAN}[INFO]${NC} $1"; }

# section header
header() {
	echo -e "\n${BOLD}====================================================================${NC}"
	echo -e "${BOLD}   $1${NC}"
	echo -e "${BOLD}====================================================================${NC}"
}

# 1. detect os firewall
check_firewall() {
	header "1. Firewall status detect"

	if [ "$EUID" -ne 0 ]; then
		log_warn "Running as normal user, some firewall rules need root permission to read"
	fi

	if command -v ufw &>/dev/null; then
		local ufw_status
		ufw_status=$(sudo -n ufw status 2>/dev/null || ufw status 2>/dev/null || echo "need_root")
		if [[ "$ufw_status" =~ "Status: active" ]]; then
			log_pass "UFW firewall is active (Status: Active)"
		elif [[ "$ufw_status" == "need_root" ]]; then
			log_info "UFW detected, root permission required to view rules (try: sudo $0)"
		else
			log_risk "UFW firewall is inactive! Inbound traffic directly reaches host!"
		fi
	elif command -v iptables &>/dev/null; then
		local rule_count
		rule_count=$(iptables -L INPUT -n --line-numbers 2>/dev/null | grep -c '^[0-9]' || echo "-1")
		if [ "$rule_count" -gt 2 ]; then
			log_pass "iptables INPUT chain has active defense rules (rule count: $rule_count)"
		elif [ "$rule_count" -eq -1 ]; then
			log_info "iptables detected, root permission required to read rule table"
		else
			log_warn "iptables rules are minimal or wide open (INPUT rule count: $rule_count)"
		fi
	else
		log_risk "No standard firewall tool (UFW / iptables) detected!"
	fi
}

# 2. check ssh server hardening
check_ssh() {
	header "2. SSH server hardening audit"

	# check if direct root login is allowed
	if grep -Eiq '^\s*PermitRootLogin\s+(yes)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null; then
		log_risk "SSH permits direct root login (PermitRootLogin yes)! Vulnerable to brute force. Recommend: prohibit-password or no"
	else
		log_pass "SSH restricts direct root login (PermitRootLogin is not yes)"
	fi

	# check if password authentication is enabled
	if grep -Eiq '^\s*PasswordAuthentication\s+(yes)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null; then
		log_warn "SSH allows password authentication (PasswordAuthentication yes). Recommend: switch to Ed25519 public key"
	else
		log_pass "SSH password authentication disabled (public key only, high security)"
	fi
}

# 3. audit listening ports & attack surface
check_ports() {
	header "3. Network listening ports audit"

	log_info "Analyzing TCP/UDP listening ports with ss..."

	# high risk port dictionary (port: description)
	declare -A HIGH_RISK_PORTS=(
		[21]="FTP (cleartext credentials, high risk)"
		[23]="Telnet (cleartext protocol, strongly recommend disable)"
		[2375]="Docker Daemon Remote API (unauthenticated API grants host root)"
		[3306]="MySQL Database (should not expose to 0.0.0.0 public net)"
		[5432]="PostgreSQL Database (should not expose to 0.0.0.0 public net)"
		[6379]="Redis Cache (unprotected exposure leads to RCE and cryptominers)"
		[27017]="MongoDB Database (frequent ransomware target)"
	)

	local exposed_count=0

	# process substitution < <(...) avoids subshell variable loss
	while read -r proto laddr pid_prog; do
		[ -z "$laddr" ] && continue

		# parameter expansion: split IP and port
		local port="${laddr##*:}"
		local ip="${laddr%:*}"

		# only audit ports open to all interfaces (0.0.0.0, *, [::])
		if [[ "$ip" == "*" || "$ip" == "0.0.0.0" || "$ip" == "[::]" ]]; then
			((exposed_count++)) || true

			# check against high risk port dictionary
			if [[ -v HIGH_RISK_PORTS[$port] ]]; then
				log_risk "High-risk service exposed to public! ${proto^^} Port: ${port} | Service: ${HIGH_RISK_PORTS[$port]} (Process: $pid_prog)"
			else
				case "$port" in
					22)
						log_pass "Management port: SSH (${proto^^} 22) open (Process: $pid_prog)"
						;;
					80|443)
						log_pass "Web service port: HTTP/HTTPS (${proto^^} ${port}) listening (Process: $pid_prog)"
						;;
					*)
						log_warn "General service listening on all interfaces: ${proto^^} Port: ${port} (Process: $pid_prog, verify if necessary)"
						;;
				esac
			fi
		fi
	done < <(ss -tulpn -H | awk '{print $1, $5, $7}')

	if [ "$exposed_count" -eq 0 ]; then
		log_pass "No TCP/UDP ports listening on public wildcard (0.0.0.0)!"
	fi
}

# 4. check privilege escalation & SUID risks
check_privileges() {
	header "4. Privilege escalation & SUID audit"

	# check empty password accounts in /etc/shadow
	if [ "$EUID" -eq 0 ]; then
		local empty_pw_users
		empty_pw_users=$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null || true)
		if [ -n "$empty_pw_users" ]; then
			log_risk "Empty password account detected: $empty_pw_users (anyone can log in without password!)"
		else
			log_pass "No empty password user accounts"
		fi
	else
		log_info "Not running as root, skipping /etc/shadow password check"
	fi

	# check dangerous SUID binaries (GTFOBins attack vectors)
	local dangerous_suids=("vim" "find" "bash" "python" "perl" "nmap")
	local found_suid=0
	for bin in "${dangerous_suids[@]}"; do
		local suid_path
		suid_path=$(find /bin /usr/bin /usr/local/bin -name "$bin" -perm -4000 2>/dev/null || true)
		if [ -n "$suid_path" ]; then
			log_risk "Dangerous SUID binary detected: $suid_path (allows unprivileged user to escalate to root!)"
			found_suid=1
		fi
	done
	[ "$found_suid" -eq 0 ] && log_pass "No common high-risk SUID binaries found"
}

# 5. main function & summary
main() {
	echo -e "${BOLD}${CYAN}[$(hostname)] Security baseline & port audit starting...${NC}"

	check_firewall
	check_ssh
	check_ports
	check_privileges

	header "5. Audit summary & recommendations"
	echo -e "Passed items (PASS)   : ${GREEN}${PASS_COUNT}${NC}"
	echo -e "Warning items (WARN)  : ${YELLOW}${WARN_COUNT}${NC}"
	echo -e "High risk items (RISK): ${RED}${RISK_COUNT}${NC}"

	if [ "$RISK_COUNT" -gt 0 ]; then
		echo -e "\n${RED}Warning: Host has ${RISK_COUNT} high-risk security issue(s), fix immediately!${NC}"
		exit 1
	elif [ "$WARN_COUNT" -gt 0 ]; then
		echo -e "\n${YELLOW}Notice: Host baseline is acceptable, but has ${WARN_COUNT} recommendation(s).${NC}"
	else
		echo -e "\n${GREEN}Perfect: All security checks passed, no abnormal exposed ports!${NC}"
	fi
}

main "$@"
