#!/bin/bash
# ==============================================================================
# Script Name : security-port-audit.sh
# Description : 主機資安基線、外部監聽埠口暴露面與高危漏洞自動稽核腳本
# ==============================================================================
set -euo pipefail

# 1. 色彩與樣式定義
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# 計數器統計
PASS_COUNT=0
WARN_COUNT=0
RISK_COUNT=0

log_pass() { echo -e "${GREEN}[PASS]${NC}  ✅ $1"; ((PASS_COUNT++)) || true; }
log_warn() { echo -e "${YELLOW}[WARN]${NC}  ⚠️  $1"; ((WARN_COUNT++)) || true; }
log_risk() { echo -e "${RED}[RISK]${NC}  🚨 $1"; ((RISK_COUNT++)) || true; }
log_info() { echo -e "${CYAN}[INFO]${NC}  🔍 $1"; }

header() {
    echo -e "\n${BOLD}====================================================================${NC}"
    echo -e "${BOLD}   $1${NC}"
    echo -e "${BOLD}====================================================================${NC}"
}

# 2. 檢測作業系統防火牆狀態
check_firewall() {
    header "1. 邊界防火牆 (Firewall) 狀態檢測"
    
    if [ "$EUID" -ne 0 ]; then
        log_warn "目前以普通使用者權限執行，部分防火牆規則需 root 權限方可讀取"
    fi

    if command -v ufw &>/dev/null; then
        local ufw_status
        ufw_status=$(sudo -n ufw status 2>/dev/null || ufw status 2>/dev/null || echo "need_root")
        if [[ "$ufw_status" =~ "Status: active" ]]; then
            log_pass "UFW 防火牆已啟用 (Status: Active)"
        elif [[ "$ufw_status" == "need_root" ]]; then
            log_info "UFW 存在，但需 root 權限讀取狀態 (建議: sudo $0)"
        else
            log_risk "UFW 防火牆處於關閉狀態！外部流量可直接衝擊本機！"
        fi
    elif command -v iptables &>/dev/null; then
        local rule_count
        rule_count=$(iptables -L INPUT -n --line-numbers 2>/dev/null | grep -c '^[0-9]' || echo "-1")
        if [ "$rule_count" -gt 2 ]; then
            log_pass "iptables INPUT 鏈已配置防禦規則 (規則數: $rule_count)"
        elif [ "$rule_count" -eq -1 ]; then
            log_info "iptables 存在，需 root 權限讀取規則表"
        else
            log_warn "iptables 規則過於精簡或處於開放狀態 (INPUT 規則數: $rule_count)"
        fi
    else
        log_risk "系統未偵測到常見防火牆工具 (UFW / iptables)！"
    fi
}

# 3. 檢測 SSH 伺服端資安配置 (Hardening)
check_ssh() {
    header "2. SSH 伺服端安全設定檢測"
    
    # 檢查是否禁止 root 密碼遠端登入
    if grep -Eiq '^\s*PermitRootLogin\s+(yes)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null; then
        log_risk "SSH 允許 root 直接登入 (PermitRootLogin yes)，易遭暴力破解！建議改為 prohibit-password 或 no"
    else
        log_pass "SSH 已限制 root 遠端直接登入 (PermitRootLogin 非 yes)"
    fi

    # 檢查是否強制使用金鑰驗證
    if grep -Eiq '^\s*PasswordAuthentication\s+(yes)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null; then
        log_warn "SSH 仍允許密碼登入 (PasswordAuthentication yes)，建議過渡至純 Ed25519 公鑰認證"
    else
        log_pass "SSH 已停用密碼登入 (僅允許公鑰驗證，最高安全等級)"
    fi
}

# 4. 核心：外部監聽埠口 (Listening Ports) 與高危險服務暴露分析
check_ports() {
    header "3. 網路監聽埠口暴露面深度分析 (Listening Ports Audit)"
    
    log_info "正在使用 ss 分析所有 TCP/UDP 監聽埠口..."
    
    # 宣告已知高危端口資料字典 (Port:風險描述)
    declare -A HIGH_RISK_PORTS=(
        [21]="FTP 傳輸 (明文傳輸帳密，極高風險)"
        [23]="Telnet (明文遠端協定，強烈建議停用)"
        [2375]="Docker Daemon Remote API (無授權將導致直接被拿 Host Root)"
        [3306]="MySQL 資料庫 (若非必要不應暴露給 0.0.0.0 公網)"
        [5432]="PostgreSQL 資料庫 (若非必要不應暴露給 0.0.0.0 公網)"
        [6379]="Redis 快取服務 (若無密碼且暴露公網，易遭未授權 RCE 植入挖礦木馬)"
        [27017]="MongoDB 資料庫 (歷史著名勒索高危暴露目標)"
    )

    # 提取所有監聽端口：協議、本地地址、程序名稱
    # 排除 127.0.0.1、::1 等本機安全迴路 (Loopback)
    local exposed_count=0
    
    while read -r proto laddr pid_prog; do
        [ -z "$laddr" ] && continue
        
        # 拆分 IP 與 Port (相容 IPv4 與 IPv6 格式)
        local port="${laddr##*:}"
        local ip="${laddr%:*}"

        # 僅審查對外全網開放的埠 (0.0.0.0 或 *)
        if [[ "$ip" == "*" || "$ip" == "0.0.0.0" || "$ip" == "[::]" ]]; then
            ((exposed_count++)) || true
            
            # 檢查是否名列高危險清單
            if [[ -v HIGH_RISK_PORTS[$port] ]]; then
                log_risk "高危服務對外全網暴露！${proto^^} Port: ${port} | 服務: ${HIGH_RISK_PORTS[$port]} (進程: $pid_prog)"
            else
                case "$port" in
                    22)
                        log_pass "管理連接埠: SSH (${proto^^} 22) 開放中 (進程: $pid_prog)"
                        ;;
                    80|443)
                        log_pass "Web 服務入口: HTTP/HTTPS (${proto^^} ${port}) 正常對外監聽 (進程: $pid_prog)"
                        ;;
                    *)
                        log_warn "一般服務對外全網監聽: ${proto^^} Port: ${port} (進程: $pid_prog，請確認是否有必要暴露)"
                        ;;
                esac
            fi
        fi
    done < <(ss -tulpn -H | awk '{print $1, $5, $7}')

    if [ "$exposed_count" -eq 0 ]; then
        log_pass "未發現任何對外 (0.0.0.0) 監聽的 TCP/UDP 埠口！"
    fi
}

# 5. 檢測全域可寫與異常 SUID 特權提權隱患
check_privileges() {
    header "4. 系統特權與檔案提權風險 (Privilege Escalation Audit)"
    
    # 檢查是否有無密碼的影子帳號 (Shadow without password)
    if [ "$EUID" -eq 0 ]; then
        local empty_pw_users
        empty_pw_users=$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null || true)
        if [ -n "$empty_pw_users" ]; then
            log_risk "發現空密碼帳號：$empty_pw_users (任何人皆可直接登入！)"
        else
            log_pass "無空密碼使用者帳號"
        fi
    else
        log_info "非 root 權限執行，略過 /etc/shadow 密碼檢驗"
    fi

    # 檢查非標準的危險 SUID 提權二進位檔案 (例如 nmap, vim, find, bash)
    local dangerous_suids=("vim" "find" "bash" "python" "perl" "nmap")
    local found_suid=0
    for bin in "${dangerous_suids[@]}"; do
        local suid_path
        suid_path=$(find /bin /usr/bin /usr/local/bin -name "$bin" -perm -4000 2>/dev/null || true)
        if [ -n "$suid_path" ]; then
            log_risk "發現危險 SUID 特權程式: $suid_path (普通使用者可用此直接提權 root！)"
            found_suid=1
        fi
    done
    [ "$found_suid" -eq 0 ] && log_pass "未發現常見的高危險 SUID 提權二進位檔"
}

# 6. 主程序與總結評估
main() {
    echo -e "${BOLD}${CYAN}🛡️  [$(hostname)] 虛擬機資安基線與暴露面自動化檢測開始...${NC}"
    
    check_firewall
    check_ssh
    check_ports
    check_privileges

    header "5. 稽核結果總覽與防護建議"
    echo -e "檢測通過項目 (PASS) : ${GREEN}${PASS_COUNT}${NC}"
    echo -e "建議關注項目 (WARN) : ${YELLOW}${WARN_COUNT}${NC}"
    echo -e "高危風險項目 (RISK) : ${RED}${RISK_COUNT}${NC}"

    if [ "$RISK_COUNT" -gt 0 ]; then
        echo -e "\n${RED}⚠️  警告：主機存在 ${RISK_COUNT} 項高危險資安隱患，建議依上方指引立即修正！${NC}"
        exit 1
    elif [ "$WARN_COUNT" -gt 0 ]; then
        echo -e "\n${YELLOW}💡 提示：主機基礎安全尚可，但有 ${WARN_COUNT} 項優化建議可進一步強化。${NC}"
    else
        echo -e "\n${GREEN}🎉 完美：主機資安基線檢測全數通過，無異常暴露埠口！${NC}"
    fi
}

main "$@"
