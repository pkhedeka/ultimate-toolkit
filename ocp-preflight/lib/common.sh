#!/bin/bash
# Shared functions for OCP pre-flight validator

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# Result counters
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
SKIP_COUNT=0

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    WARN_COUNT=$((WARN_COUNT + 1))
}

log_skip() {
    echo -e "${BLUE}[SKIP]${NC} $1"
    SKIP_COUNT=$((SKIP_COUNT + 1))
}

log_info() {
    echo -e "${BOLD}[INFO]${NC} $1"
}

log_section() {
    echo ""
    echo -e "${BOLD}--- $1 ---${NC}"
}

print_summary() {
    echo ""
    echo -e "${BOLD}========================================${NC}"
    echo -e "${BOLD}  Pre-flight Results${NC}"
    echo -e "${BOLD}========================================${NC}"
    echo -e "  ${GREEN}Passed:${NC}   ${PASS_COUNT}"
    echo -e "  ${RED}Failed:${NC}   ${FAIL_COUNT}"
    echo -e "  ${YELLOW}Warnings:${NC} ${WARN_COUNT}"
    echo -e "  ${BLUE}Skipped:${NC}  ${SKIP_COUNT}"
    echo -e "${BOLD}========================================${NC}"
    if [[ $FAIL_COUNT -gt 0 ]]; then
        echo -e "  ${RED}${BOLD}RESULT: FAIL — fix issues above before installing${NC}"
        return 1
    else
        echo -e "  ${GREEN}${BOLD}RESULT: PASS — prerequisites met${NC}"
        return 0
    fi
}

check_tool() {
    local tool="$1"
    local pkg="${2:-$1}"
    if command -v "$tool" &>/dev/null; then
        return 0
    else
        log_warn "Tool '${tool}' not found (install: ${pkg}). Some checks will be skipped."
        return 1
    fi
}

# --- DNS Checks ---

check_dns_a() {
    local fqdn="$1"
    local result
    result=$(dig +short "$fqdn" A 2>/dev/null | head -1)
    if [[ -n "$result" ]]; then
        log_pass "DNS: ${fqdn} -> ${result}"
        return 0
    else
        log_fail "DNS: ${fqdn} -> no A record found"
        return 1
    fi
}

check_dns_wildcard() {
    local cluster="$1"
    local domain="$2"
    local fqdn="test.apps.${cluster}.${domain}"
    local result
    result=$(dig +short "$fqdn" A 2>/dev/null | head -1)
    if [[ -n "$result" ]]; then
        log_pass "DNS: *.apps.${cluster}.${domain} -> ${result}"
        return 0
    else
        log_fail "DNS: *.apps.${cluster}.${domain} -> no wildcard record found"
        return 1
    fi
}

check_dns_ptr() {
    local ip="$1"
    local label="${2:-$ip}"
    local result
    result=$(dig -x "$ip" +short 2>/dev/null | head -1)
    if [[ -n "$result" ]]; then
        log_pass "DNS PTR: ${ip} -> ${result}"
        return 0
    else
        log_warn "DNS PTR: ${ip} (${label}) -> no PTR record"
        return 1
    fi
}

run_dns_checks() {
    local cluster="$1"
    local domain="$2"

    log_section "DNS Checks"

    if ! check_tool dig bind-utils; then
        log_skip "DNS checks require 'dig' (bind-utils)"
        return
    fi

    check_dns_a "api.${cluster}.${domain}"
    check_dns_a "api-int.${cluster}.${domain}"
    check_dns_wildcard "$cluster" "$domain"
}

# --- NTP Check ---

check_ntp() {
    log_section "NTP Check"

    if command -v chronyc &>/dev/null; then
        local leap
        leap=$(chronyc tracking 2>/dev/null | grep "Leap status" | awk -F: '{print $2}' | xargs)
        if [[ "$leap" == "Normal" ]]; then
            log_pass "NTP: chrony synchronized (${leap})"
        elif [[ -n "$leap" ]]; then
            log_warn "NTP: chrony leap status '${leap}'"
        else
            log_warn "NTP: chrony not responding"
        fi
    elif command -v timedatectl &>/dev/null; then
        local synced
        synced=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)
        if [[ "$synced" == "yes" ]]; then
            log_pass "NTP: system clock synchronized"
        else
            log_warn "NTP: system clock not synchronized"
        fi
    else
        log_skip "NTP: no chronyc or timedatectl found"
    fi
}

# --- Port Checks ---

check_port() {
    local host="$1"
    local port="$2"
    local label="${3:-${host}:${port}}"
    local timeout="${4:-5}"

    if nc -zv -w "$timeout" "$host" "$port" &>/dev/null 2>&1; then
        log_pass "Port: ${label} reachable"
        return 0
    else
        log_fail "Port: ${label} not reachable"
        return 1
    fi
}

check_port_warn() {
    local host="$1"
    local port="$2"
    local label="${3:-${host}:${port}}"
    local timeout="${4:-5}"

    if nc -zv -w "$timeout" "$host" "$port" &>/dev/null 2>&1; then
        log_pass "Port: ${label} reachable"
        return 0
    else
        log_warn "Port: ${label} not reachable"
        return 1
    fi
}

run_vip_port_checks() {
    local api_vip="$1"
    local ingress_vip="$2"

    log_section "VIP / Load Balancer Checks"

    if ! check_tool nc nmap-ncat; then
        log_skip "Port checks require 'nc' (nmap-ncat)"
        return
    fi

    if [[ -n "$api_vip" ]]; then
        check_port_warn "$api_vip" 6443 "API VIP ${api_vip}:6443"
        check_port_warn "$api_vip" 22623 "MCS VIP ${api_vip}:22623"
    else
        log_skip "API VIP not provided, skipping API port checks"
    fi

    if [[ -n "$ingress_vip" ]]; then
        check_port_warn "$ingress_vip" 443 "Ingress VIP ${ingress_vip}:443"
        check_port_warn "$ingress_vip" 80 "Ingress VIP ${ingress_vip}:80"
    else
        log_skip "Ingress VIP not provided, skipping ingress port checks"
    fi
}

# --- Pull Secret Check ---

check_pull_secret() {
    local secret_path="$1"

    log_section "Pull Secret Check"

    if [[ -z "$secret_path" ]]; then
        log_skip "Pull secret path not provided"
        return
    fi

    if [[ ! -f "$secret_path" ]]; then
        log_fail "Pull secret: file '${secret_path}' not found"
        return
    fi

    if ! python3 -c "import json; json.load(open('${secret_path}'))" 2>/dev/null; then
        log_fail "Pull secret: invalid JSON"
        return
    fi

    local has_rh
    has_rh=$(python3 -c "
import json, sys
data = json.load(open('${secret_path}'))
auths = data.get('auths', {})
registries = ['registry.redhat.io', 'quay.io', 'registry.connect.redhat.com']
found = [r for r in registries if r in auths]
print(' '.join(found))
" 2>/dev/null)

    if [[ -n "$has_rh" ]]; then
        log_pass "Pull secret: valid JSON, contains auth for: ${has_rh}"
    else
        log_warn "Pull secret: valid JSON but missing standard registry entries"
    fi

    if command -v podman &>/dev/null; then
        if podman login --authfile "$secret_path" registry.redhat.io --get-login &>/dev/null 2>&1; then
            log_pass "Pull secret: registry.redhat.io auth works"
        else
            log_warn "Pull secret: could not verify registry.redhat.io login (may need network)"
        fi
    fi
}

# --- SSH Key Check ---

check_ssh_key() {
    local key_path="${1:-${HOME}/.ssh/id_rsa.pub}"

    log_section "SSH Key Check"

    if [[ -f "$key_path" ]]; then
        log_pass "SSH key: ${key_path} exists"
    elif [[ -f "${HOME}/.ssh/id_ed25519.pub" ]]; then
        log_pass "SSH key: ${HOME}/.ssh/id_ed25519.pub exists"
    elif [[ -f "${HOME}/.ssh/id_rsa.pub" ]]; then
        log_pass "SSH key: ${HOME}/.ssh/id_rsa.pub exists"
    else
        log_fail "SSH key: no public key found in ~/.ssh/"
    fi
}

# --- Host Reachability ---

check_host_reachable() {
    local host="$1"
    local label="${2:-$host}"

    if ping -c 1 -W 3 "$host" &>/dev/null; then
        log_pass "Ping: ${label} reachable"
        return 0
    else
        log_fail "Ping: ${label} not reachable"
        return 1
    fi
}

# --- Disk / etcd fsync ---

check_etcd_disk() {
    log_section "Disk Performance (etcd fsync)"

    if ! command -v fio &>/dev/null; then
        log_skip "Disk: 'fio' not installed, skipping etcd fsync test"
        return
    fi

    local tmpdir
    tmpdir=$(mktemp -d)
    local result
    result=$(fio --name=etcd-fsync-test --filename="${tmpdir}/test" \
        --rw=write --ioengine=sync --fdatasync=1 --bs=2300 \
        --size=22m --runtime=10 --time_based \
        --output-format=json 2>/dev/null | \
        python3 -c "import json,sys; d=json.load(sys.stdin); print(d['jobs'][0]['sync']['lat_ns']['percentile']['99.000000'])" 2>/dev/null)
    rm -rf "$tmpdir"

    if [[ -n "$result" ]]; then
        local ms
        ms=$(python3 -c "print(f'{${result}/1e6:.2f}')" 2>/dev/null)
        if python3 -c "exit(0 if ${result} < 10000000 else 1)" 2>/dev/null; then
            log_pass "Disk: etcd fsync p99 = ${ms}ms (< 10ms requirement)"
        else
            log_warn "Disk: etcd fsync p99 = ${ms}ms (should be < 10ms for etcd)"
        fi
    else
        log_warn "Disk: fio test did not produce results"
    fi
}

# --- Prompt helper ---

prompt_value() {
    local var_name="$1"
    local prompt_text="$2"
    local default="${3:-}"
    local value

    if [[ -n "$default" ]]; then
        read -rp "${prompt_text} [${default}]: " value
        value="${value:-$default}"
    else
        read -rp "${prompt_text}: " value
    fi
    eval "${var_name}='${value}'"
}

prompt_value_secret() {
    local var_name="$1"
    local prompt_text="$2"
    local value

    read -rsp "${prompt_text}: " value
    echo ""
    eval "${var_name}='${value}'"
}

prompt_yes_no() {
    local prompt_text="$1"
    local default="${2:-n}"
    local answer

    if [[ "$default" == "y" ]]; then
        read -rp "${prompt_text} [Y/n]: " answer
        answer="${answer:-y}"
    else
        read -rp "${prompt_text} [y/N]: " answer
        answer="${answer:-n}"
    fi

    [[ "${answer,,}" == "y" || "${answer,,}" == "yes" ]]
}

prompt_choice() {
    local prompt_text="$1"
    shift
    local options=("$@")
    local i

    echo -e "\n${BOLD}${prompt_text}${NC}" >&2
    for i in "${!options[@]}"; do
        echo "  $((i+1))) ${options[$i]}" >&2
    done

    local choice
    while true; do
        read -rp "Select [1-${#options[@]}]: " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#options[@]} )); then
            echo "${options[$((choice-1))]}"
            return
        fi
        echo "Invalid selection." >&2
    done
}
