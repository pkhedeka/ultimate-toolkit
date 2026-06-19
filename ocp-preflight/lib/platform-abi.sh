#!/bin/bash
# Agent-Based Installer pre-flight checks

run_abi_checks() {
    local install_config_json="$1"
    local agent_config_path="$2"

    log_section "Agent-Based Installer Checks"

    check_abi_network_plugin "$install_config_json"
    check_abi_topology "$install_config_json"

    if [[ -n "$agent_config_path" && -f "$agent_config_path" ]]; then
        check_agent_config_syntax "$agent_config_path"
        local agent_json
        agent_json=$(parse_agent_config "$agent_config_path")
        if [[ -n "$agent_json" ]]; then
            check_abi_rendezvous_ip "$agent_json"
            check_abi_hosts "$agent_json"
            check_abi_nmstate "$agent_json"
            check_abi_vips "$install_config_json" "$agent_json"
        fi
    else
        log_warn "ABI: agent-config.yaml not found — some checks skipped"
        prompt_abi_manual_checks
    fi
}

check_abi_network_plugin() {
    local config_json="$1"
    local network_type
    network_type=$(get_config_value "$config_json" "network_type")

    if [[ "$network_type" == "OVNKubernetes" ]]; then
        log_pass "ABI: networkType is OVNKubernetes (required)"
    elif [[ -z "$network_type" ]]; then
        log_pass "ABI: networkType not set, defaults to OVNKubernetes"
    else
        log_fail "ABI: networkType is '${network_type}' — must be OVNKubernetes for ABI"
    fi
}

check_abi_topology() {
    local config_json="$1"
    local cp_replicas worker_replicas
    cp_replicas=$(get_config_value "$config_json" "control_plane_replicas")
    worker_replicas=$(get_config_value "$config_json" "worker_replicas")

    cp_replicas="${cp_replicas:-3}"
    worker_replicas="${worker_replicas:-2}"

    if [[ "$INSTALL_TYPE" == "SNO" ]]; then
        if [[ "$cp_replicas" == "1" && "$worker_replicas" == "0" ]]; then
            log_pass "ABI/SNO: topology correct (1 control plane, 0 workers)"
        else
            log_fail "ABI/SNO: topology must be 1 control plane + 0 workers (got ${cp_replicas} CP, ${worker_replicas} workers)"
        fi
    else
        if (( cp_replicas == 3 )); then
            log_pass "ABI: ${cp_replicas} control plane replicas"
        elif (( cp_replicas == 1 )); then
            log_warn "ABI: 1 control plane replica — this is SNO topology"
        else
            log_fail "ABI: control plane replicas must be 1 (SNO) or 3 (HA), got ${cp_replicas}"
        fi
        log_info "ABI: ${worker_replicas} worker replicas configured"
    fi
}

check_agent_config_syntax() {
    local config_path="$1"
    local result
    result=$(validate_yaml_syntax "$config_path")

    if [[ "$result" == "valid" ]]; then
        log_pass "ABI: agent-config.yaml syntax valid"
    else
        log_fail "ABI: agent-config.yaml syntax error — ${result}"
    fi
}

check_abi_rendezvous_ip() {
    local agent_json="$1"
    local rendezvous_ip
    rendezvous_ip=$(get_config_value "$agent_json" "rendezvous_ip")

    if [[ -z "$rendezvous_ip" ]]; then
        log_fail "ABI: rendezvousIP not specified in agent-config.yaml"
        return
    fi

    log_pass "ABI: rendezvousIP = ${rendezvous_ip}"

    if ping -c 1 -W 3 "$rendezvous_ip" &>/dev/null; then
        log_pass "ABI: rendezvousIP ${rendezvous_ip} reachable"
    else
        log_warn "ABI: rendezvousIP ${rendezvous_ip} not reachable (may be normal pre-boot)"
    fi
}

check_abi_hosts() {
    local agent_json="$1"
    local host_count
    host_count=$(get_config_value "$agent_json" "host_count")

    if [[ -z "$host_count" || "$host_count" == "0" ]]; then
        log_warn "ABI: no hosts defined in agent-config.yaml"
        return
    fi

    log_pass "ABI: ${host_count} host(s) defined in agent-config.yaml"

    while IFS='|' read -r name role bmc_addr ip; do
        [[ -z "$name" ]] && continue
        local role_info="${role:+ (${role})}"
        if [[ -n "$ip" ]]; then
            log_info "ABI: host '${name}'${role_info} — static IP ${ip}"
            if ping -c 1 -W 3 "$ip" &>/dev/null; then
                log_warn "ABI: ${ip} already responding (expected offline pre-boot, or existing host)"
            fi
        else
            log_info "ABI: host '${name}'${role_info} — DHCP/no static IP configured"
        fi
    done < <(get_config_hosts "$agent_json")
}

check_abi_nmstate() {
    local agent_json="$1"
    local has_nmstate

    has_nmstate=$(echo "$agent_json" | python3 -c "
import json, sys
d = json.load(sys.stdin)
has = any(h.get('has_nmstate', False) for h in d.get('hosts', []))
print('yes' if has else 'no')
" 2>/dev/null)

    if [[ "$has_nmstate" == "yes" ]]; then
        log_pass "ABI: NMState network config present for hosts (static IP)"
        if command -v nmstatectl &>/dev/null; then
            log_pass "ABI: nmstatectl available for validation"
        else
            log_warn "ABI: nmstatectl not installed — cannot validate NMState configs locally"
        fi
    else
        log_info "ABI: no NMState config — hosts will use DHCP"
    fi
}

check_abi_vips() {
    local install_json="$1"
    local agent_json="$2"

    local platform
    platform=$(get_config_value "$install_json" "platform")

    if [[ "$INSTALL_TYPE" == "SNO" ]]; then
        log_info "ABI/SNO: VIPs not required for single-node"
        return
    fi

    local api_vips ingress_vips
    api_vips=$(get_config_list "$install_json" "api_vips")
    ingress_vips=$(get_config_list "$install_json" "ingress_vips")

    if [[ -z "$api_vips" && "$platform" != "none" ]]; then
        log_fail "ABI: apiVIPs not specified (required for platform '${platform}')"
    elif [[ -n "$api_vips" ]]; then
        log_pass "ABI: apiVIPs configured: $(echo "$api_vips" | tr '\n' ' ')"
    fi

    if [[ -z "$ingress_vips" && "$platform" != "none" ]]; then
        log_fail "ABI: ingressVIPs not specified (required for platform '${platform}')"
    elif [[ -n "$ingress_vips" ]]; then
        log_pass "ABI: ingressVIPs configured: $(echo "$ingress_vips" | tr '\n' ' ')"
    fi
}

prompt_abi_manual_checks() {
    echo ""
    log_info "Without agent-config.yaml, checking basic ABI requirements:"

    local rendezvous_ip=""
    prompt_value rendezvous_ip "  Rendezvous IP (empty to skip)" ""
    if [[ -n "$rendezvous_ip" ]]; then
        if ping -c 1 -W 3 "$rendezvous_ip" &>/dev/null; then
            log_warn "ABI: rendezvousIP ${rendezvous_ip} already responding"
        else
            log_info "ABI: rendezvousIP ${rendezvous_ip} not responding (normal pre-boot)"
        fi
    fi
}
