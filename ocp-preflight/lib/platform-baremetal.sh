#!/bin/bash
# Bare Metal platform pre-flight checks

run_baremetal_checks() {
    local install_type="$1"

    log_section "Bare Metal Platform Checks"

    if [[ "$install_type" == "IPI" ]]; then
        run_bmc_checks
        run_provisioning_network_check
    fi

    run_node_reachability_checks
    run_internode_port_checks
    run_dhcp_check
}

run_bmc_checks() {
    log_section "BMC Connectivity (IPI)"

    if [[ ${#BMC_ADDRESSES[@]} -eq 0 ]]; then
        log_skip "No BMC addresses provided"
        return
    fi

    for i in "${!BMC_ADDRESSES[@]}"; do
        local addr="${BMC_ADDRESSES[$i]}"
        local user="${BMC_USERS[$i]:-}"
        local pass="${BMC_PASSWORDS[$i]:-}"
        local name="${BMC_NAMES[$i]:-host-$i}"

        local host port proto
        proto="https"
        if [[ "$addr" =~ ^(https?://)?(.*) ]]; then
            [[ -n "${BASH_REMATCH[1]}" ]] && proto="${BASH_REMATCH[1]%://}"
            addr="${BASH_REMATCH[2]}"
        fi
        addr="${addr%/}"

        host=$(echo "$addr" | cut -d: -f1 | cut -d/ -f1)
        port=$(echo "$addr" | grep -oP ':\K[0-9]+' | head -1)
        port="${port:-443}"

        if ! ping -c 1 -W 3 "$host" &>/dev/null; then
            log_fail "BMC: ${name} (${host}) not reachable"
            continue
        fi
        log_pass "BMC: ${name} (${host}) reachable"

        local redfish_url="${proto}://${addr}"
        if [[ "$addr" != *"/redfish"* ]]; then
            redfish_url="${proto}://${host}:${port}/redfish/v1/Systems"
        fi

        local http_code
        if [[ -n "$user" && -n "$pass" ]]; then
            http_code=$(curl -sk --connect-timeout 10 -o /dev/null -w "%{http_code}" \
                -u "${user}:${pass}" "$redfish_url" 2>/dev/null)
        else
            http_code=$(curl -sk --connect-timeout 10 -o /dev/null -w "%{http_code}" \
                "$redfish_url" 2>/dev/null)
        fi

        case "$http_code" in
            200)
                log_pass "BMC: ${name} Redfish API accessible (HTTP ${http_code})"
                ;;
            401)
                log_fail "BMC: ${name} Redfish auth failed (HTTP 401) — check credentials"
                ;;
            000)
                log_fail "BMC: ${name} Redfish API not responding at ${redfish_url}"
                ;;
            *)
                log_warn "BMC: ${name} Redfish returned HTTP ${http_code}"
                ;;
        esac

        if [[ -n "$user" && -n "$pass" ]]; then
            local ipmi_result
            if command -v ipmitool &>/dev/null; then
                ipmi_result=$(ipmitool -I lanplus -H "$host" -U "$user" -P "$pass" \
                    chassis status 2>&1)
                if [[ $? -eq 0 ]]; then
                    log_pass "BMC: ${name} IPMI accessible"
                else
                    log_warn "BMC: ${name} IPMI not accessible (Redfish may be sufficient)"
                fi
            fi
        fi
    done
}

run_provisioning_network_check() {
    log_section "Provisioning Network"

    if [[ -n "$PROVISIONING_NETWORK_CIDR" ]]; then
        log_pass "Provisioning network CIDR: ${PROVISIONING_NETWORK_CIDR}"
    else
        log_info "No provisioning network CIDR — using external network provisioning"
    fi

    if [[ -n "$PROVISIONING_BRIDGE" ]]; then
        if ip link show "$PROVISIONING_BRIDGE" &>/dev/null; then
            log_pass "Provisioning bridge '${PROVISIONING_BRIDGE}' exists on this host"
        else
            log_warn "Provisioning bridge '${PROVISIONING_BRIDGE}' not found on this host"
        fi
    fi

    if [[ -n "$EXTERNAL_BRIDGE" ]]; then
        if ip link show "$EXTERNAL_BRIDGE" &>/dev/null; then
            log_pass "External bridge '${EXTERNAL_BRIDGE}' exists on this host"
        else
            log_warn "External bridge '${EXTERNAL_BRIDGE}' not found on this host"
        fi
    fi
}

run_node_reachability_checks() {
    if [[ ${#NODE_IPS[@]} -eq 0 ]]; then
        return
    fi

    log_section "Node Reachability"

    for i in "${!NODE_IPS[@]}"; do
        local ip="${NODE_IPS[$i]}"
        local name="${NODE_NAMES[$i]:-node-$i}"
        check_host_reachable "$ip" "${name} (${ip})"
    done
}

run_internode_port_checks() {
    if [[ ${#NODE_IPS[@]} -eq 0 ]]; then
        return
    fi

    if ! check_tool nc nmap-ncat; then
        log_skip "Inter-node port checks require 'nc' (nmap-ncat)"
        return
    fi

    log_section "Inter-node Port Checks"

    local ports=(6443 22623 10250 2379 2380 9000 4789 6081)

    for i in "${!NODE_IPS[@]}"; do
        local ip="${NODE_IPS[$i]}"
        local name="${NODE_NAMES[$i]:-node-$i}"
        local accessible=0
        local total=0

        for port in "${ports[@]}"; do
            ((total++))
            if nc -zv -w 2 "$ip" "$port" &>/dev/null 2>&1; then
                ((accessible++))
            fi
        done

        if (( accessible == total )); then
            log_pass "Ports: ${name} (${ip}) — all ${total} ports accessible"
        elif (( accessible > 0 )); then
            log_warn "Ports: ${name} (${ip}) — ${accessible}/${total} ports accessible (some may open during install)"
        else
            log_warn "Ports: ${name} (${ip}) — no ports accessible yet (expected pre-install)"
        fi
    done
}

run_dhcp_check() {
    log_section "DHCP Check"

    if command -v nmap &>/dev/null; then
        local iface
        iface=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $5; exit}')
        if [[ -n "$iface" ]]; then
            log_info "Checking DHCP on interface ${iface} (may need root)..."
            local dhcp_result
            dhcp_result=$(timeout 10 nmap --script broadcast-dhcp-discover -e "$iface" 2>/dev/null)
            if echo "$dhcp_result" | grep -q "DHCPOFFER"; then
                local dhcp_server
                dhcp_server=$(echo "$dhcp_result" | grep "Server Identifier" | awk '{print $NF}')
                log_pass "DHCP: server found${dhcp_server:+ at ${dhcp_server}}"
            else
                log_warn "DHCP: no DHCP response detected on ${iface}"
            fi
        else
            log_skip "DHCP: could not determine default interface"
        fi
    else
        log_skip "DHCP: nmap not installed, skipping DHCP discovery"
    fi
}

prompt_baremetal_details() {
    local install_type="$1"

    log_info "Enter bare metal environment details:"
    echo ""

    prompt_value API_VIP "  API VIP address"
    prompt_value INGRESS_VIP "  Ingress VIP address"

    BMC_ADDRESSES=()
    BMC_USERS=()
    BMC_PASSWORDS=()
    BMC_NAMES=()
    NODE_IPS=()
    NODE_NAMES=()

    if [[ "$install_type" == "IPI" ]]; then
        echo ""
        log_info "Enter BMC details for each host (empty name to stop):"
        local idx=0
        while true; do
            local name="" addr="" user="" pass=""
            echo ""
            prompt_value name "  Host ${idx} name (empty to finish)" ""
            [[ -z "$name" ]] && break
            prompt_value addr "  Host ${idx} BMC address (e.g., 192.168.1.10 or redfish://host/path)"
            prompt_value user "  Host ${idx} BMC username" "admin"
            prompt_value_secret pass "  Host ${idx} BMC password"

            BMC_NAMES+=("$name")
            BMC_ADDRESSES+=("$addr")
            BMC_USERS+=("$user")
            BMC_PASSWORDS+=("$pass")
            ((idx++))
        done
    fi

    echo ""
    log_info "Enter node IPs for reachability checks (empty to stop):"
    local idx=0
    while true; do
        local ip="" name=""
        prompt_value ip "  Node IP (empty to finish)" ""
        [[ -z "$ip" ]] && break
        prompt_value name "  Node name" "node-${idx}"
        NODE_IPS+=("$ip")
        NODE_NAMES+=("$name")
        ((idx++))
    done

    prompt_value PROVISIONING_NETWORK_CIDR "  Provisioning network CIDR (empty if none)" ""
    prompt_value PROVISIONING_BRIDGE "  Provisioning bridge name (empty if none)" ""
    prompt_value EXTERNAL_BRIDGE "  External bridge name (empty if none)" ""
}

load_baremetal_from_config() {
    local config_json="$1"

    BMC_ADDRESSES=()
    BMC_USERS=()
    BMC_PASSWORDS=()
    BMC_NAMES=()
    NODE_IPS=()
    NODE_NAMES=()

    local api_vips ingress_vips
    api_vips=$(get_config_list "$config_json" "api_vips")
    ingress_vips=$(get_config_list "$config_json" "ingress_vips")
    API_VIP=$(echo "$api_vips" | head -1)
    INGRESS_VIP=$(echo "$ingress_vips" | head -1)

    PROVISIONING_NETWORK_CIDR=$(get_config_value "$config_json" "provisioning_network_cidr")
    PROVISIONING_BRIDGE=$(get_config_value "$config_json" "provisioning_bridge")
    EXTERNAL_BRIDGE=$(get_config_value "$config_json" "external_bridge")

    while IFS='|' read -r name role bmc_addr ip; do
        [[ -z "$name" ]] && continue
        BMC_NAMES+=("$name")
        NODE_NAMES+=("$name")
        if [[ -n "$bmc_addr" ]]; then
            BMC_ADDRESSES+=("$bmc_addr")
            BMC_USERS+=("")
            BMC_PASSWORDS+=("")
        fi
        if [[ -n "$ip" ]]; then
            NODE_IPS+=("$ip")
        fi
    done < <(get_config_hosts "$config_json")
}
