#!/bin/bash
# vSphere platform pre-flight checks

run_vsphere_checks() {
    local vcenter="$1"
    local vcenter_user="$2"
    local vcenter_password="$3"
    local datacenter="$4"
    local vs_cluster="$5"
    local datastore="$6"
    local network="$7"
    local folder="$8"
    local resource_pool="$9"

    log_section "vSphere Platform Checks"

    check_vcenter_connectivity "$vcenter"
    check_vcenter_tls "$vcenter"

    if check_tool govc govc; then
        export GOVC_URL="https://${vcenter}/sdk"
        export GOVC_USERNAME="$vcenter_user"
        export GOVC_PASSWORD="$vcenter_password"
        export GOVC_INSECURE=1

        check_vcenter_auth
        check_vcenter_datacenter "$datacenter"
        check_vcenter_cluster "$datacenter" "$vs_cluster"
        check_vcenter_datastore "$datacenter" "$datastore"
        check_vcenter_network "$datacenter" "$network"
        [[ -n "$folder" ]] && check_vcenter_folder "$datacenter" "$folder"
        [[ -n "$resource_pool" ]] && check_vcenter_resource_pool "$resource_pool"
        check_vcenter_version
    else
        log_skip "govc not installed — skipping vCenter object validation"
        log_info "Install govc: https://github.com/vmware/govmomi/releases"
    fi
}

check_vcenter_connectivity() {
    local vcenter="$1"

    if curl -sk --connect-timeout 10 "https://${vcenter}/sdk" -o /dev/null 2>/dev/null; then
        log_pass "vCenter: ${vcenter} reachable on 443"
    else
        log_fail "vCenter: ${vcenter} not reachable on 443"
    fi
}

check_vcenter_tls() {
    local vcenter="$1"
    local issuer
    issuer=$(echo | openssl s_client -connect "${vcenter}:443" 2>/dev/null | \
        openssl x509 -noout -issuer 2>/dev/null)

    if [[ -z "$issuer" ]]; then
        log_warn "vCenter TLS: could not retrieve certificate"
        return
    fi

    if echo "$issuer" | grep -qi "self-signed\|vmware\|localhost"; then
        log_warn "vCenter TLS: certificate appears self-signed (${issuer})"
        log_info "  Self-signed certs may cause issues; add to additionalTrustBundle if needed"
    else
        log_pass "vCenter TLS: certificate issuer looks valid"
    fi
}

check_vcenter_auth() {
    local output
    output=$(govc about 2>&1)
    if [[ $? -eq 0 ]]; then
        local version
        version=$(echo "$output" | grep "Version:" | awk '{print $2}')
        log_pass "vCenter: authentication successful (version: ${version:-unknown})"
    else
        log_fail "vCenter: authentication failed — ${output}"
    fi
}

check_vcenter_version() {
    local version
    version=$(govc about -json 2>/dev/null | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print(d.get('about', {}).get('version', ''))
except: pass
" 2>/dev/null)

    if [[ -z "$version" ]]; then
        log_warn "vCenter: could not determine version"
        return
    fi

    local major minor
    major=$(echo "$version" | cut -d. -f1)
    minor=$(echo "$version" | cut -d. -f2)

    if (( major >= 8 )) || (( major == 7 && minor >= 0 )); then
        log_pass "vCenter: version ${version} meets minimum (7.0U2+)"
    else
        log_fail "vCenter: version ${version} does not meet minimum (7.0U2+)"
    fi
}

check_vcenter_datacenter() {
    local datacenter="$1"

    if [[ -z "$datacenter" ]]; then
        log_warn "vCenter: datacenter not specified"
        return
    fi

    if govc datacenter.info "/${datacenter}" &>/dev/null; then
        log_pass "vCenter: datacenter '${datacenter}' exists"
    else
        log_fail "vCenter: datacenter '${datacenter}' not found"
    fi
}

check_vcenter_cluster() {
    local datacenter="$1"
    local cluster="$2"

    if [[ -z "$cluster" ]]; then
        log_warn "vCenter: compute cluster not specified"
        return
    fi

    if govc cluster.rule.ls -cluster "/${datacenter}/host/${cluster}" &>/dev/null 2>&1 || \
       govc object.collect "/${datacenter}/host/${cluster}" name &>/dev/null 2>&1; then
        log_pass "vCenter: cluster '${cluster}' exists in datacenter '${datacenter}'"
    else
        log_fail "vCenter: cluster '${cluster}' not found in datacenter '${datacenter}'"
    fi
}

check_vcenter_datastore() {
    local datacenter="$1"
    local datastore="$2"

    if [[ -z "$datastore" ]]; then
        log_warn "vCenter: datastore not specified"
        return
    fi

    local ds_info
    ds_info=$(govc datastore.info -dc "/${datacenter}" "${datastore}" 2>/dev/null)
    if [[ $? -ne 0 ]]; then
        log_fail "vCenter: datastore '${datastore}' not found"
        return
    fi

    log_pass "vCenter: datastore '${datastore}' exists"

    local free_gb
    free_gb=$(echo "$ds_info" | grep "Free:" | awk '{print $2}' | sed 's/GB//')
    if [[ -n "$free_gb" ]]; then
        if python3 -c "exit(0 if float('${free_gb}') >= 100 else 1)" 2>/dev/null; then
            log_pass "vCenter: datastore '${datastore}' has ${free_gb}GB free (>= 100GB)"
        else
            log_fail "vCenter: datastore '${datastore}' has only ${free_gb}GB free (need >= 100GB)"
        fi
    fi
}

check_vcenter_network() {
    local datacenter="$1"
    local network="$2"

    if [[ -z "$network" ]]; then
        log_warn "vCenter: network/portgroup not specified"
        return
    fi

    if govc network.info -dc "/${datacenter}" "${network}" &>/dev/null; then
        log_pass "vCenter: network '${network}' exists"
    else
        log_fail "vCenter: network '${network}' not found"
    fi
}

check_vcenter_folder() {
    local datacenter="$1"
    local folder="$2"

    if govc folder.info "/${datacenter}/vm/${folder}" &>/dev/null 2>&1; then
        log_pass "vCenter: folder '${folder}' exists"
    else
        log_warn "vCenter: folder '${folder}' not found (installer may create it)"
    fi
}

check_vcenter_resource_pool() {
    local resource_pool="$1"

    if govc pool.info "${resource_pool}" &>/dev/null 2>&1; then
        log_pass "vCenter: resource pool '${resource_pool}' exists"
    else
        log_fail "vCenter: resource pool '${resource_pool}' not found"
    fi
}

prompt_vsphere_details() {
    log_info "Enter vSphere environment details:"
    echo ""
    prompt_value VCENTER "  vCenter FQDN or IP"
    prompt_value VCENTER_USER "  vCenter username" "administrator@vsphere.local"
    prompt_value_secret VCENTER_PASSWORD "  vCenter password"
    prompt_value DATACENTER "  Datacenter name"
    prompt_value VS_CLUSTER "  Compute cluster name"
    prompt_value DATASTORE "  Datastore name"
    prompt_value NETWORK "  Network/portgroup name"
    prompt_value FOLDER "  VM folder (leave empty if installer should create)" ""
    prompt_value RESOURCE_POOL "  Resource pool (leave empty for default)" ""
}
