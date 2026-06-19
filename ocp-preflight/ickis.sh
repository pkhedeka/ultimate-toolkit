#!/bin/bash
#
# Ickis — OCP Installation Pre-flight Validator
# "Scaring up install problems before they scare you!"
#
# Validates OpenShift Container Platform installation prerequisites
# before running openshift-install.
#
# Usage:
#   ./ickis.sh [install-config.yaml] [--agent-config agent-config.yaml]
#   ./ickis.sh                        # interactive mode
#   ./ickis.sh /path/to/install-dir/  # auto-detect configs in directory
#
# Supports: vSphere, Bare Metal (IPI/UPI), Agent-Based Installer, SNO
#

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source library modules
source "${SCRIPT_DIR}/lib/common.sh"
source "${SCRIPT_DIR}/lib/parse-config.sh"
source "${SCRIPT_DIR}/lib/platform-vsphere.sh"
source "${SCRIPT_DIR}/lib/platform-baremetal.sh"
source "${SCRIPT_DIR}/lib/platform-abi.sh"

# Globals
INSTALL_CONFIG_PATH=""
AGENT_CONFIG_PATH=""
INSTALL_CONFIG_JSON=""
PLATFORM=""
INSTALL_TYPE=""
CLUSTER_NAME=""
BASE_DOMAIN=""
API_VIP=""
INGRESS_VIP=""
PULL_SECRET_PATH=""

print_banner() {
    echo -e "${BOLD}"
    echo "╔══════════════════════════════════════════════════╗"
    echo "║   ICKIS — OCP Pre-flight Validator               ║"
    echo "║   Scaring up install problems before they        ║"
    echo "║   scare you!                                     ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

usage() {
    echo "Usage: $0 [OPTIONS] [install-config.yaml | install-dir]"
    echo ""
    echo "Options:"
    echo "  --agent-config FILE   Path to agent-config.yaml (ABI installs)"
    echo "  --pull-secret FILE    Path to pull-secret.json"
    echo "  --help                Show this help"
    echo ""
    echo "Examples:"
    echo "  $0                              # Interactive mode"
    echo "  $0 ./install-config.yaml        # Parse config, auto-detect platform"
    echo "  $0 /path/to/install-dir/        # Auto-detect configs in directory"
    echo "  $0 install-config.yaml --agent-config agent-config.yaml"
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --agent-config)
                AGENT_CONFIG_PATH="$2"
                shift 2
                ;;
            --pull-secret)
                PULL_SECRET_PATH="$2"
                shift 2
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                if [[ -d "$1" ]]; then
                    [[ -f "$1/install-config.yaml" ]] && INSTALL_CONFIG_PATH="$1/install-config.yaml"
                    [[ -f "$1/agent-config.yaml" && -z "$AGENT_CONFIG_PATH" ]] && AGENT_CONFIG_PATH="$1/agent-config.yaml"
                elif [[ -f "$1" ]]; then
                    INSTALL_CONFIG_PATH="$1"
                else
                    echo "Error: '$1' is not a valid file or directory" >&2
                    exit 1
                fi
                shift
                ;;
        esac
    done

    if [[ -z "$INSTALL_CONFIG_PATH" && -f "./install-config.yaml" ]]; then
        INSTALL_CONFIG_PATH="./install-config.yaml"
        log_info "Found install-config.yaml in current directory"
    fi

    if [[ -z "$AGENT_CONFIG_PATH" && -f "./agent-config.yaml" ]]; then
        AGENT_CONFIG_PATH="./agent-config.yaml"
        log_info "Found agent-config.yaml in current directory"
    fi
}

check_dependencies() {
    log_section "Dependency Check"

    local required_tools=("python3" "curl")
    local optional_tools=("dig:bind-utils" "nc:nmap-ncat" "govc:govc" "fio:fio"
                          "podman:podman" "nmap:nmap" "nmstatectl:nmstate"
                          "ipmitool:ipmitool" "openssl:openssl")

    local missing_required=()
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing_required+=("$tool")
        fi
    done

    if [[ ${#missing_required[@]} -gt 0 ]]; then
        log_fail "Missing required tools: ${missing_required[*]}"
        echo "Cannot continue without: ${missing_required[*]}" >&2
        exit 1
    fi

    if ! python3 -c "import yaml" 2>/dev/null; then
        log_fail "Missing required: python3-pyyaml"
        echo "Install with: pip3 install pyyaml  OR  dnf install python3-pyyaml" >&2
        exit 1
    fi

    local missing_optional=()
    local missing_pkgs=()
    local found_optional=()
    for entry in "${optional_tools[@]}"; do
        local tool="${entry%%:*}"
        local pkg="${entry##*:}"
        if command -v "$tool" &>/dev/null; then
            found_optional+=("$tool")
        else
            missing_optional+=("$tool")
            missing_pkgs+=("$pkg")
        fi
    done

    log_pass "Required tools OK (${required_tools[*]}, PyYAML)"

    if [[ ${#missing_optional[@]} -gt 0 ]]; then
        log_warn "Missing optional: ${missing_optional[*]}"
        echo -e "  Some checks will be skipped without these tools."
        echo ""

        local install_cmd=""
        if command -v dnf &>/dev/null; then
            install_cmd="dnf"
        elif command -v yum &>/dev/null; then
            install_cmd="yum"
        fi

        if [[ -n "$install_cmd" ]]; then
            local unique_pkgs
            unique_pkgs=$(printf '%s\n' "${missing_pkgs[@]}" | sort -u | tr '\n' ' ')
            if prompt_yes_no "  Install missing tools? (${install_cmd} install ${unique_pkgs})"; then
                echo ""
                if sudo "${install_cmd}" install -y ${unique_pkgs}; then
                    log_pass "Installed: ${unique_pkgs}"
                else
                    log_warn "Some packages failed to install — continuing anyway"
                fi
            fi
        else
            echo "  Install packages: ${missing_pkgs[*]}"
        fi
    fi

    if [[ ${#found_optional[@]} -gt 0 ]]; then
        log_info "Available: ${found_optional[*]}"
    fi
}

load_from_config() {
    log_section "Config Parsing"

    local result
    result=$(validate_yaml_syntax "$INSTALL_CONFIG_PATH")
    if [[ "$result" != "valid" ]]; then
        log_fail "install-config.yaml: ${result}"
        return 1
    fi
    log_pass "install-config.yaml: YAML syntax valid"

    INSTALL_CONFIG_JSON=$(parse_install_config "$INSTALL_CONFIG_PATH")
    if [[ $? -ne 0 || -z "$INSTALL_CONFIG_JSON" ]]; then
        log_fail "install-config.yaml: failed to parse"
        return 1
    fi
    log_pass "install-config.yaml: parsed successfully"

    PLATFORM=$(get_config_value "$INSTALL_CONFIG_JSON" "platform")
    CLUSTER_NAME=$(get_config_value "$INSTALL_CONFIG_JSON" "cluster_name")
    BASE_DOMAIN=$(get_config_value "$INSTALL_CONFIG_JSON" "base_domain")

    local cp_replicas worker_replicas
    cp_replicas=$(get_config_value "$INSTALL_CONFIG_JSON" "control_plane_replicas")
    worker_replicas=$(get_config_value "$INSTALL_CONFIG_JSON" "worker_replicas")

    if [[ -n "$AGENT_CONFIG_PATH" ]]; then
        INSTALL_TYPE="ABI"
    elif [[ "$cp_replicas" == "1" && "$worker_replicas" == "0" ]]; then
        INSTALL_TYPE="SNO"
    elif [[ "$PLATFORM" == "baremetal" ]]; then
        INSTALL_TYPE="IPI"
    elif [[ "$PLATFORM" == "vsphere" ]]; then
        INSTALL_TYPE="IPI"
    else
        INSTALL_TYPE="UPI"
    fi

    local api_vips ingress_vips
    api_vips=$(get_config_list "$INSTALL_CONFIG_JSON" "api_vips")
    ingress_vips=$(get_config_list "$INSTALL_CONFIG_JSON" "ingress_vips")
    API_VIP=$(echo "$api_vips" | head -1)
    INGRESS_VIP=$(echo "$ingress_vips" | head -1)

    local ssh_key_present pull_secret_present
    ssh_key_present=$(get_config_value "$INSTALL_CONFIG_JSON" "ssh_key_present")
    pull_secret_present=$(get_config_value "$INSTALL_CONFIG_JSON" "has_pull_secret")

    echo ""
    log_info "Detected configuration:"
    log_info "  Platform:       ${PLATFORM}"
    log_info "  Install Type:   ${INSTALL_TYPE}"
    log_info "  Cluster:        ${CLUSTER_NAME}"
    log_info "  Base Domain:    ${BASE_DOMAIN}"
    [[ -n "$API_VIP" ]] && log_info "  API VIP:        ${API_VIP}"
    [[ -n "$INGRESS_VIP" ]] && log_info "  Ingress VIP:    ${INGRESS_VIP}"
    log_info "  SSH Key:        ${ssh_key_present}"
    log_info "  Pull Secret:    ${pull_secret_present}"

    return 0
}

interactive_setup() {
    log_section "Interactive Setup"

    PLATFORM=$(prompt_choice "Select platform:" "vsphere" "baremetal" "none (ABI/SNO)")
    case "$PLATFORM" in
        "none (ABI/SNO)") PLATFORM="none" ;;
    esac

    if [[ "$PLATFORM" == "none" ]]; then
        INSTALL_TYPE=$(prompt_choice "Select install type:" "ABI" "SNO")
    else
        INSTALL_TYPE=$(prompt_choice "Select install type:" "IPI" "UPI" "ABI" "SNO")
    fi

    echo ""
    prompt_value CLUSTER_NAME "  Cluster name"
    prompt_value BASE_DOMAIN "  Base domain"

    if [[ "$INSTALL_TYPE" != "SNO" ]]; then
        prompt_value API_VIP "  API VIP address (empty to skip)" ""
        prompt_value INGRESS_VIP "  Ingress VIP address (empty to skip)" ""
    fi

    prompt_value PULL_SECRET_PATH "  Pull secret file path (empty to skip)" ""
}

run_common_checks() {
    run_dns_checks "$CLUSTER_NAME" "$BASE_DOMAIN"
    check_ntp
    check_ssh_key
    check_pull_secret "$PULL_SECRET_PATH"

    if [[ -n "$API_VIP" || -n "$INGRESS_VIP" ]]; then
        run_vip_port_checks "$API_VIP" "$INGRESS_VIP"
    fi
}

run_platform_checks() {
    case "$PLATFORM" in
        vsphere)
            if [[ -n "$INSTALL_CONFIG_JSON" ]]; then
                local vcenter vcenter_user vcenter_password datacenter
                local vs_cluster datastore network folder resource_pool

                vcenter=$(get_config_value "$INSTALL_CONFIG_JSON" "vcenter")
                vcenter_user=$(get_config_value "$INSTALL_CONFIG_JSON" "vcenter_user")
                vcenter_password=$(get_config_value "$INSTALL_CONFIG_JSON" "vcenter_password")
                datacenter=$(get_config_value "$INSTALL_CONFIG_JSON" "datacenter")
                vs_cluster=$(get_config_value "$INSTALL_CONFIG_JSON" "cluster")
                datastore=$(get_config_value "$INSTALL_CONFIG_JSON" "datastore")
                network=$(get_config_value "$INSTALL_CONFIG_JSON" "network")
                folder=$(get_config_value "$INSTALL_CONFIG_JSON" "folder")
                resource_pool=$(get_config_value "$INSTALL_CONFIG_JSON" "resourcePool")

                if [[ -z "$vcenter_user" || -z "$vcenter_password" ]]; then
                    log_info "vCenter credentials not in install-config (using credentialsMode)."
                    prompt_value vcenter_user "  vCenter username" "administrator@vsphere.local"
                    prompt_value_secret vcenter_password "  vCenter password"
                fi

                run_vsphere_checks "$vcenter" "$vcenter_user" "$vcenter_password" \
                    "$datacenter" "$vs_cluster" "$datastore" "$network" \
                    "$folder" "$resource_pool"
            else
                prompt_vsphere_details
                run_vsphere_checks "$VCENTER" "$VCENTER_USER" "$VCENTER_PASSWORD" \
                    "$DATACENTER" "$VS_CLUSTER" "$DATASTORE" "$NETWORK" \
                    "$FOLDER" "$RESOURCE_POOL"
            fi
            ;;

        baremetal)
            if [[ -n "$INSTALL_CONFIG_JSON" ]]; then
                load_baremetal_from_config "$INSTALL_CONFIG_JSON"
            else
                prompt_baremetal_details "$INSTALL_TYPE"
            fi
            run_baremetal_checks "$INSTALL_TYPE"
            ;;

        none)
            ;;
    esac

    if [[ "$INSTALL_TYPE" == "ABI" || "$INSTALL_TYPE" == "SNO" ]]; then
        if [[ -z "$INSTALL_CONFIG_JSON" ]]; then
            INSTALL_CONFIG_JSON='{"platform":"none","network_type":"OVNKubernetes","control_plane_replicas":3,"worker_replicas":2}'
            if [[ "$INSTALL_TYPE" == "SNO" ]]; then
                INSTALL_CONFIG_JSON='{"platform":"none","network_type":"OVNKubernetes","control_plane_replicas":1,"worker_replicas":0}'
            fi
        fi
        run_abi_checks "$INSTALL_CONFIG_JSON" "$AGENT_CONFIG_PATH"
    fi
}

# --- Main ---

main() {
    print_banner
    parse_args "$@"
    check_dependencies

    if [[ -n "$INSTALL_CONFIG_PATH" ]]; then
        load_from_config || {
            echo ""
            log_warn "Config parsing failed. Falling back to interactive mode."
            interactive_setup
        }
    else
        interactive_setup
    fi

    echo ""
    echo -e "${BOLD}=== Running Pre-flight Checks ===${NC}"
    echo -e "${BOLD}Platform: ${PLATFORM} | Install Type: ${INSTALL_TYPE}${NC}"
    echo -e "${BOLD}Cluster:  ${CLUSTER_NAME}.${BASE_DOMAIN}${NC}"

    run_common_checks
    run_platform_checks

    check_etcd_disk

    print_summary
    exit $?
}

main "$@"
