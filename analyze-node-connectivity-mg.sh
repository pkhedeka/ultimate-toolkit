#!/bin/bash
# analyze-node-connectivity-mg.sh — Must-gather analysis for node connectivity failures
#
# Root-causes: annotation corruption, chassis mismatch, ovnkube-controller parse errors,
#              reconciliation loops, Geneve tunnel failures
#
# Usage: ./analyze-node-connectivity-mg.sh [--scrub|--no-scrub] <must-gather-dir>
#
# --scrub (default): sanitize hostnames, FQDNs, and IPs in output (safe for Jira)
# --no-scrub: show raw hostnames and IPs (for local analysis only)

set -euo pipefail

SCRUB=true
while [[ "${1:-}" == --* ]]; do
    case "$1" in
        --scrub) SCRUB=true; shift ;;
        --no-scrub) SCRUB=false; shift ;;
        *) echo "Unknown flag: $1" >&2; exit 1 ;;
    esac
done

MG="${1:?Usage: $0 [--scrub|--no-scrub] <must-gather-dir>}"

RED='\033[0;31m'
YEL='\033[0;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
BLD='\033[1m'
RST='\033[0m'

verdict_summary=()

verdict() {
    local section="$1" level="$2" msg="$3"
    local color="$GRN"
    [[ "$level" == "WARNING" ]] && color="$YEL"
    [[ "$level" == "CRITICAL" ]] && color="$RED"
    verdict_summary+=("$(printf "%-35s ${color}%-10s${RST} %s" "$section" "$level" "$msg")")
}

header() { echo ""; echo -e "${BLD}${CYN}=== $1 ===${RST}"; }
sub_header() { echo -e "${BLD}--- $1 ---${RST}"; }
die() { echo -e "${RED}ERROR: $1${RST}" >&2; exit 1; }

scrub_output() {
    if [[ "$SCRUB" == "true" ]]; then
        python3 -c "
import re, sys

ip_map = {}
host_map = {}
ip_counter = [0]
host_counter = [0]
role_counters = {}

def replace_ip(m):
    ip = m.group(0)
    if ip not in ip_map:
        ip_counter[0] += 1
        ip_map[ip] = f'x.x.x.{ip_counter[0]}'
    return ip_map[ip]

def replace_fqdn(m):
    fqdn = m.group(0)
    if fqdn.startswith(('quay-io', 'registry-')) or fqdn.endswith(('.log', '.yaml', '.gz', '.tar', '.txt')):
        return fqdn
    if re.match(r'^\d+\.\d+\.\d', fqdn):
        return fqdn
    if fqdn not in host_map:
        lower = fqdn.lower()
        if 'master' in lower or 'control-plane' in lower:
            role = 'control-plane'
        elif 'worker' in lower or 'compute' in lower:
            role = 'worker'
        elif 'infra' in lower:
            role = 'infra'
        elif 'monitor' in lower:
            role = 'monitoring'
        else:
            role = 'node'
        role_counters[role] = role_counters.get(role, 0) + 1
        host_map[fqdn] = f'cluster-{role}-{role_counters[role]}.redacted'
    return host_map[fqdn]

def replace_hostname(m):
    name = m.group(0)
    if name not in host_map:
        lower = name.lower()
        if 'master' in lower or 'control-plane' in lower:
            role = 'control-plane'
        elif 'worker' in lower or 'compute' in lower:
            role = 'worker'
        elif 'infra' in lower:
            role = 'infra'
        elif 'monitor' in lower:
            role = 'monitoring'
        else:
            role = 'node'
        role_counters[role] = role_counters.get(role, 0) + 1
        host_map[name] = f'cluster-{role}-{role_counters[role]}'
    return host_map[name]

ip_re = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b')
fqdn_re = re.compile(r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?){2,}\b')
hostname_re = re.compile(r'\b(?:master|worker|agent|infra|compute|monitor)[a-zA-Z0-9]*-[a-zA-Z0-9][-a-zA-Z0-9]*\b')

for line in sys.stdin:
    line = ip_re.sub(replace_ip, line)
    line = fqdn_re.sub(replace_fqdn, line)
    line = hostname_re.sub(replace_hostname, line)
    sys.stdout.write(line)
"
    else
        cat
    fi
}

main() {

MG_ROOT=$(find "$MG" -maxdepth 3 -type d -name "cluster-scoped-resources" -print -quit 2>/dev/null)
[[ -z "$MG_ROOT" ]] && die "Can't find cluster-scoped-resources in $MG"
MG_ROOT=$(dirname "$MG_ROOT")

NODES_DIR="$MG_ROOT/cluster-scoped-resources/core/nodes"
NS_DIR="$MG_ROOT/namespaces/openshift-ovn-kubernetes"

echo "Must-gather root: $MG_ROOT"
echo "Scrubbing: $SCRUB"

# --------------------------------------------------
header "1. CLUSTER VERSION & PLATFORM"
# --------------------------------------------------
CV_FILE="$MG_ROOT/cluster-scoped-resources/config.openshift.io/clusterversions/version.yaml"
if [[ -f "$CV_FILE" ]]; then
    python3 -c "
import yaml, sys
try:
    with open('$CV_FILE') as f:
        doc = yaml.safe_load(f)
    spec = doc.get('spec', {})
    status = doc.get('status', {})
    print(f\"  channel: {spec.get('channel', 'unknown')}\")
    history = status.get('history', [])
    if history:
        print(f\"  version: {history[0].get('version', 'unknown')}\")
        print(f\"  state: {history[0].get('state', 'unknown')}\")
except Exception as e:
    print(f'  parse error: {e}')
" 2>/dev/null
    INFRA_FILE=$(find "$MG_ROOT" -path "*infrastructures/cluster.yaml" 2>/dev/null | head -1)
    if [[ -n "$INFRA_FILE" ]]; then
        python3 -c "
import yaml
try:
    with open('$INFRA_FILE') as f:
        doc = yaml.safe_load(f)
    ptype = doc.get('status', {}).get('platformStatus', {}).get('type', 'unknown')
    print(f'  platform: {ptype}')
except Exception as e:
    print(f'  parse error: {e}')
" 2>/dev/null
    fi
else
    echo "  version.yaml not found"
fi

# --------------------------------------------------
header "2. NODE OVN ANNOTATIONS — ALL NODES"
# --------------------------------------------------
echo "Checking: l3-gateway-config, node-chassis-id, node-subnets, host-cidrs"
echo ""
annotation_issues=0
if [[ -d "$NODES_DIR" ]]; then
    for node_file in "$NODES_DIR"/*.yaml; do
        [[ -f "$node_file" ]] || continue
        node=$(basename "$node_file" .yaml)
        echo "--- $node ---"

        result=$(python3 << 'PYEOF'
import yaml, json, sys

node_file = sys.argv[1] if len(sys.argv) > 1 else ""
try:
    with open(node_file) as f:
        doc = yaml.safe_load(f)
except Exception as e:
    print(f"  parse error: {e}")
    sys.exit(0)

annotations = doc.get("metadata", {}).get("annotations", {})
issues = 0

ovn_keys = {
    "chassis-id": "k8s.ovn.org/node-chassis-id",
    "node-subnets": "k8s.ovn.org/node-subnets",
    "host-cidrs": "k8s.ovn.org/host-cidrs",
    "primary-ifaddr": "k8s.ovn.org/node-primary-ifaddr",
}

for label, key in ovn_keys.items():
    val = annotations.get(key, "")
    if val:
        print(f"  {label}: {val}")
    else:
        print(f"  {label}: MISSING")
        if label == "chassis-id":
            issues += 1

l3gw = annotations.get("k8s.ovn.org/l3-gateway-config", "")
if l3gw:
    try:
        parsed = json.loads(l3gw)
        print(f"  l3-gateway-config: VALID JSON ({len(l3gw)} bytes)")
    except json.JSONDecodeError as e:
        print(f"  l3-gateway-config: *** INVALID/TRUNCATED JSON ***")
        print(f"    Error: {e}")
        print(f"    RAW (first 200 chars): {l3gw[:200]}")
        print(f"    RAW (last 50 chars):   {l3gw[-50:]}")
        issues += 1
else:
    print(f"  l3-gateway-config: *** MISSING ***")
    issues += 1

print(f"  __issues__:{issues}")
PYEOF
        "$node_file" 2>/dev/null)

        node_issues=$(echo "$result" | grep '__issues__:' | cut -d: -f2)
        echo "$result" | grep -v '__issues__:'
        annotation_issues=$((annotation_issues + ${node_issues:-0}))
        echo ""
    done
else
    echo "  Nodes dir not found: $NODES_DIR"
fi
[[ $annotation_issues -gt 0 ]] && verdict "Node Annotations" "CRITICAL" "$annotation_issues node(s) with annotation issues" || verdict "Node Annotations" "OK" "All nodes have valid OVN annotations"

# --------------------------------------------------
header "3. NODE CONDITIONS"
# --------------------------------------------------
ready_issues=0
if [[ -d "$NODES_DIR" ]]; then
    for node_file in "$NODES_DIR"/*.yaml; do
        [[ -f "$node_file" ]] || continue
        node=$(basename "$node_file" .yaml)
        not_ready=$(python3 -c "
import yaml, sys
try:
    with open('$node_file') as f:
        doc = yaml.safe_load(f)
    conditions = doc.get('status', {}).get('conditions', [])
    for c in conditions:
        if c.get('type') == 'Ready' and c.get('status') != 'True':
            print(f\"  {c.get('reason', 'unknown')}: {c.get('message', '')[:100]}\")
        if c.get('type') == 'NetworkUnavailable' and c.get('status') == 'True':
            print(f\"  NetworkUnavailable: {c.get('message', '')[:100]}\")
except Exception as e:
    print(f'  parse error: {e}')
" 2>/dev/null)
        if [[ -n "$not_ready" ]]; then
            echo "$node:"
            echo "$not_ready"
            ((ready_issues++))
        fi
    done
    [[ $ready_issues -eq 0 ]] && echo "All nodes Ready, NetworkUnavailable=False"
else
    echo "  Nodes dir not found"
fi
[[ $ready_issues -gt 0 ]] && verdict "Node Conditions" "CRITICAL" "$ready_issues node(s) unhealthy" || verdict "Node Conditions" "OK" "All nodes healthy"

# --------------------------------------------------
header "4. CHASSIS TABLE — OVN SB"
# --------------------------------------------------
echo "Looking for OVN SB DB dump to cross-reference chassis IDs..."
OVN_DB_FILES=$(find "$MG_ROOT" -type f \( -name "*.db" -o -name "*sbdb*" -o -name "*sb_dump*" \) -path "*ovn*" 2>/dev/null)
NETWORK_LOGS=$(find "$MG_ROOT" -type d -name "network_logs" 2>/dev/null | head -1)
if [[ -n "$NETWORK_LOGS" ]]; then
    echo "  Network logs dir: $NETWORK_LOGS"
    find "$NETWORK_LOGS" -type f 2>/dev/null | head -20
fi
if [[ -n "$OVN_DB_FILES" ]]; then
    echo "  OVN DB files:"
    echo "$OVN_DB_FILES" | head -10
    for dbf in $OVN_DB_FILES; do
        sub_header "Chassis from: $(basename "$dbf")"
        strings "$dbf" 2>/dev/null | grep -oP '"name"\s*:\s*"[^"]*"' | sort -u | head -20
        strings "$dbf" 2>/dev/null | grep -oP '"hostname"\s*:\s*"[^"]*"' | sort -u | head -20
    done
    verdict "Chassis Cross-ref" "WARNING" "Verify chassis IDs match node annotations"
else
    echo "  No OVN SB DB found — use sosreport script for chassis verification"
    verdict "Chassis Cross-ref" "WARNING" "Need sosreport for chassis cross-check"
fi

# --------------------------------------------------
header "5. OVNKUBE-CONTROLLER LOGS"
# --------------------------------------------------
CTRL_LOGS=""
if [[ -d "$NS_DIR" ]]; then
    CTRL_LOGS=$(find "$NS_DIR" -type f -name "*.log" -path "*ovnkube-controller*" 2>/dev/null)
    if [[ -z "$CTRL_LOGS" ]]; then
        CTRL_LOGS=$(find "$NS_DIR" -type f -name "*.log" 2>/dev/null | xargs grep -l "ovnkube-controller\|gateway_init\|defaultNetworkController" 2>/dev/null | head -10)
    fi
fi
ctrl_errors=0
if [[ -n "$CTRL_LOGS" ]]; then
    sub_header "Unmarshal / JSON parse errors"
    unmarshal_hits=$(grep -ch "unmarshal\|unexpected end of JSON\|invalid character\|cannot unmarshal" $CTRL_LOGS 2>/dev/null | paste -sd+ | bc 2>/dev/null || echo 0)
    if [[ "$unmarshal_hits" -gt 0 ]]; then
        echo -e "  ${RED}Found $unmarshal_hits unmarshal errors${RST}"
        grep -h "unmarshal\|unexpected end of JSON\|invalid character\|cannot unmarshal" $CTRL_LOGS 2>/dev/null | tail -10
        ctrl_errors=$unmarshal_hits
    else
        echo "  None found"
    fi

    echo ""
    sub_header "l3-gateway-config errors"
    l3gw_hits=$(grep -ch "l3-gateway-config\|l3GatewayConfig\|parseGatewayConfig" $CTRL_LOGS 2>/dev/null | paste -sd+ | bc 2>/dev/null || echo 0)
    if [[ "$l3gw_hits" -gt 0 ]]; then
        echo -e "  ${RED}Found $l3gw_hits gateway config references${RST}"
        grep -h "l3-gateway-config\|l3GatewayConfig\|parseGatewayConfig" $CTRL_LOGS 2>/dev/null | grep -i "error\|fail\|invalid\|truncat" | tail -10
    else
        echo "  None found"
    fi

    echo ""
    sub_header "Reconciliation loop indicators"
    route_adds=$(grep -ch "Attempting to add route\|adding route\|route.*retry" $CTRL_LOGS 2>/dev/null | paste -sd+ | bc 2>/dev/null || echo 0)
    echo "  Route-add attempts: $route_adds"
    [[ "$route_adds" -gt 100 ]] && echo -e "  ${YEL}High count — possible reconciliation loop${RST}"

    echo ""
    sub_header "General ERROR lines (last 20)"
    grep -h "^E[0-9]\|\" level=error" $CTRL_LOGS 2>/dev/null | tail -20
else
    echo "  No ovnkube-controller logs found"
    echo "  Looking for log dirs:"
    find "$NS_DIR" -type d -name "*ovnkube*" 2>/dev/null | head -10
fi
[[ $ctrl_errors -gt 0 ]] && verdict "Controller Logs" "CRITICAL" "$ctrl_errors unmarshal errors" || verdict "Controller Logs" "OK" "No parse errors"

# --------------------------------------------------
header "6. OVN-CONTROLLER LOGS — TUNNEL ERRORS"
# --------------------------------------------------
OVN_CTRL_LOGS=""
if [[ -d "$NS_DIR" ]]; then
    OVN_CTRL_LOGS=$(find "$NS_DIR" -type f -name "*.log" -path "*ovn-controller*" 2>/dev/null)
fi
tunnel_errors=0
if [[ -n "$OVN_CTRL_LOGS" ]]; then
    sub_header "Geneve / tunnel errors"
    tunnel_err_lines=$(grep -h "geneve\|tunnel\|encap" $OVN_CTRL_LOGS 2>/dev/null | grep -i "error\|fail\|invalid\|malformed")
    if [[ -n "$tunnel_err_lines" ]]; then
        tunnel_errors=$(echo "$tunnel_err_lines" | wc -l)
        echo "$tunnel_err_lines" | tail -15
    else
        echo "  None found"
    fi

    echo ""
    sub_header "TLV mapping issues"
    grep -h "tlv\|tun_metadata\|metadata" $OVN_CTRL_LOGS 2>/dev/null | grep -i "error\|fail\|invalid" | tail -5
    echo "  (empty = OK)"

    echo ""
    sub_header "Connection to SB"
    grep -h "connected\|disconnected\|connection\|ovnsb" $OVN_CTRL_LOGS 2>/dev/null | grep -iv "debug" | tail -10
else
    echo "  No ovn-controller logs found"
fi
[[ $tunnel_errors -gt 0 ]] && verdict "OVN Controller" "WARNING" "$tunnel_errors tunnel errors" || verdict "OVN Controller" "OK" "No tunnel errors"

# --------------------------------------------------
header "7. OVNKUBE-NODE POD STATUS"
# --------------------------------------------------
OVN_PODS=$(find "$NS_DIR" -type f -name "*.yaml" -path "*pods/ovnkube-node*" 2>/dev/null)
high_restarts=0
if [[ -n "$OVN_PODS" ]]; then
    for pod_file in $OVN_PODS; do
        pod=$(basename "$pod_file" .yaml)
        node=$(grep 'nodeName:' "$pod_file" 2>/dev/null | head -1 | awk '{print $2}')
        phase=$(grep '^\s*phase:' "$pod_file" 2>/dev/null | head -1 | awk '{print $2}')
        restarts=$(grep 'restartCount:' "$pod_file" 2>/dev/null | awk '{sum+=$2} END {print sum}')
        echo "  $pod -> node=$node phase=$phase restarts=${restarts:-0}"
        [[ "${restarts:-0}" -gt 10 ]] && ((high_restarts++))
    done
else
    echo "  No ovnkube-node pod YAMLs found"
fi
[[ $high_restarts -gt 0 ]] && verdict "Pod Restarts" "WARNING" "$high_restarts pod(s) high restarts" || verdict "Pod Restarts" "OK" "Normal restart counts"

# --------------------------------------------------
header "8. MACHINE CONFIG POOL"
# --------------------------------------------------
MCP_DIR=$(find "$MG_ROOT" -type d -name "machineconfigpools" 2>/dev/null | head -1)
mcp_degraded=0
if [[ -n "$MCP_DIR" ]]; then
    for f in "$MCP_DIR"/*.yaml; do
        [[ -f "$f" ]] || continue
        pool=$(basename "$f" .yaml)
        echo "--- $pool ---"
        degraded=$(grep 'degradedMachineCount:' "$f" 2>/dev/null | awk '{print $2}')
        updating=$(grep 'unavailableMachineCount:' "$f" 2>/dev/null | awk '{print $2}')
        grep -E 'machineCount:|readyMachineCount:|updatedMachineCount:|degradedMachineCount:|unavailableMachineCount:' "$f" 2>/dev/null
        [[ "${degraded:-0}" -gt 0 ]] && { echo -e "  ${RED}DEGRADED${RST}"; ((mcp_degraded++)); }
        [[ "${updating:-0}" -gt 0 ]] && echo -e "  ${YEL}UPDATING${RST}"
    done
else
    echo "  No MCP files found"
fi
[[ $mcp_degraded -gt 0 ]] && verdict "MCP Status" "CRITICAL" "Degraded pool(s)" || verdict "MCP Status" "OK" "All pools healthy"

# --------------------------------------------------
header "9. OVN NAMESPACE EVENTS"
# --------------------------------------------------
EVENTS_FILE=$(find "$MG_ROOT" -type f -name "events.yaml" -path "*openshift-ovn-kubernetes*" 2>/dev/null | head -1)
if [[ -n "$EVENTS_FILE" ]]; then
    warn_count=$(grep -c "type: Warning" "$EVENTS_FILE" 2>/dev/null || echo 0)
    echo "  Warning events: $warn_count"
    [[ "$warn_count" -gt 0 ]] && grep -B1 -A4 "type: Warning" "$EVENTS_FILE" 2>/dev/null | tail -30
else
    echo "  No events file found"
fi

# --------------------------------------------------
header "VERDICT SUMMARY"
# --------------------------------------------------
for v in "${verdict_summary[@]}"; do
    echo -e "  $v"
done
echo ""
echo "Next: run analyze-node-connectivity-sos.sh on sosreport for OVS-level data"

} # end main

main 2>&1 | scrub_output
