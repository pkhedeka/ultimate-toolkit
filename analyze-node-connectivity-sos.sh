#!/bin/bash
# analyze-node-connectivity-sos.sh — SOSreport analysis for node connectivity failures
#
# Checks OVS/OVN local state: system-id, flow tables, tunnel config,
# ovn-controller connection, dmesg NIC flaps, OOM kills
#
# Usage: ./analyze-node-connectivity-sos.sh [--scrub|--no-scrub] <sosreport-dir>
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

SOS="${1:?Usage: $0 [--scrub|--no-scrub] <sosreport-dir>}"

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

# Auto-detect sosreport root
SOS_ROOT=$(find "$SOS" -maxdepth 3 -type f -name "hostname" -print -quit 2>/dev/null)
if [[ -n "$SOS_ROOT" ]]; then
    SOS_ROOT=$(dirname "$SOS_ROOT")
else
    SOS_ROOT="$SOS"
fi
echo "SOSreport root: $SOS_ROOT"
echo "Hostname: $(cat "$SOS_ROOT/hostname" 2>/dev/null || echo 'unknown')"
echo "Scrubbing: $SCRUB"

SOS_OVS_CMD=$(find "$SOS_ROOT" -path "*/sos_commands/openvswitch*" -type d 2>/dev/null | head -1)
SOS_OVN_CMD=$(find "$SOS_ROOT" -path "*/sos_commands/ovn*" -type d 2>/dev/null | head -1)

# --------------------------------------------------
header "1. OVS SYSTEM-ID (ground truth chassis)"
# --------------------------------------------------
sos_sysid=""
CONFDB=$(find "$SOS_ROOT" -type f -name "conf.db" -path "*openvswitch*" 2>/dev/null | head -1)
if [[ -n "$CONFDB" ]]; then
    sos_sysid=$(strings "$CONFDB" 2>/dev/null | grep -oP '(?<="system-id":")[^"]+' | head -1)
    echo "  system-id (conf.db): ${sos_sysid:-NOT FOUND}"
fi
if [[ -n "$SOS_OVS_CMD" ]]; then
    ext_ids_file=$(find "$SOS_OVS_CMD" -name "*external*ids*" -o -name "*external-ids*" 2>/dev/null | head -1)
    if [[ -n "$ext_ids_file" ]]; then
        echo "  external_ids:"
        cat "$ext_ids_file"
    fi
fi
if [[ -n "$sos_sysid" ]]; then
    verdict "OVS System-ID" "OK" "system-id=$sos_sysid — compare with k8s chassis annotation"
else
    verdict "OVS System-ID" "WARNING" "Could not extract system-id"
fi

# --------------------------------------------------
header "2. OVS BRIDGE CONFIG"
# --------------------------------------------------
OVS_SHOW=""
if [[ -n "$SOS_OVS_CMD" ]]; then
    OVS_SHOW=$(find "$SOS_OVS_CMD" -name "*vsctl*show*" 2>/dev/null | head -1)
fi
[[ -z "$OVS_SHOW" ]] && OVS_SHOW=$(find "$SOS_ROOT" -name "*ovs-vsctl*show*" -o -name "*ovs_vsctl_show*" 2>/dev/null | head -1)
if [[ -n "$OVS_SHOW" ]]; then
    cat "$OVS_SHOW"
else
    echo "  No ovs-vsctl show found"
fi

# --------------------------------------------------
header "3. br-int FLOW TABLE"
# --------------------------------------------------
FLOW_DUMP=""
if [[ -n "$SOS_OVS_CMD" ]]; then
    FLOW_DUMP=$(find "$SOS_OVS_CMD" -name "*dump-flows*" 2>/dev/null | grep -i "br.int" | head -1)
fi
[[ -z "$FLOW_DUMP" ]] && FLOW_DUMP=$(find "$SOS_ROOT" -type f -name "*dump-flows*br-int*" -o -name "*dump_flows*br-int*" 2>/dev/null | head -1)

if [[ -n "$FLOW_DUMP" ]]; then
    total_flows=$(wc -l < "$FLOW_DUMP")
    echo "  Total flows in br-int: $total_flows"

    echo ""
    sub_header "Table 0 — Classification (tunnel input)"
    grep "table=0," "$FLOW_DUMP" 2>/dev/null | head -20
    geneve_input=$(grep "table=0," "$FLOW_DUMP" 2>/dev/null | grep -c "tun_id\|in_port" || echo 0)
    [[ "$geneve_input" -eq 0 ]] && echo -e "  ${RED}*** NO tunnel input flows in table 0 ***${RST}"

    echo ""
    sub_header "TLV map actions"
    tlv_count=$(grep -c "tlv_map\|tun_metadata" "$FLOW_DUMP" 2>/dev/null || echo 0)
    echo "  TLV-related flows: $tlv_count"
    [[ "$tlv_count" -eq 0 ]] && echo -e "  ${RED}*** NO TLV mappings — tunnel metadata broken ***${RST}"
    grep "tlv_map\|tun_metadata" "$FLOW_DUMP" 2>/dev/null | head -5

    echo ""
    sub_header "Drop actions"
    drop_count=$(grep -c "actions=drop" "$FLOW_DUMP" 2>/dev/null || echo 0)
    echo "  Drop rules: $drop_count"
    grep "actions=drop" "$FLOW_DUMP" 2>/dev/null | head -5

    [[ "$total_flows" -lt 50 ]] && verdict "br-int Flows" "CRITICAL" "Only $total_flows flows — severely incomplete" || verdict "br-int Flows" "OK" "$total_flows flows"
else
    echo "  No br-int flow dump found"
    find "$SOS_ROOT" -name "*dump*flow*" 2>/dev/null | head -10
    verdict "br-int Flows" "WARNING" "No flow dump available"
fi

# --------------------------------------------------
header "4. br-ex FLOW TABLE"
# --------------------------------------------------
BREX_DUMP=""
if [[ -n "$SOS_OVS_CMD" ]]; then
    BREX_DUMP=$(find "$SOS_OVS_CMD" -name "*dump-flows*" 2>/dev/null | grep -i "br.ex" | head -1)
fi
[[ -z "$BREX_DUMP" ]] && BREX_DUMP=$(find "$SOS_ROOT" -type f -name "*dump-flows*br-ex*" 2>/dev/null | head -1)
if [[ -n "$BREX_DUMP" ]]; then
    echo "  Total flows in br-ex: $(wc -l < "$BREX_DUMP")"
    sub_header "Patch port flows"
    grep -i "patch\|in_port" "$BREX_DUMP" 2>/dev/null | head -10
else
    echo "  No br-ex flow dump found"
fi

# --------------------------------------------------
header "5. OVN-CONTROLLER STATE"
# --------------------------------------------------
sub_header "Connection status to SB"
conn_file=$(find "$SOS_ROOT" -name "*connection*status*" -path "*ovn*" 2>/dev/null | head -1)
if [[ -n "$conn_file" ]]; then
    conn_status=$(cat "$conn_file")
    echo "  $conn_status"
    if echo "$conn_status" | grep -qi "not connected\|disconnected"; then
        verdict "OVN Connection" "CRITICAL" "ovn-controller disconnected from SB"
    else
        verdict "OVN Connection" "OK" "Connected to SB"
    fi
else
    echo "  Not found"
    verdict "OVN Connection" "WARNING" "Connection status unavailable"
fi

echo ""
sub_header "ovn-controller logs — errors"
OVN_LOG=$(find "$SOS_ROOT" -type f -name "ovn-controller.log" 2>/dev/null | head -1)
[[ -z "$OVN_LOG" ]] && [[ -n "$SOS_OVN_CMD" ]] && OVN_LOG=$(find "$SOS_OVN_CMD" -name "*controller*log*" 2>/dev/null | head -1)
if [[ -n "$OVN_LOG" ]]; then
    err_count=$(grep -c "ERR" "$OVN_LOG" 2>/dev/null || echo 0)
    echo "  ERR lines: $err_count"
    grep "ERR" "$OVN_LOG" 2>/dev/null | tail -15
    echo ""
    sub_header "Chassis / encap issues"
    grep -i "chassis\|encap\|geneve\|tunnel" "$OVN_LOG" 2>/dev/null | grep -i "err\|warn\|fail" | tail -10
    echo "  (empty = OK)"
else
    echo "  No ovn-controller log found"
fi

# --------------------------------------------------
header "6. OVN SB LOCAL COPY"
# --------------------------------------------------
OVN_SB=$(find "$SOS_ROOT" -type f \( -name "ovnsb_db.db" -o -name "ovn-sb*.db" \) 2>/dev/null | head -1)
if [[ -n "$OVN_SB" ]]; then
    echo "  SB DB: $OVN_SB ($(du -h "$OVN_SB" | cut -f1))"
    sub_header "Chassis entries"
    strings "$OVN_SB" 2>/dev/null | grep -oP '"name"\s*:\s*"[^"]*"' | sort -u | head -20
    sub_header "Encap IPs"
    strings "$OVN_SB" 2>/dev/null | grep -oP '"ip"\s*:\s*"[^"]*"' | sort -u | head -20
else
    echo "  No SB DB found"
fi

# --------------------------------------------------
header "7. NETWORK INTERFACES"
# --------------------------------------------------
IP_LINK=$(find "$SOS_ROOT" -type f -name "ip_-d_link" 2>/dev/null | head -1)
[[ -z "$IP_LINK" ]] && IP_LINK=$(find "$SOS_ROOT" -path "*/sos_commands/networking/*" -name "*ip*link*" 2>/dev/null | head -1)
if [[ -n "$IP_LINK" ]]; then
    sub_header "Geneve interface"
    grep -A4 "genev" "$IP_LINK" 2>/dev/null || echo "  No geneve interface"
    echo ""
    sub_header "br-int / br-ex"
    grep -A4 "br-int\|br-ex" "$IP_LINK" 2>/dev/null | head -20
    echo ""
    sub_header "Bond/team interfaces"
    grep -A6 "bond\|team" "$IP_LINK" 2>/dev/null | head -20 || echo "  None"
else
    echo "  No ip link output found"
fi

# --------------------------------------------------
header "8. DMESG — HARDWARE/NETWORK"
# --------------------------------------------------
DMESG=$(find "$SOS_ROOT" -type f -name "dmesg" -not -path "*/sos_commands/*" 2>/dev/null | head -1)
if [[ -n "$DMESG" ]]; then
    sub_header "NIC / bond / link events"
    nic_events=$(grep -i "link.*down\|link.*up\|bond\|NIC\|carrier\|netdev" "$DMESG" 2>/dev/null | tail -15)
    if [[ -n "$nic_events" ]]; then
        echo "$nic_events"
        verdict "NIC Stability" "WARNING" "Link state changes detected — check for flaps"
    else
        echo "  None"
        verdict "NIC Stability" "OK" "No link events"
    fi

    echo ""
    sub_header "OVS / Geneve kernel errors"
    grep -i "openvswitch\|geneve\|vxlan" "$DMESG" 2>/dev/null | tail -10 || echo "  None"

    echo ""
    sub_header "OOM kills"
    oom_count=$(grep -c "Out of memory\|Killed process" "$DMESG" 2>/dev/null || echo 0)
    echo "  OOM events: $oom_count"
    if [[ "$oom_count" -gt 0 ]]; then
        grep -i "Out of memory\|Killed process" "$DMESG" 2>/dev/null | tail -5
        verdict "OOM" "CRITICAL" "$oom_count OOM kill(s) — may have crashed ovn-controller"
    else
        verdict "OOM" "OK" "No OOM events"
    fi
else
    echo "  No dmesg found"
fi

# --------------------------------------------------
header "9. SYSTEM STATE"
# --------------------------------------------------
echo "-- Uptime --"
cat "$SOS_ROOT/uptime" 2>/dev/null || echo "  not found"
echo "-- Memory --"
head -5 "$SOS_ROOT/proc/meminfo" 2>/dev/null || echo "  not found"
echo "-- Load avg --"
cat "$SOS_ROOT/proc/loadavg" 2>/dev/null || echo "  not found"

# --------------------------------------------------
header "VERDICT SUMMARY"
# --------------------------------------------------
for v in "${verdict_summary[@]}"; do
    echo -e "  $v"
done
echo ""
echo "Cross-check with must-gather script output:"
echo "  1. system-id here == node-chassis-id annotation?"
echo "  2. br-int has Geneve decap flows?"
echo "  3. TLV mappings present?"
echo "  4. ovn-controller connected?"
echo "  5. NIC flaps explain transient self-heal on other node?"

} # end main

main 2>&1 | scrub_output
