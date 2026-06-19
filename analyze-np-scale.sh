#!/bin/bash
#
# analyze-np-scale.sh — Parse a must-gather for OVN NP-at-scale issues
# Usage: ./analyze-np-scale.sh [--scrub] <must-gather-dir>
#
# Checks: nb_cfg sync gap, northd recomputes, ovn-controller saturation,
#          ACL/Port_Group/AddressSet counts, ANP bloat, resource usage
#
# --scrub (default): sanitize hostnames, FQDNs, and IPs in output (safe for sharing)
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
    verdict_summary+=("$(printf "%-30s ${color}%-10s${RST} %s" "$section" "$level" "$msg")")
}

header() {
    echo ""
    echo -e "${BLD}${CYN}=== $1 ===${RST}"
}

die() { echo -e "${RED}ERROR: $1${RST}" >&2; exit 1; }

# --- Scrub filter: replace IPs and FQDNs with anonymized placeholders ---
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
        else:
            role = 'node'
        role_counters[role] = role_counters.get(role, 0) + 1
        host_map[name] = f'cluster-{role}-{role_counters[role]}'
    return host_map[name]

ip_re = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b')
# FQDN: 3+ dot-separated parts
fqdn_re = re.compile(r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?){2,}\b')
# Short hostnames: master-N, worker-N, or agent-hash-role-N patterns
hostname_re = re.compile(r'\b(?:master|worker|agent|infra|compute)-[a-zA-Z0-9][-a-zA-Z0-9]*\b')

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

# --- Python helper: parse OVSDB clustered backup (JSON diff format) ---
# Reconstructs full DB state by replaying all diffs
parse_ovsdb() {
    local dbfile="$1"
    local mode="$2"  # "nb_tables" | "sb_chassis" | "nb_cfg"
    python3 - "$dbfile" "$mode" << 'PYEOF'
import json, sys

dbfile = sys.argv[1]
mode = sys.argv[2]

with open(dbfile) as f:
    lines = f.readlines()

# OVSDB clustered backup format:
# Line 0: "OVSDB JSON <size> <hash>" (header)
# Line 1: schema JSON (tables, columns, version)
# Line 2: "OVSDB JSON <size> <hash>" (data header)
# Line 3+: alternating "OVSDB JSON..." headers and JSON diff data
# All data lines have _is_diff=True — must replay to get final state

state = {}  # table -> {uuid -> {field -> value}}

for i in range(3, len(lines), 2):
    try:
        d = json.loads(lines[i])
    except (json.JSONDecodeError, IndexError):
        continue
    for table_name, records in d.items():
        if table_name.startswith('_'):
            continue
        if table_name not in state:
            state[table_name] = {}
        if not isinstance(records, dict):
            continue
        for uuid, row in records.items():
            if row is None:
                state[table_name].pop(uuid, None)
            elif isinstance(row, dict):
                if uuid not in state[table_name]:
                    state[table_name][uuid] = {}
                state[table_name][uuid].update(row)

if mode == "nb_tables":
    for t in ["ACL", "Port_Group", "Address_Set", "Logical_Switch",
              "Logical_Router", "Logical_Switch_Port", "Load_Balancer",
              "NAT", "Logical_Router_Policy", "Logical_Flow",
              "QoS", "Static_MAC_Binding"]:
        count = len(state.get(t, {}))
        print(f"{t}:{count}")
    # NB_Global nb_cfg
    for uid, rec in state.get("NB_Global", {}).items():
        print(f"NB_Global_nb_cfg:{rec.get('nb_cfg', '?')}")

elif mode == "sb_chassis":
    # Get SB_Global nb_cfg
    for uid, rec in state.get("SB_Global", {}).items():
        print(f"SB_Global_nb_cfg:{rec.get('nb_cfg', '?')}")

    # Chassis hostnames
    chassis_hosts = {}
    for uid, rec in state.get("Chassis", {}).items():
        hostname = rec.get("hostname", uid[:12])
        chassis_hosts[uid] = hostname

    # Chassis_Private has per-chassis nb_cfg
    for uid, rec in state.get("Chassis_Private", {}).items():
        chassis_ref = rec.get("chassis", "")
        # chassis field is a UUID ref — may be ["uuid","<uuid>"] or just a string
        if isinstance(chassis_ref, list) and len(chassis_ref) == 2:
            chassis_ref = chassis_ref[1]
        hostname = chassis_hosts.get(chassis_ref, rec.get("name", uid[:12]))
        nb_cfg = rec.get("nb_cfg", "?")
        print(f"Chassis:{hostname}:{nb_cfg}")

    # Also check Chassis table directly for nb_cfg (older OVN)
    for uid, rec in state.get("Chassis", {}).items():
        if "nb_cfg" in rec:
            hostname = rec.get("hostname", uid[:12])
            print(f"Chassis:{hostname}:{rec['nb_cfg']}")

    # SB scale stats
    for t in ["Logical_Flow", "Port_Binding", "Datapath_Binding",
              "Address_Set", "MAC_Binding", "Load_Balancer"]:
        count = len(state.get(t, {}))
        print(f"SB_{t}:{count}")

elif mode == "nb_cfg":
    for uid, rec in state.get("NB_Global", {}).items():
        print(rec.get("nb_cfg", "?"))

PYEOF
}

# --- Main logic (piped through scrub_output at the end) ---

main() {

# --- Setup & Auto-detect ---

[[ $# -lt 1 ]] && die "Usage: $0 [--scrub] <must-gather-dir>"

MG_ROOT="$(realpath "$1")"
[[ -d "$MG_ROOT" ]] || die "Not a directory: $MG_ROOT"

# Find nested quay-io hash dir (or registry.redhat.io variant)
INNER_DIR=$(find "$MG_ROOT" -maxdepth 1 -type d \( -name "quay-io-*" -o -name "registry-*" \) | head -1)
if [[ -z "$INNER_DIR" ]]; then
    if [[ -d "$MG_ROOT/network_logs" || -d "$MG_ROOT/namespaces" ]]; then
        INNER_DIR="$MG_ROOT"
    else
        die "Cannot find must-gather inner directory under $MG_ROOT"
    fi
fi

echo -e "${BLD}Must-gather root:${RST} $INNER_DIR"

NETWORK_LOGS="$INNER_DIR/network_logs"
NS_OVN="$INNER_DIR/namespaces/openshift-ovn-kubernetes"
CLUSTER_SCOPED="$INNER_DIR/cluster-scoped-resources"
TMPDIR_DB=""

cleanup() {
    [[ -n "$TMPDIR_DB" && -d "$TMPDIR_DB" ]] && rm -rf "$TMPDIR_DB"
}
trap cleanup EXIT

# --- Extract OVN DB archive ---

header "OVN Database Extraction"

DB_ARCHIVE="$NETWORK_LOGS/ovnk_database_store.tar.gz"
NBDB=""
SBDB=""

if [[ -f "$DB_ARCHIVE" ]]; then
    TMPDIR_DB=$(mktemp -d)
    tar -xzf "$DB_ARCHIVE" -C "$TMPDIR_DB" 2>/dev/null
    echo "Extracted OVN DB to temp dir"

    # Collect all NB and SB dumps (one per node in IC, one total in non-IC)
    mapfile -t NBDB_FILES < <(find "$TMPDIR_DB" -name "*_nbdb" -type f 2>/dev/null)
    mapfile -t SBDB_FILES < <(find "$TMPDIR_DB" -name "*_sbdb" -type f 2>/dev/null)

    echo "  Found ${#NBDB_FILES[@]} NB database(s), ${#SBDB_FILES[@]} SB database(s)"
    for f in "${NBDB_FILES[@]}"; do echo "    NB: $(basename "$f")"; done
    for f in "${SBDB_FILES[@]}"; do echo "    SB: $(basename "$f")"; done

    # Use first NB for scale metrics, collect all SBs for chassis coverage
    NBDB="${NBDB_FILES[0]:-}"
    SBDB="${SBDB_FILES[0]:-}"
else
    echo "No ovnk_database_store.tar.gz found — DB analysis skipped"
fi

# --- Scale Metrics (NB Database) ---

header "Scale Metrics (NB Database)"

if [[ -n "$NBDB" ]]; then
    nb_data=$(parse_ovsdb "$NBDB" "nb_tables")
    echo "$nb_data" | while IFS=: read -r table count; do
        [[ "$table" == "NB_Global_nb_cfg" ]] && continue
        printf "  %-25s %s\n" "$table" "$count"
    done

    total_acls=$(echo "$nb_data" | grep "^ACL:" | cut -d: -f2)
    total_pg=$(echo "$nb_data" | grep "^Port_Group:" | cut -d: -f2)
    nb_cfg=$(echo "$nb_data" | grep "^NB_Global_nb_cfg:" | cut -d: -f2)
    echo ""
    echo -e "  ${BLD}NB_Global nb_cfg: $nb_cfg${RST}"

    if [[ "${total_acls:-0}" -gt 10000 ]]; then
        verdict "Scale Metrics" "CRITICAL" "${total_acls} ACLs, ${total_pg} Port_Groups"
    elif [[ "${total_acls:-0}" -gt 5000 ]]; then
        verdict "Scale Metrics" "WARNING" "${total_acls} ACLs, ${total_pg} Port_Groups"
    elif [[ "${total_acls:-0}" -gt 1000 ]]; then
        verdict "Scale Metrics" "WARNING" "${total_acls} ACLs — moderate"
    else
        verdict "Scale Metrics" "OK" "${total_acls} ACLs"
    fi
else
    echo "  Skipped (no NB database)"
    verdict "Scale Metrics" "WARNING" "No NB database available"
fi

# --- nb_cfg Sync Gap (SB Database) ---

header "nb_cfg Sync Gap"

if [[ -n "$SBDB" ]]; then
    sb_data=$(parse_ovsdb "$SBDB" "sb_chassis")

    sb_global_cfg=$(echo "$sb_data" | grep "^SB_Global_nb_cfg:" | cut -d: -f2)
    echo "  SB_Global nb_cfg: ${sb_global_cfg:-unknown}"
    echo "  NB_Global nb_cfg: ${nb_cfg:-unknown}"
    echo ""

    max_gap=0
    worst_chassis=""
    chassis_count=0

    echo "  Per-chassis nb_cfg:"
    echo "$sb_data" | grep "^Chassis:" | sort -t: -k2 | while IFS=: read -r _ hostname chassis_cfg; do
        gap=0
        level=""
        if [[ -n "$nb_cfg" && "$nb_cfg" =~ ^[0-9]+$ && "$chassis_cfg" =~ ^[0-9]+$ ]]; then
            gap=$((nb_cfg - chassis_cfg))
        fi
        [[ "$gap" -gt 0 ]] && level=" ${YEL}(behind by $gap)${RST}"
        [[ "$gap" -gt 5 ]] && level=" ${RED}(behind by $gap — STALE)${RST}"
        printf "    %-50s nb_cfg=%-8s%b\n" "$hostname" "$chassis_cfg" "$level"
    done

    # For IC clusters, each node has its own NB+SB pair
    # Compare each node's NB nb_cfg with its own SB nb_cfg
    if [[ ${#SBDB_FILES[@]} -gt 1 ]]; then
        echo ""
        echo "  IC cluster: per-node NB vs SB nb_cfg comparison..."
        max_ic_gap=0
        for sbf in "${SBDB_FILES[@]}"; do
            node=$(basename "$sbf" | sed 's/_sbdb//')
            nbf="${sbf/_sbdb/_nbdb}"
            local_nb_cfg="?"
            if [[ -f "$nbf" ]]; then
                local_nb_cfg=$(parse_ovsdb "$nbf" "nb_tables" | grep "^NB_Global_nb_cfg:" | cut -d: -f2)
            fi
            local_sb_cfg=$(parse_ovsdb "$sbf" "sb_chassis" | grep "^SB_Global_nb_cfg:" | cut -d: -f2)
            local_gap=0
            level=""
            if [[ "$local_nb_cfg" =~ ^[0-9]+$ && "$local_sb_cfg" =~ ^[0-9]+$ ]]; then
                local_gap=$((local_nb_cfg - local_sb_cfg))
                [[ "$local_gap" -lt 0 ]] && local_gap=0
            fi
            [[ "$local_gap" -gt 0 ]] && level=" ${YEL}(gap: $local_gap)${RST}"
            [[ "$local_gap" -gt 5 ]] && level=" ${RED}(gap: $local_gap — STALE)${RST}"
            [[ "$local_gap" -gt "$max_ic_gap" ]] && max_ic_gap=$local_gap
            printf "    %-40s NB=%s  SB=%s%b\n" "$node" "${local_nb_cfg}" "${local_sb_cfg}" "$level"
        done
    fi

    # Calculate verdict
    chassis_gaps=0
    if [[ ${#SBDB_FILES[@]} -gt 1 ]]; then
        chassis_gaps=${max_ic_gap:-0}
    else
        chassis_gaps=$(echo "$sb_data" | grep "^Chassis:" | while IFS=: read -r _ hostname chassis_cfg; do
            if [[ -n "$nb_cfg" && "$nb_cfg" =~ ^[0-9]+$ && "$chassis_cfg" =~ ^[0-9]+$ ]]; then
                echo $((nb_cfg - chassis_cfg))
            fi
        done | sort -rn | head -1)
    fi

    if [[ "${chassis_gaps:-0}" -gt 5 ]]; then
        verdict "nb_cfg Sync" "CRITICAL" "Worst gap: ${chassis_gaps}"
    elif [[ "${chassis_gaps:-0}" -gt 0 ]]; then
        verdict "nb_cfg Sync" "WARNING" "Worst gap: ${chassis_gaps}"
    else
        verdict "nb_cfg Sync" "OK" "Chassis in sync (at snapshot time)"
    fi

    # SB scale stats
    echo ""
    echo "  SB scale stats:"
    echo "$sb_data" | grep "^SB_" | grep -v "Global" | while IFS=: read -r label count; do
        table=${label#SB_}
        printf "    %-25s %s\n" "$table" "$count"
    done
else
    echo "  Skipped (no SB database)"
    verdict "nb_cfg Sync" "WARNING" "No SB database"
fi

# --- northd Recompute Analysis ---

header "northd Recompute Analysis"

northd_logs=""
if [[ -d "$NS_OVN/pods" ]]; then
    northd_logs=$(find "$NS_OVN/pods" -path "*/ovnkube-control-plane*/northd/logs/current.log" 2>/dev/null || true)
    [[ -z "$northd_logs" ]] && northd_logs=$(find "$NS_OVN/pods" -path "*/northd*current.log" 2>/dev/null || true)
fi

if [[ -n "$northd_logs" ]]; then
    total_recomputes=0
    while IFS= read -r logfile; do
        [[ -f "$logfile" ]] || continue
        podname=$(echo "$logfile" | grep -oP 'pods/\K[^/]+')
        echo -e "  ${BLD}Pod: $podname${RST}"

        recompute_count=$(grep -ciE "recompute|Recomputing" "$logfile" 2>/dev/null) || recompute_count=0
        echo "    Recompute events: $recompute_count"
        total_recomputes=$((total_recomputes + recompute_count))

        poll_loops=$(grep "poll_loop" "$logfile" 2>/dev/null | tail -5 || true)
        if [[ -n "$poll_loops" ]]; then
            echo "    Last poll_loop entries:"
            echo "$poll_loops" | while read -r pl; do echo "      $pl"; done
        fi

        ip_failures=$(grep -ciE "fell back|fallback|full recompute" "$logfile" 2>/dev/null) || ip_failures=0
        echo "    I-P fallback events: $ip_failures"

        long_polls=$(grep "poll_loop" "$logfile" 2>/dev/null | grep -oP '[0-9]+\s*ms' 2>/dev/null | awk '{if($1+0>1000) c++} END{print c+0}' 2>/dev/null) || long_polls=0
        echo "    Slow poll iterations (>1s): $long_polls"
    done <<< "$northd_logs"

    if [[ "$total_recomputes" -gt 100 ]]; then
        verdict "northd Recomputes" "CRITICAL" "$total_recomputes recompute events"
    elif [[ "$total_recomputes" -gt 10 ]]; then
        verdict "northd Recomputes" "WARNING" "$total_recomputes recompute events"
    else
        verdict "northd Recomputes" "OK" "$total_recomputes recompute events"
    fi
else
    echo "  No northd logs found"
    verdict "northd Recomputes" "WARNING" "No logs"
fi

# --- ovn-controller Health (per node) ---

header "ovn-controller Health (per node)"

ctrl_logs=""
if [[ -d "$NS_OVN/pods" ]]; then
    ctrl_logs=$(find "$NS_OVN/pods" -path "*/ovnkube-node-*/ovn-controller/logs/current.log" 2>/dev/null || true)
fi

total_cpu_hits=0
total_dropped=0
problem_nodes=()

if [[ -n "$ctrl_logs" ]]; then
    while IFS= read -r logfile; do
        [[ -f "$logfile" ]] || continue
        podname=$(echo "$logfile" | grep -oP 'pods/\K[^/]+')

        cpu_hits=$(grep -c "100% CPU" "$logfile" 2>/dev/null) || cpu_hits=0
        dropped=$(grep -c "Dropped.*log messages" "$logfile" 2>/dev/null) || dropped=0
        long_polls=$(grep "poll_loop" "$logfile" 2>/dev/null | grep -oP '[0-9]+\s*ms' 2>/dev/null | awk '{if($1+0>1000) c++} END{print c+0}' 2>/dev/null) || long_polls=0

        total_cpu_hits=$((total_cpu_hits + cpu_hits))
        total_dropped=$((total_dropped + dropped))

        flag=""
        if [[ "$cpu_hits" -gt 0 || "$dropped" -gt 0 ]]; then
            flag=" ${RED}<-- PROBLEM${RST}"
            problem_nodes+=("$podname")
        fi

        printf "  %-45s CPU-100%%: %-5s Dropped: %-5s SlowPoll: %-5s%b\n" \
            "$podname" "$cpu_hits" "$dropped" "$long_polls" "$flag"
    done <<< "$ctrl_logs"

    if [[ "$total_cpu_hits" -gt 10 ]]; then
        verdict "ovn-controller" "CRITICAL" "${#problem_nodes[@]} nodes with CPU saturation ($total_cpu_hits events)"
    elif [[ "$total_cpu_hits" -gt 0 ]]; then
        verdict "ovn-controller" "WARNING" "$total_cpu_hits CPU-100% events across ${#problem_nodes[@]} nodes"
    else
        verdict "ovn-controller" "OK" "No CPU saturation detected"
    fi
else
    echo "  No ovn-controller logs found"
    verdict "ovn-controller" "WARNING" "No logs"
fi

# --- Resource Usage ---

header "Resource Requests/Limits"

top_file="$NETWORK_LOGS/ovn_kubernetes_top_pods"
if [[ -f "$top_file" ]]; then
    echo "  Top pods snapshot:"
    grep -E "ovnkube|ovn-controller|NAME" "$top_file" 2>/dev/null | while read -r l; do
        echo "    $l"
    done

    high_cpu=$(grep -E "ovn-controller|ovnkube" "$top_file" 2>/dev/null | awk '{gsub(/m/,"",$3); if($3+0 > 200) print $1, $2, $3"m"}' || true)
    if [[ -n "$high_cpu" ]]; then
        verdict "Resource Usage" "WARNING" "High CPU usage detected at snapshot"
    else
        verdict "Resource Usage" "OK" "CPU within bounds at snapshot time"
    fi
else
    echo "  No top_pods data found"
    verdict "Resource Usage" "WARNING" "No top data"
fi

# --- ANP Status Bloat ---

header "AdminNetworkPolicy Status Bloat"

anp_dir="$CLUSTER_SCOPED/policy.networking.k8s.io/adminnetworkpolicies"
if [[ -d "$anp_dir" ]]; then
    total_conditions=0
    anp_count=0
    bloated=()

    for f in "$anp_dir"/*.yaml; do
        [[ -f "$f" ]] || continue
        anp_count=$((anp_count + 1))
        name=$(basename "$f" .yaml)
        cond_count=$(grep -c "type:.*Ready" "$f" 2>/dev/null) || cond_count=0
        total_conditions=$((total_conditions + cond_count))

        zone_count=$(grep -oP 'ReadyInZone-\K[^ "]+' "$f" 2>/dev/null | sort -u | wc -l) || zone_count=0
        if [[ "$cond_count" -gt "$((zone_count + 5))" && "$zone_count" -gt 0 ]]; then
            bloat_pct=$(( (cond_count - zone_count) * 100 / cond_count ))
            bloated+=("$name: $cond_count conditions, $zone_count unique zones (~${bloat_pct}% bloat)")
        fi
    done

    echo "  ANP count: $anp_count"
    echo "  Total status.conditions entries: $total_conditions"

    if [[ ${#bloated[@]} -gt 0 ]]; then
        echo ""
        echo "  Bloated ANPs:"
        for b in "${bloated[@]}"; do
            echo -e "    ${YEL}$b${RST}"
        done
        verdict "ANP Bloat" "WARNING" "${#bloated[@]} ANPs with stale conditions"
    else
        verdict "ANP Bloat" "OK" "No significant bloat detected"
    fi
else
    echo "  No ANP resources found"
    verdict "ANP Bloat" "OK" "No ANPs present"
fi

# --- OpenFlow Stats ---

header "OpenFlow Rule Counts"

of_files=$(find "$INNER_DIR" \( -name "*dump-flows*" -o -name "*ofctl*" \) -type f 2>/dev/null | head -20 || true)
if [[ -n "$of_files" ]]; then
    while IFS= read -r of_file; do
        node_hint=$(echo "$of_file" | grep -oP 'nodes/\K[^/]+' 2>/dev/null || basename "$(dirname "$of_file")")
        total_flows=$(wc -l < "$of_file" 2>/dev/null) || total_flows=0
        conj_flows=$(grep -c "conjunction" "$of_file" 2>/dev/null) || conj_flows=0
        printf "  %-45s total: %-8s conjunction: %s\n" "$node_hint" "$total_flows" "$conj_flows"
    done <<< "$of_files"
    verdict "OpenFlow" "OK" "Data available"
else
    echo "  No OpenFlow dump files found in must-gather"
    verdict "OpenFlow" "WARNING" "No dump-flows data"
fi

# --- Summary ---

echo ""
echo -e "${BLD}${CYN}==========================================${RST}"
echo -e "${BLD}${CYN}            VERDICT SUMMARY               ${RST}"
echo -e "${BLD}${CYN}==========================================${RST}"
echo ""

for v in "${verdict_summary[@]}"; do
    echo -e "  $v"
done

echo ""
if [[ ${#problem_nodes[@]} -gt 0 ]]; then
    echo -e "${BLD}Problem nodes:${RST}"
    for pn in "${problem_nodes[@]}"; do
        echo "  - $pn"
    done
else
    echo -e "${BLD}Problem nodes:${RST} none detected"
fi
echo ""

} # end main

main "$@" 2>&1 | scrub_output
