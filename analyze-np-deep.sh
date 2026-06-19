#!/bin/bash
#
# analyze-np-deep.sh — Deep diagnostics for problem nodes from analyze-np-scale.sh
# Usage: ./analyze-np-deep.sh [--no-scrub] <must-gather-dir>
#
# Digs into ovn-controller logs, northd I-P engine details, and ovnkube-controller
# activity on nodes showing CPU saturation or dropped messages.
# Default: scrub enabled (safe to share output)

set -euo pipefail

RED='\033[0;31m'
YEL='\033[0;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
BLD='\033[1m'
RST='\033[0m'

SCRUB=true
while [[ "${1:-}" == --* ]]; do
    case "$1" in
        --scrub) SCRUB=true; shift ;;
        --no-scrub) SCRUB=false; shift ;;
        *) echo "Unknown flag: $1" >&2; exit 1 ;;
    esac
done

header() { echo ""; echo -e "${BLD}${CYN}=== $1 ===${RST}"; }
subheader() { echo -e "  ${BLD}--- $1 ---${RST}"; }
die() { echo -e "${RED}ERROR: $1${RST}" >&2; exit 1; }

# --- Scrub filter (same as analyze-np-scale.sh) ---
scrub_output() {
    if [[ "$SCRUB" == "true" ]]; then
        python3 -c "
import re, sys
ip_map, host_map = {}, {}
ip_counter, host_counter, role_counters = [0], [0], {}
def replace_ip(m):
    ip = m.group(0)
    if ip not in ip_map:
        ip_counter[0] += 1
        ip_map[ip] = f'x.x.x.{ip_counter[0]}'
    return ip_map[ip]
def replace_fqdn(m):
    fqdn = m.group(0)
    if fqdn.startswith(('quay-io','registry-')) or fqdn.endswith(('.log','.yaml','.gz','.tar','.txt')):
        return fqdn
    if fqdn not in host_map:
        lower = fqdn.lower()
        role = 'control-plane' if ('master' in lower or 'control-plane' in lower) else 'worker' if ('worker' in lower or 'compute' in lower) else 'infra' if 'infra' in lower else 'node'
        role_counters[role] = role_counters.get(role, 0) + 1
        host_map[fqdn] = f'cluster-{role}-{role_counters[role]}.redacted'
    return host_map[fqdn]
def replace_hostname(m):
    name = m.group(0)
    if name not in host_map:
        lower = name.lower()
        role = 'control-plane' if ('master' in lower or 'control-plane' in lower) else 'worker' if ('worker' in lower or 'compute' in lower) else 'infra' if 'infra' in lower else 'node'
        role_counters[role] = role_counters.get(role, 0) + 1
        host_map[name] = f'cluster-{role}-{role_counters[role]}'
    return host_map[name]
ip_re = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b')
fqdn_re = re.compile(r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?){2,}\b')
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

main() {

[[ $# -lt 1 ]] && die "Usage: $0 [--no-scrub] <must-gather-dir>"

MG_ROOT="$(realpath "$1")"
[[ -d "$MG_ROOT" ]] || die "Not a directory: $MG_ROOT"

INNER_DIR=$(find "$MG_ROOT" -maxdepth 1 -type d \( -name "quay-io-*" -o -name "registry-*" \) | head -1)
if [[ -z "$INNER_DIR" ]]; then
    if [[ -d "$MG_ROOT/network_logs" || -d "$MG_ROOT/namespaces" ]]; then
        INNER_DIR="$MG_ROOT"
    else
        die "Cannot find must-gather inner directory under $MG_ROOT"
    fi
fi

NS_OVN="$INNER_DIR/namespaces/openshift-ovn-kubernetes"

# =====================================================================
# 1. Identify problem nodes (CPU-100% or Dropped in ovn-controller)
# =====================================================================
header "Problem Node Identification"

declare -A problem_nodes
if [[ -d "$NS_OVN/pods" ]]; then
    while IFS= read -r logfile; do
        [[ -f "$logfile" ]] || continue
        podname=$(echo "$logfile" | grep -oP 'pods/\K[^/]+')
        cpu_hits=$(grep -c "100% CPU" "$logfile" 2>/dev/null) || cpu_hits=0
        dropped=$(grep -c "Dropped.*log messages" "$logfile" 2>/dev/null) || dropped=0
        if [[ "$cpu_hits" -gt 0 || "$dropped" -gt 0 ]]; then
            problem_nodes[$podname]="CPU-100%:$cpu_hits Dropped:$dropped"
            echo "  $podname — CPU-100%: $cpu_hits, Dropped: $dropped"
        fi
    done < <(find "$NS_OVN/pods" -path "*/ovnkube-node-*/ovn-controller/logs/current.log" 2>/dev/null)
fi

if [[ ${#problem_nodes[@]} -eq 0 ]]; then
    echo "  No problem nodes detected. Analyzing all nodes..."
    while IFS= read -r logdir; do
        podname=$(basename "$logdir")
        [[ "$podname" == ovnkube-node-* ]] && problem_nodes[$podname]="no-issues"
    done < <(find "$NS_OVN/pods" -maxdepth 1 -type d -name "ovnkube-node-*" 2>/dev/null | head -5)
fi

# =====================================================================
# 2. ovn-controller detailed logs for problem nodes
# =====================================================================
header "ovn-controller Deep Dive (problem nodes)"

for podname in "${!problem_nodes[@]}"; do
    ctrl_log="$NS_OVN/pods/$podname/ovn-controller/ovn-controller/logs/current.log"
    [[ -f "$ctrl_log" ]] || ctrl_log="$NS_OVN/pods/$podname/ovn-controller/logs/current.log"
    [[ -f "$ctrl_log" ]] || continue

    subheader "$podname (${problem_nodes[$podname]})"

    # a) AddressSet processing time
    echo "    Address_Set / Port_Group update events:"
    grep -iE "address.set|port.group" "$ctrl_log" 2>/dev/null | grep -iv "poll_loop" | tail -10 | while read -r l; do
        echo "      $l"
    done

    # b) lflow_run / recompute events
    echo "    lflow_run / recompute events:"
    grep -iE "lflow_run|lflow.*recompute|full recompute" "$ctrl_log" 2>/dev/null | tail -5 | while read -r l; do
        echo "      $l"
    done

    # c) Binding updates (patch port, claim)
    echo "    Binding claim/release events:"
    grep -iE "claim|release|binding" "$ctrl_log" 2>/dev/null | grep -iv "poll_loop\|mac_binding" | tail -5 | while read -r l; do
        echo "      $l"
    done

    # d) Errors and warnings
    echo "    Errors/Warnings (last 10):"
    grep -iE "\|ERR\||\|WARN\|" "$ctrl_log" 2>/dev/null | tail -10 | while read -r l; do
        echo "      $l"
    done

    # e) 100% CPU timestamps (for correlation)
    echo "    CPU-100% timestamps:"
    grep "100% CPU" "$ctrl_log" 2>/dev/null | head -10 | grep -oP '^\S+' | while read -r ts; do
        echo "      $ts"
    done

    # f) Flow installation stats
    echo "    Flow update stats:"
    grep -iE "flow.*added|flow.*deleted|flow.*modified|installed.*flow" "$ctrl_log" 2>/dev/null | tail -5 | while read -r l; do
        echo "      $l"
    done
    echo ""
done

# =====================================================================
# 3. ovnkube-controller logs for problem nodes
# =====================================================================
header "ovnkube-controller Logs (problem nodes)"

for podname in "${!problem_nodes[@]}"; do
    ctrl_log="$NS_OVN/pods/$podname/ovnkube-controller/ovnkube-controller/logs/current.log"
    [[ -f "$ctrl_log" ]] || ctrl_log="$NS_OVN/pods/$podname/ovnkube-controller/logs/current.log"
    [[ -f "$ctrl_log" ]] || continue

    subheader "$podname"

    # a) NetworkPolicy processing
    echo "    NetworkPolicy events (last 20):"
    grep -iE "network.?policy|netpol|acl" "$ctrl_log" 2>/dev/null | tail -20 | while read -r l; do
        echo "      $l"
    done

    # b) Errors and warnings
    echo "    Errors/Warnings (last 15):"
    grep -iE "\|ERR\||\|WARN\||error|failed" "$ctrl_log" 2>/dev/null | grep -iv "TLS\|cert\|x509" | tail -15 | while read -r l; do
        echo "      $l"
    done

    # c) Retry/queue events (sign of overload)
    echo "    Retry/queue events:"
    grep -iE "retry|queue|backoff|timeout|deadline" "$ctrl_log" 2>/dev/null | tail -10 | while read -r l; do
        echo "      $l"
    done

    # d) Pod/namespace events (ArgoCD churn signal)
    echo "    Recent namespace/pod update rate:"
    ns_updates=$(grep -ciE "namespace.*update|namespace.*add|namespace.*delete" "$ctrl_log" 2>/dev/null) || ns_updates=0
    pod_updates=$(grep -ciE "pod.*update|pod.*add|pod.*delete" "$ctrl_log" 2>/dev/null) || pod_updates=0
    echo "      Namespace events: $ns_updates"
    echo "      Pod events: $pod_updates"
    echo ""
done

# =====================================================================
# 4. northd I-P engine details
# =====================================================================
header "northd Incremental Processing Details"

while IFS= read -r logfile; do
    [[ -f "$logfile" ]] || continue
    podname=$(echo "$logfile" | grep -oP 'pods/\K[^/]+')

    # Only show nodes with high recompute or dropped messages
    recomputes=$(grep -ciE "recompute|Recomputing" "$logfile" 2>/dev/null) || recomputes=0
    drops=$(grep -c "Dropped" "$logfile" 2>/dev/null) || drops=0
    [[ "$recomputes" -le 2 && "$drops" -eq 0 ]] && continue

    subheader "$podname (recomputes: $recomputes, drops: $drops)"

    # I-P engine node details
    echo "    I-P engine change tracking:"
    grep -iE "change.*tracked|eng_has_run|I-P.*abort|I-P.*skip" "$logfile" 2>/dev/null | tail -10 | while read -r l; do
        echo "      $l"
    done

    # Recompute reasons
    echo "    Recompute reasons:"
    grep -B1 -iE "recompute|Recomputing" "$logfile" 2>/dev/null | tail -10 | while read -r l; do
        echo "      $l"
    done

    # Timing: time between poll_loop wakeups (detect slow iterations)
    echo "    Poll loop timing (showing gaps >5s):"
    grep "poll_loop" "$logfile" 2>/dev/null | grep -oP '^\S+' | while read -r ts; do
        echo "$ts"
    done | awk -F'[T.]' '
    NR>1 {
        split(prev, a, ":")
        split($3, b, ":")
        prev_s = a[1]*3600 + a[2]*60 + a[3]
        cur_s = b[1]*3600 + b[2]*60 + b[3]
        gap = cur_s - prev_s
        if (gap < 0) gap += 86400
        if (gap > 5) printf "      %s -> %s (gap: %ds)\n", prev_full, $0, gap
    }
    { prev = $3; prev_full = $0 }
    ' 2>/dev/null

    echo ""
done < <(find "$NS_OVN/pods" -path "*/northd/*/logs/current.log" -o -path "*/northd/logs/current.log" 2>/dev/null)

# =====================================================================
# 5. ArgoCD churn detection
# =====================================================================
header "ArgoCD Churn Detection"

# Check if ArgoCD annotations/labels appear in ovnkube-controller logs
for podname in "${!problem_nodes[@]}"; do
    ctrl_log="$NS_OVN/pods/$podname/ovnkube-controller/ovnkube-controller/logs/current.log"
    [[ -f "$ctrl_log" ]] || ctrl_log="$NS_OVN/pods/$podname/ovnkube-controller/logs/current.log"
    [[ -f "$ctrl_log" ]] || continue

    argocd_events=$(grep -ciE "argocd|argoproj" "$ctrl_log" 2>/dev/null) || argocd_events=0
    if [[ "$argocd_events" -gt 0 ]]; then
        echo "  $podname: $argocd_events ArgoCD-related events"
        grep -iE "argocd|argoproj" "$ctrl_log" 2>/dev/null | tail -5 | while read -r l; do
            echo "    $l"
        done
    fi
done

# Check for ArgoCD labels in cluster-scoped resources
argocd_ns_dir="$INNER_DIR/namespaces"
if [[ -d "$argocd_ns_dir" ]]; then
    argocd_labeled=$(find "$argocd_ns_dir" -name "*.yaml" -exec grep -l "argocd\|argoproj" {} \; 2>/dev/null | wc -l) || argocd_labeled=0
    echo "  Resources with ArgoCD annotations/labels: $argocd_labeled"
fi

# =====================================================================
# 6. NP count per namespace (top 10)
# =====================================================================
header "NetworkPolicy Distribution (top namespaces)"

np_dir="$INNER_DIR/cluster-scoped-resources/networking.k8s.io/networkpolicies"
if [[ -d "$np_dir" ]]; then
    find "$np_dir" -name "*.yaml" 2>/dev/null | while read -r f; do
        grep -m1 "namespace:" "$f" 2>/dev/null | awk '{print $2}'
    done | sort | uniq -c | sort -rn | head -10 | while read -r count ns; do
        printf "  %-50s %s NPs\n" "$ns" "$count"
    done
else
    # Try from namespaced resources
    find "$INNER_DIR/namespaces" -path "*/networking.k8s.io/networkpolicies/*.yaml" 2>/dev/null | \
        awk -F'/' '{for(i=1;i<=NF;i++) if($(i)=="namespaces") print $(i+1)}' | \
        sort | uniq -c | sort -rn | head -10 | while read -r count ns; do
            printf "  %-50s %s NPs\n" "$ns" "$count"
        done
fi

# =====================================================================
# 7. Time correlation: when did problems cluster?
# =====================================================================
header "Problem Timeline"

echo "  CPU-100% event distribution (by hour):"
find "$NS_OVN/pods" -path "*/ovn-controller/*/logs/current.log" -o -path "*/ovn-controller/logs/current.log" 2>/dev/null | while read -r f; do
    grep "100% CPU" "$f" 2>/dev/null
done | grep -oP '^\S+T\d{2}' 2>/dev/null | sort | uniq -c | sort -rn | head -10 | while read -r count hour; do
    echo "    $hour:xx — $count events"
done

echo ""
echo "  Dropped messages distribution (by hour):"
find "$NS_OVN/pods" -path "*/ovn-controller/*/logs/current.log" -o -path "*/ovn-controller/logs/current.log" 2>/dev/null | while read -r f; do
    grep "Dropped.*log messages" "$f" 2>/dev/null
done | grep -oP '^\S+T\d{2}' 2>/dev/null | sort | uniq -c | sort -rn | head -10 | while read -r count hour; do
    echo "    $hour:xx — $count events"
done

echo ""

} # end main

main "$@" 2>&1 | scrub_output
