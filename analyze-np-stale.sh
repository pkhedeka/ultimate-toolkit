#!/bin/bash
#
# analyze-np-stale.sh — Detect stale NP state in must-gather OVSDB dumps
# Usage: ./analyze-np-stale.sh [--no-scrub] <must-gather-dir> <broken-ns> [good-ns]
#
# Compares Port Groups, ACLs, LSPs, and Address Sets between a known-broken
# namespace and a known-good one. Flags missing port-group membership,
# orphaned ACLs, and address set mismatches.
#
# Detects stale NP state after mass re-sync events (e.g., GitOps tracking
# migration, controller ownership changes, API server reconnects).
#
# --scrub (default): sanitize hostnames, FQDNs, and IPs in output
# --no-scrub: show raw data (for local analysis only)

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

verdict_summary=()

verdict() {
    local section="$1" level="$2" msg="$3"
    local color="$GRN"
    [[ "$level" == "WARNING" ]] && color="$YEL"
    [[ "$level" == "CRITICAL" ]] && color="$RED"
    verdict_summary+=("$(printf "%-35s ${color}%-10s${RST} %s" "$section" "$level" "$msg")")
}

header() { echo ""; echo -e "${BLD}${CYN}=== $1 ===${RST}"; }
subheader() { echo -e "  ${BLD}--- $1 ---${RST}"; }
die() { echo -e "${RED}ERROR: $1${RST}" >&2; exit 1; }

scrub_output() {
    if [[ "$SCRUB" == "true" ]]; then
        python3 -c "
import re, sys
ip_map, host_map = {}, {}
ip_counter, role_counters = [0], {}
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
ip_re = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b')
fqdn_re = re.compile(r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?){2,}\b')
for line in sys.stdin:
    line = ip_re.sub(replace_ip, line)
    line = fqdn_re.sub(replace_fqdn, line)
    sys.stdout.write(line)
"
    else
        cat
    fi
}

# Python helper: extract NP-related OVN state for given namespaces from OVSDB
analyze_np_state() {
    local dbfile="$1"
    local broken_ns="$2"
    local good_ns="$3"
    python3 - "$dbfile" "$broken_ns" "$good_ns" << 'PYEOF'
import json, sys, re
from collections import defaultdict

dbfile = sys.argv[1]
broken_ns = sys.argv[2]
good_ns = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else ""

with open(dbfile) as f:
    lines = f.readlines()

# Replay OVSDB clustered backup diffs to reconstruct final state
state = {}
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

def get_ext_id(rec, key):
    """Extract value from external_ids field."""
    ext = rec.get("external_ids", {})
    if isinstance(ext, list) and len(ext) == 2 and ext[0] == "map":
        ext = dict(ext[1])
    elif isinstance(ext, list):
        ext = {}
    return ext.get(key, "")

def get_set(rec, field):
    """Extract set field as list of UUIDs."""
    val = rec.get(field, [])
    if isinstance(val, list) and len(val) == 2:
        if val[0] == "set":
            return [v[1] if isinstance(v, list) and len(v) == 2 else v for v in val[1]]
        elif val[0] == "uuid":
            return [val[1]]
    if isinstance(val, str):
        return [val] if val else []
    return []

def analyze_namespace(ns, label):
    """Analyze OVN NP state for a namespace."""
    if not ns:
        return

    print(f"\n{'='*60}")
    print(f"  {label}: {ns}")
    print(f"{'='*60}")

    # 1. Find all Port Groups for this namespace
    print(f"\n  --- Port Groups ---")
    ns_port_groups = {}
    for uuid, rec in state.get("Port_Group", {}).items():
        name = get_ext_id(rec, "k8s.ovn.org/name")
        owner_type = get_ext_id(rec, "k8s.ovn.org/owner-type")
        if ns in name:
            ports = get_set(rec, "ports")
            acls = get_set(rec, "acls")
            direction = get_ext_id(rec, "direction")
            pg_name = rec.get("name", "?")
            ns_port_groups[uuid] = {
                "name": name, "owner_type": owner_type,
                "ports": ports, "acls": acls,
                "direction": direction, "pg_name": pg_name
            }
            dir_str = f" [{direction}]" if direction else ""
            print(f"    {owner_type}{dir_str}: {name}")
            print(f"      UUID: {uuid}")
            print(f"      PG name: {pg_name}")
            print(f"      Ports: {len(ports)} {ports[:5]}{'...' if len(ports)>5 else ''}")
            print(f"      ACLs:  {len(acls)} {acls[:5]}{'...' if len(acls)>5 else ''}")

    # 2. Find LSPs for this namespace
    print(f"\n  --- Logical Switch Ports ---")
    ns_lsps = {}
    for uuid, rec in state.get("Logical_Switch_Port", {}).items():
        lsp_ns = get_ext_id(rec, "namespace")
        if lsp_ns == ns:
            lsp_name = rec.get("name", "?")
            addresses = rec.get("addresses", [])
            if isinstance(addresses, list) and len(addresses) == 2 and addresses[0] == "set":
                addresses = addresses[1]
            elif isinstance(addresses, str):
                addresses = [addresses]
            up = rec.get("up", "?")
            ns_lsps[uuid] = {"name": lsp_name, "addresses": addresses, "up": up}
            print(f"    {lsp_name}")
            print(f"      UUID: {uuid}")
            print(f"      Addresses: {addresses}")
            print(f"      Up: {up}")

    # 3. Cross-check: are LSP UUIDs in Port Group ports?
    print(f"\n  --- Port Group Membership Check ---")
    all_pg_ports = set()
    for pg in ns_port_groups.values():
        all_pg_ports.update(pg["ports"])

    orphan_lsps = []
    for lsp_uuid, lsp in ns_lsps.items():
        in_pg = lsp_uuid in all_pg_ports
        status = "OK" if in_pg else "MISSING"
        if not in_pg:
            orphan_lsps.append(lsp["name"])
        marker = "" if in_pg else " <-- NOT IN ANY PORT GROUP"
        print(f"    [{status}] {lsp['name']} ({lsp_uuid[:12]}){marker}")

    if orphan_lsps:
        print(f"\n    *** {len(orphan_lsps)} LSP(s) NOT in any Port Group — NP won't apply to these pods ***")

    # 4. Examine ACLs
    print(f"\n  --- ACLs ---")
    ns_acls = {}
    for uuid, rec in state.get("ACL", {}).items():
        owner_type = get_ext_id(rec, "k8s.ovn.org/owner-type")
        acl_name = get_ext_id(rec, "k8s.ovn.org/name")
        if owner_type == "NetworkPolicy" and ns in acl_name:
            action = rec.get("action", "?")
            direction = rec.get("direction", "?")
            match_str = rec.get("match", "?")
            priority = rec.get("priority", "?")
            ns_acls[uuid] = {
                "name": acl_name, "action": action,
                "direction": direction, "match": match_str,
                "priority": priority
            }
            print(f"    {action:6s} {direction:10s} pri={priority} {acl_name}")
            print(f"      UUID: {uuid}")
            print(f"      Match: {match_str[:100]}{'...' if len(str(match_str))>100 else ''}")

    # Also check NetpolNamespace ACLs (default deny)
    for uuid, rec in state.get("ACL", {}).items():
        owner_type = get_ext_id(rec, "k8s.ovn.org/owner-type")
        acl_name = get_ext_id(rec, "k8s.ovn.org/name")
        if owner_type == "NetpolNamespace" and ns in acl_name:
            action = rec.get("action", "?")
            direction = rec.get("direction", "?")
            match_str = rec.get("match", "?")
            priority = rec.get("priority", "?")
            ns_acls[uuid] = {
                "name": acl_name, "action": action,
                "direction": direction, "match": match_str,
                "priority": priority
            }
            print(f"    {action:6s} {direction:10s} pri={priority} {acl_name} [NetpolNamespace]")

    # 5. ACL completeness check
    print(f"\n  --- ACL Completeness ---")
    # Group ACLs by NP name
    np_acls = defaultdict(list)
    for uuid, acl in ns_acls.items():
        np_name = acl["name"].split("/")[-1] if "/" in acl["name"] else acl["name"]
        np_acls[np_name].append(acl)

    for np_name, acls in sorted(np_acls.items()):
        actions = {a["action"] for a in acls}
        directions = {a["direction"] for a in acls}
        has_allow = "allow-related" in actions or "allow" in actions
        has_deny = "drop" in actions
        status = "OK" if (has_allow or has_deny) else "SUSPECT"
        if not has_allow and has_deny:
            status = "DENY-ONLY"
        print(f"    [{status}] {np_name}: {len(acls)} ACLs, actions={actions}, dirs={directions}")
        if status == "DENY-ONLY":
            print(f"      *** Only deny ACLs — allow ACL missing? ***")

    # 6. Address Sets
    print(f"\n  --- Address Sets ---")
    ns_addr_sets = {}
    for uuid, rec in state.get("Address_Set", {}).items():
        as_name = get_ext_id(rec, "k8s.ovn.org/name")
        owner_type = get_ext_id(rec, "k8s.ovn.org/owner-type")
        if ns in as_name:
            addresses = rec.get("addresses", [])
            if isinstance(addresses, list) and len(addresses) == 2 and addresses[0] == "set":
                addresses = addresses[1]
            elif isinstance(addresses, str):
                addresses = [addresses]
            ip_family = get_ext_id(rec, "ip-family")
            ns_addr_sets[uuid] = {"name": as_name, "addresses": addresses, "ip_family": ip_family}
            print(f"    {as_name} [{ip_family}] ({owner_type})")
            print(f"      Addresses: {len(addresses)} {addresses[:5]}{'...' if len(addresses)>5 else ''}")

    # 7. Address Set vs LSP cross-check
    if ns_lsps and ns_addr_sets:
        print(f"\n  --- Address Set vs Pod IP Check ---")
        lsp_ips = set()
        for lsp in ns_lsps.values():
            for addr in lsp["addresses"]:
                if isinstance(addr, str):
                    for part in addr.split():
                        if re.match(r'\d+\.\d+\.\d+\.\d+', part):
                            lsp_ips.add(part)

        for as_uuid, aset in ns_addr_sets.items():
            if aset["ip_family"] != "v4":
                continue
            as_ips = set()
            for a in aset["addresses"]:
                if isinstance(a, str) and re.match(r'\d+\.\d+\.\d+\.\d+', a):
                    as_ips.add(a)
            # In IC mode, this node's NB only has local LSPs
            # Address set may have IPs from other zones — that's normal
            local_missing = lsp_ips - as_ips
            if local_missing:
                print(f"    [WARNING] {aset['name']}: local pod IPs missing from address set: {local_missing}")
            else:
                print(f"    [OK] {aset['name']}: all local pod IPs present in address set")

    # Summary counts
    return {
        "port_groups": len(ns_port_groups),
        "lsps": len(ns_lsps),
        "acls": len(ns_acls),
        "addr_sets": len(ns_addr_sets),
        "orphan_lsps": len(orphan_lsps) if 'orphan_lsps' in dir() else 0,
        "total_pg_ports": sum(len(pg["ports"]) for pg in ns_port_groups.values()),
    }

# Run analysis
broken_stats = analyze_namespace(broken_ns, "BROKEN NAMESPACE")
good_stats = None
if good_ns:
    good_stats = analyze_namespace(good_ns, "GOOD NAMESPACE")

# Comparison
if broken_stats and good_stats:
    print(f"\n{'='*60}")
    print(f"  COMPARISON: {broken_ns} vs {good_ns}")
    print(f"{'='*60}")
    for key in ["port_groups", "lsps", "acls", "addr_sets", "total_pg_ports"]:
        bv = broken_stats.get(key, 0)
        gv = good_stats.get(key, 0)
        marker = ""
        if key == "total_pg_ports" and bv == 0 and gv > 0:
            marker = " <-- STALE: broken has no ports in PGs!"
        elif key == "acls" and bv < gv:
            marker = " <-- FEWER ACLs in broken namespace"
        elif key == "orphan_lsps" and bv > 0:
            marker = " <-- LSPs not in port groups!"
        print(f"    {key:20s}  broken={bv:5d}  good={gv:5d}{marker}")

    if broken_stats.get("orphan_lsps", 0) > 0:
        print(f"\n    *** VERDICT: Stale port-group membership detected ***")
        print(f"    *** Pods exist but not in NP port groups = NP not enforced ***")

PYEOF
}

main() {

[[ $# -lt 2 ]] && die "Usage: $0 [--scrub|--no-scrub] <must-gather-dir> <broken-ns> [good-ns]"

MG_ROOT="$(realpath "$1")"
BROKEN_NS="$2"
GOOD_NS="${3:-}"

[[ -d "$MG_ROOT" ]] || die "Not a directory: $MG_ROOT"

INNER_DIR=$(find "$MG_ROOT" -maxdepth 1 -type d \( -name "quay-io-*" -o -name "registry-*" \) | head -1)
if [[ -z "$INNER_DIR" ]]; then
    if [[ -d "$MG_ROOT/network_logs" || -d "$MG_ROOT/namespaces" ]]; then
        INNER_DIR="$MG_ROOT"
    else
        die "Cannot find must-gather inner directory under $MG_ROOT"
    fi
fi

NETWORK_LOGS="$INNER_DIR/network_logs"
NS_OVN="$INNER_DIR/namespaces/openshift-ovn-kubernetes"
TMPDIR_DB=""

cleanup() {
    [[ -n "$TMPDIR_DB" && -d "$TMPDIR_DB" ]] && rm -rf "$TMPDIR_DB"
}
trap cleanup EXIT

echo -e "${BLD}Must-gather root:${RST} $INNER_DIR"
echo -e "${BLD}Broken namespace:${RST} $BROKEN_NS"
[[ -n "$GOOD_NS" ]] && echo -e "${BLD}Good namespace:${RST}   $GOOD_NS"

# --- Extract OVN DB ---

header "OVN Database Extraction"

DB_ARCHIVE="$NETWORK_LOGS/ovnk_database_store.tar.gz"

if [[ ! -f "$DB_ARCHIVE" ]]; then
    die "No ovnk_database_store.tar.gz — cannot analyze NP state without DB dumps"
fi

TMPDIR_DB=$(mktemp -d)
tar -xzf "$DB_ARCHIVE" -C "$TMPDIR_DB" 2>/dev/null
echo "Extracted OVN DB to temp dir"

mapfile -t NBDB_FILES < <(find "$TMPDIR_DB" -name "*_nbdb" -type f 2>/dev/null)
echo "Found ${#NBDB_FILES[@]} NB database(s)"

if [[ ${#NBDB_FILES[@]} -eq 0 ]]; then
    die "No NB database files found in archive"
fi

# --- Analyze each NB database (one per node in IC mode) ---

header "NP State Analysis"

if [[ ${#NBDB_FILES[@]} -gt 1 ]]; then
    echo -e "${YEL}  IC cluster detected (${#NBDB_FILES[@]} zones). Analyzing each zone separately.${RST}"
    echo "  NOTE: In IC mode, LSPs and Port Group ports are zone-local."
    echo "        Address Sets are cluster-wide."
fi

for nbf in "${NBDB_FILES[@]}"; do
    node_name=$(basename "$nbf" | sed 's/_nbdb//')
    echo ""
    echo -e "${BLD}  Zone: $node_name${RST}"
    analyze_np_state "$nbf" "$BROKEN_NS" "$GOOD_NS"
done

# --- Controller logs for broken namespace ---

header "Controller Logs for $BROKEN_NS"

if [[ -d "$NS_OVN/pods" ]]; then
    found_logs=false
    while IFS= read -r logfile; do
        [[ -f "$logfile" ]] || continue
        podname=$(echo "$logfile" | grep -oP 'pods/\K[^/]+')

        np_events=$(grep -c "$BROKEN_NS" "$logfile" 2>/dev/null) || np_events=0
        [[ "$np_events" -eq 0 ]] && continue

        found_logs=true
        subheader "$podname ($np_events events)"

        echo "    NP processing events:"
        grep "$BROKEN_NS" "$logfile" 2>/dev/null | grep -iE "networkpolicy|port.?group|address.?set" | tail -15 | while read -r l; do
            echo "      $l"
        done

        echo "    Errors/warnings:"
        grep "$BROKEN_NS" "$logfile" 2>/dev/null | grep -iE "error|warn|fail" | tail -10 | while read -r l; do
            echo "      $l"
        done
    done < <(find "$NS_OVN/pods" \( -path "*/ovnkube-controller/*/logs/current.log" -o -path "*/ovnkube-controller/logs/current.log" \) 2>/dev/null)

    if [[ "$found_logs" == "false" ]]; then
        echo "  No controller log entries found for $BROKEN_NS"
    fi
else
    echo "  No ovnkube pod logs in must-gather"
fi

# --- Summary ---

echo ""
echo -e "${BLD}${CYN}==========================================${RST}"
echo -e "${BLD}${CYN}       WHAT TO DO WITH THIS OUTPUT        ${RST}"
echo -e "${BLD}${CYN}==========================================${RST}"
echo ""
echo "  Key things to check in the output above:"
echo ""
echo "  1. Port Group 'Ports' count vs LSP count"
echo "     - If PG has 0 ports but LSPs exist → stale port-group membership"
echo "     - NP won't apply to pods not in port groups"
echo ""
echo "  2. ACL completeness per NP"
echo "     - DENY-ONLY means allow ACL is missing → all traffic dropped"
echo "     - Compare ACL count between broken and good namespaces"
echo ""
echo "  3. LSPs marked 'NOT IN ANY PORT GROUP'"
echo "     - Pods exist in OVN but NP port groups don't reference them"
echo "     - Root cause of intermittent NP enforcement failure"
echo ""
echo "  4. Address Set IPs vs pod IPs"
echo "     - Missing IPs = NP ingress rules won't match source pods"
echo "     - In IC mode, only local zone LSPs are visible"
echo ""
echo "  Causality tests (run on LIVE cluster, not from must-gather):"
echo ""
echo "    Test 1 — annotation touch (is it a cache miss?):"
echo "      oc annotate networkpolicy -n $BROKEN_NS <np-name> debug=test"
echo "      oc annotate networkpolicy -n $BROKEN_NS <np-name> debug-"
echo ""
echo "    Test 2 — delete+recreate (stale port-group?):"
echo "      oc get networkpolicy -n $BROKEN_NS <np-name> -o yaml > /tmp/np-bak.yaml"
echo "      oc delete -f /tmp/np-bak.yaml"
echo "      oc apply -f /tmp/np-bak.yaml"
echo ""

} # end main

main "$@" 2>&1 | scrub_output
