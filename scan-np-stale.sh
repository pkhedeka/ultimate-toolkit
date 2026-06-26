#!/bin/bash
#
# scan-np-stale.sh — Scan must-gather for stale NP port-group membership
# Usage: ./scan-np-stale.sh [--no-scrub] <must-gather-dir>
#
# Auto-detects all namespaces with NetworkPolicies and checks every zone's
# NB database for stale Port Group membership (pods exist but not in PG).
# No need to know which namespace is broken — the script finds them.
#
# Detects stale NP state after mass re-sync events (e.g., GitOps tracking
# migration, controller ownership changes, API server reconnects).

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

scan_all_zones() {
    local tmpdir="$1"
    python3 - "$tmpdir" << 'PYEOF'
import json, sys, os, glob, re
from collections import defaultdict

tmpdir = sys.argv[1]

# Find all NB database files
nbdb_files = glob.glob(os.path.join(tmpdir, "**/*_nbdb"), recursive=True)
if not nbdb_files:
    nbdb_files = glob.glob(os.path.join(tmpdir, "**/*.db"), recursive=True)

if not nbdb_files:
    print("ERROR: No NB database files found")
    sys.exit(1)

print(f"Found {len(nbdb_files)} NB database(s)")
print(f"{'IC cluster (zone-per-node)' if len(nbdb_files) > 1 else 'Single NB database'}")
print()

def replay_ovsdb(dbfile):
    """Replay OVSDB clustered backup diffs to get final state."""
    with open(dbfile) as f:
        lines = f.readlines()
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
    return state

def get_ext_id(rec, key):
    ext = rec.get("external_ids", {})
    if isinstance(ext, list) and len(ext) == 2 and ext[0] == "map":
        ext = dict(ext[1])
    elif isinstance(ext, list):
        ext = {}
    return ext.get(key, "")

def get_set(rec, field):
    val = rec.get(field, [])
    if isinstance(val, list) and len(val) == 2:
        if val[0] == "set":
            return [v[1] if isinstance(v, list) and len(v) == 2 else v for v in val[1]]
        elif val[0] == "uuid":
            return [val[1]]
    if isinstance(val, str):
        return [val] if val else []
    return []

# Aggregate findings across all zones
# Key: namespace -> { zone -> { lsps: set, pg_ports: set, acl_issues: [], pg_details: {} } }
ns_findings = defaultdict(lambda: defaultdict(lambda: {
    "lsps": {},
    "pg_ports": set(),
    "np_pg_details": {},
    "acl_issues": [],
    "addr_set_ips": set(),
}))

all_np_namespaces = set()

for nbf in sorted(nbdb_files):
    zone = os.path.basename(nbf).replace("_nbdb", "")
    state = replay_ovsdb(nbf)

    # Find all namespaces that have NetworkPolicy port groups
    for uuid, rec in state.get("Port_Group", {}).items():
        owner_type = get_ext_id(rec, "k8s.ovn.org/owner-type")
        name = get_ext_id(rec, "k8s.ovn.org/name")

        if owner_type == "NetworkPolicy" and ":" in name:
            ns = name.split(":")[0]
            all_np_namespaces.add(ns)
            np_name = name.split(":", 1)[1]
            ports = get_set(rec, "ports")
            acls = get_set(rec, "acls")
            ns_findings[ns][zone]["np_pg_details"][np_name] = {
                "ports": len(ports), "acls": len(acls),
                "port_uuids": set(ports), "acl_uuids": set(acls)
            }
            ns_findings[ns][zone]["pg_ports"].update(ports)

        elif owner_type == "Namespace":
            ns = name
            if ns:
                ports = get_set(rec, "ports")
                ns_findings[ns][zone]["pg_ports"].update(ports)

        elif owner_type == "NetpolNamespace":
            ns = name
            if ns:
                all_np_namespaces.add(ns)
                ports = get_set(rec, "ports")
                ns_findings[ns][zone]["pg_ports"].update(ports)

    # Find LSPs per namespace
    for uuid, rec in state.get("Logical_Switch_Port", {}).items():
        ns = get_ext_id(rec, "namespace")
        if ns and ns in all_np_namespaces:
            lsp_name = rec.get("name", "?")
            ns_findings[ns][zone]["lsps"][uuid] = lsp_name

    # Check ACLs for completeness per NP
    np_acls = defaultdict(list)
    for uuid, rec in state.get("ACL", {}).items():
        owner_type = get_ext_id(rec, "k8s.ovn.org/owner-type")
        acl_name = get_ext_id(rec, "k8s.ovn.org/name")
        if owner_type == "NetworkPolicy" and ":" in acl_name:
            ns = acl_name.split(":")[0]
            action = rec.get("action", "?")
            direction = rec.get("direction", "?")
            np_acls[(ns, acl_name)].append({"action": action, "direction": direction})

    for (ns, np_name), acls in np_acls.items():
        actions = {a["action"] for a in acls}
        has_allow = bool(actions & {"allow-related", "allow"})
        has_deny = "drop" in actions
        if has_deny and not has_allow:
            ns_findings[ns][zone]["acl_issues"].append(
                f"{np_name}: DENY-ONLY (allow ACL missing)")

    # Address Sets
    for uuid, rec in state.get("Address_Set", {}).items():
        as_name = get_ext_id(rec, "k8s.ovn.org/name")
        owner_type = get_ext_id(rec, "k8s.ovn.org/owner-type")
        ip_family = get_ext_id(rec, "ip-family")
        if owner_type == "Namespace" and ip_family == "v4" and as_name in all_np_namespaces:
            addresses = rec.get("addresses", [])
            if isinstance(addresses, list) and len(addresses) == 2 and addresses[0] == "set":
                addresses = addresses[1]
            elif isinstance(addresses, str):
                addresses = [addresses]
            for a in addresses:
                if isinstance(a, str) and re.match(r'\d+\.\d+\.\d+\.\d+', a):
                    ns_findings[as_name]["_global"]["addr_set_ips"].add(a)

# --- Analysis ---

print("=" * 70)
print("  SCAN RESULTS")
print("=" * 70)

stale_namespaces = []
acl_issue_namespaces = []
healthy_count = 0

for ns in sorted(all_np_namespaces):
    zones = ns_findings[ns]

    # Aggregate across zones
    total_lsps = {}
    total_pg_ports = set()
    total_acl_issues = []

    for zone, data in zones.items():
        if zone == "_global":
            continue
        total_lsps.update(data["lsps"])
        total_pg_ports.update(data["pg_ports"])
        total_acl_issues.extend(data["acl_issues"])

    # Check: LSPs exist but not in any port group
    orphan_lsps = {uuid: name for uuid, name in total_lsps.items()
                   if uuid not in total_pg_ports}

    if orphan_lsps or total_acl_issues:
        if orphan_lsps:
            stale_namespaces.append((ns, orphan_lsps, total_lsps, total_pg_ports))
        if total_acl_issues:
            acl_issue_namespaces.append((ns, total_acl_issues))
    else:
        healthy_count += 1

# Print stale namespaces
if stale_namespaces:
    print()
    print(f"  \033[0;31m*** STALE PORT GROUP MEMBERSHIP: {len(stale_namespaces)} namespace(s) ***\033[0m")
    print()
    for ns, orphans, all_lsps, pg_ports in stale_namespaces:
        print(f"  \033[1m{ns}\033[0m")
        print(f"    LSPs (pods): {len(all_lsps)}  |  In Port Groups: {len(pg_ports)}  |  Orphaned: {len(orphans)}")
        for uuid, name in sorted(orphans.items(), key=lambda x: x[1]):
            print(f"    \033[0;31m  NOT IN PG: {name} ({uuid[:12]})\033[0m")

        # Show per-NP port group details for this namespace
        for zone, data in sorted(zones.items()):
            if zone == "_global" or not data["np_pg_details"]:
                continue
            for np_name, pg in sorted(data["np_pg_details"].items()):
                if pg["ports"] == 0 and data["lsps"]:
                    print(f"    \033[0;33m  Zone {zone}: NP '{np_name}' PG has 0 ports but {len(data['lsps'])} LSP(s) exist\033[0m")
        print()
else:
    print()
    print(f"  \033[0;32mNo stale port-group membership detected.\033[0m")
    print()

# Print ACL issues
if acl_issue_namespaces:
    print(f"  \033[0;31m*** ACL ISSUES: {len(acl_issue_namespaces)} namespace(s) ***\033[0m")
    print()
    for ns, issues in acl_issue_namespaces:
        print(f"  \033[1m{ns}\033[0m")
        for issue in issues:
            print(f"    \033[0;33m  {issue}\033[0m")
        print()

# Summary
print("=" * 70)
print("  SUMMARY")
print("=" * 70)
print()
print(f"  Namespaces with NPs scanned:     {len(all_np_namespaces)}")
print(f"  Healthy:                         {healthy_count}")
print(f"  Stale port-group membership:     {len(stale_namespaces)}")
print(f"  ACL issues (deny-only):          {len(acl_issue_namespaces)}")
print(f"  NB databases (zones):            {len(nbdb_files)}")
print()

if stale_namespaces:
    print("  VERDICT: Stale NP port-group membership detected")
    print()
    print("  Workaround — touch all NPs to force reconcile (non-disruptive):")
    print()
    ns_list = " ".join(ns for ns, _, _, _ in stale_namespaces[:10])
    if len(stale_namespaces) <= 10:
        print(f"    for ns in {ns_list}; do")
    else:
        print(f"    # {len(stale_namespaces)} namespaces affected — showing pattern for all app namespaces")
        print("    for ns in $(oc get ns --no-headers -o custom-columns=':metadata.name' | grep -v '^openshift-'); do")
    print("      for np in $(oc get networkpolicy -n \"$ns\" --no-headers -o custom-columns=':metadata.name' 2>/dev/null); do")
    print("        oc annotate networkpolicy -n \"$ns\" \"$np\" force-resync=$(date +%s) --overwrite")
    print("      done")
    print("    done")
    print()
    print("  If annotation touch doesn't fix specific NPs, delete+recreate those individually.")
elif acl_issue_namespaces:
    print("  VERDICT: ACL issues found — some NPs may have missing allow rules")
else:
    print("  VERDICT: All NP port-group memberships look healthy")

print()

PYEOF
}

main() {

[[ $# -lt 1 ]] && die "Usage: $0 [--scrub|--no-scrub] <must-gather-dir>"

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

NETWORK_LOGS="$INNER_DIR/network_logs"
DB_ARCHIVE="$NETWORK_LOGS/ovnk_database_store.tar.gz"

[[ -f "$DB_ARCHIVE" ]] || die "No ovnk_database_store.tar.gz found — need must-gather with gather_network_logs"

echo -e "${BLD}Must-gather:${RST} $INNER_DIR"
echo -e "${BLD}Scanning all namespaces with NetworkPolicies...${RST}"
echo ""

TMPDIR_DB=$(mktemp -d)
trap "rm -rf $TMPDIR_DB" EXIT

tar -xzf "$DB_ARCHIVE" -C "$TMPDIR_DB" 2>/dev/null

scan_all_zones "$TMPDIR_DB"

} # end main

main "$@" 2>&1 | scrub_output
