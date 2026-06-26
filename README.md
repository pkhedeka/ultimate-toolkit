# ultimate-toolkit

Diagnostic scripts for OpenShift networking (OVN-Kubernetes, OVS, OVN). Parse must-gather archives, sosreports, and live clusters to root-cause connectivity failures, NetworkPolicy enforcement issues, and performance bottlenecks.

## Quick Start

Download any script directly:

```bash
curl -sLO https://raw.githubusercontent.com/Ultimate-etamitlU/ultimate-toolkit/main/<script>.sh
chmod +x <script>.sh
```

## Tools Overview

| Script | Input | What It Does |
|--------|-------|-------------|
| `scan-np-stale.sh` | must-gather | Auto-scans all namespaces for stale NP port-group membership |
| `analyze-np-stale.sh` | must-gather | Compares NP state between a broken and healthy namespace |
| `analyze-np-scale.sh` | must-gather | Checks NP-at-scale health: ACL counts, nb_cfg sync, northd recomputes |
| `analyze-np-deep.sh` | must-gather | Deep dive on problem nodes: controller logs, I-P engine, timelines |
| `analyze-node-connectivity-mg.sh` | must-gather | Root-causes node connectivity failures from OVN state |
| `analyze-node-connectivity-sos.sh` | sosreport | Root-causes node connectivity failures from OVS/system state |
| `scrub-must-gather.sh` | must-gather | Creates a scrubbed copy with IPs and hostnames anonymized |
| `ocp-preflight/` | install-config | Pre-install validation (DNS, creds, infra) — see its own [README](ocp-preflight/README.md) |
| `oc-traffic/` | live cluster | OVN traffic path tracer |

## Common Flags

All analysis scripts support:

- `--scrub` (default) — anonymize IPs, hostnames, and FQDNs in output. Safe for sharing in Jira or with customers.
- `--no-scrub` — show raw data. Use for local analysis only.

## Collecting a Must-Gather with Network Logs

Most scripts need a must-gather collected with `gather_network_logs`, which includes OVN database dumps:

```bash
oc adm must-gather --dest-dir=/tmp/must-gather -- /usr/bin/gather_network_logs
```

---

## NetworkPolicy Scripts

### scan-np-stale.sh

Auto-scans **all** namespaces with NetworkPolicies for stale port-group membership. No need to know which namespace is broken — the script finds them.

**When to use:** NetworkPolicy enforcement stops intermittently. Policies only work after deleting and recreating them. Happens after mass re-sync events like GitOps tracking migration, controller ownership changes, or API server reconnects.

**What it checks:**
- Extracts all NB databases from the must-gather (one per node in OVN IC clusters)
- For every namespace with NetworkPolicies, compares the Logical Switch Ports (pods) against Port Group membership
- Flags namespaces where pods exist in OVN but aren't referenced by any NP Port Group
- Checks ACL completeness — flags NPs that have deny rules but no matching allow rules
- Outputs a targeted workaround command for affected namespaces

**Usage:**
```bash
./scan-np-stale.sh <must-gather-dir>
./scan-np-stale.sh --no-scrub <must-gather-dir>
```

**Sample output:**
```
Found 35 NB database(s)
IC cluster (zone-per-node)

======================================================================
  SCAN RESULTS
======================================================================

  *** STALE PORT GROUP MEMBERSHIP: 25 namespace(s) ***

  my-app-namespace
    LSPs (pods): 4  |  In Port Groups: 3  |  Orphaned: 1
      NOT IN PG: my-app-namespace_my-pod-abc123 (58c72a36-0d0)

======================================================================
  SUMMARY
======================================================================

  Namespaces with NPs scanned:     1408
  Healthy:                         1383
  Stale port-group membership:     25
  ACL issues (deny-only):          0
  NB databases (zones):            35

  VERDICT: Stale NP port-group membership detected
```

---

### analyze-np-stale.sh

Detailed per-namespace comparison of NP state between a known-broken and known-good namespace. Use after `scan-np-stale.sh` identifies the broken namespaces.

**When to use:** You know which namespace is broken and want to see exactly what's wrong — which Port Groups are missing ports, which ACLs are present/absent, whether Address Sets match pod IPs.

**What it checks:**
- Port Groups per namespace (Namespace, NetpolNamespace, per-NetworkPolicy) — lists ports and ACLs in each
- Logical Switch Ports — all pods in the namespace visible in this zone's NB database
- Port Group membership cross-check — flags LSPs not in any Port Group
- ACL completeness — lists every ACL by action/direction, flags deny-only NPs
- Address Sets — checks pod IPs match the namespace address set
- Controller logs — NP processing events and errors for the namespace
- Side-by-side comparison of all counts between broken and good namespace

**Usage:**
```bash
./analyze-np-stale.sh <must-gather-dir> <broken-ns> [good-ns]
./analyze-np-stale.sh --no-scrub <must-gather-dir> <broken-ns> <good-ns>
```

---

### analyze-np-scale.sh

Overall NP-at-scale health check. Parses the OVSDB database dumps and OVN logs to assess whether the cluster is under NP-related stress.

**When to use:** Cluster has a large number of NetworkPolicies (1000+) and you suspect OVN is struggling to keep up. Symptoms: slow NP application, northd CPU saturation, ovn-controller dropping messages.

**What it checks:**
- NB database scale metrics: ACL, Port_Group, Address_Set, LSP, Load_Balancer counts
- nb_cfg sync gap between NB_Global and per-chassis SB values (detects nodes falling behind)
- Per-node NB vs SB sync for IC clusters
- northd recompute frequency and I-P engine fallbacks
- ovn-controller health per node: CPU-100% events, dropped log messages, slow poll loops
- Resource usage: CPU consumption vs requests from top-pods snapshot
- AdminNetworkPolicy status bloat: stale node conditions consuming CPU
- OpenFlow rule counts per node

**Usage:**
```bash
./analyze-np-scale.sh <must-gather-dir>
./analyze-np-scale.sh --no-scrub <must-gather-dir>
```

---

### analyze-np-deep.sh

Deep dive into the OVN logs on problem nodes identified by `analyze-np-scale.sh`.

**When to use:** `analyze-np-scale.sh` flagged nodes with CPU saturation or dropped messages and you need to understand what's driving the load.

**What it checks:**
- Identifies problem nodes (CPU-100% or dropped messages in ovn-controller)
- Per-node ovn-controller analysis: log module breakdown, errors/warnings, CPU-100% timestamps, dropped message bursts
- Per-node ovnkube-controller analysis: NP processing events, retry/queue activity, pod/namespace update rate
- northd I-P engine details: change tracking, recompute reasons, poll loop timing gaps
- ArgoCD churn detection: ArgoCD-related events in controller logs, annotated resource count
- NetworkPolicy distribution: NP count per namespace (top 10)
- Problem timeline: CPU-100% and dropped message distribution by hour

**Usage:**
```bash
./analyze-np-deep.sh <must-gather-dir>
./analyze-np-deep.sh --no-scrub <must-gather-dir>
```

---

## Node Connectivity Scripts

### analyze-node-connectivity-mg.sh

Root-causes node connectivity failures from a must-gather.

**When to use:** A node loses cluster network connectivity, pods can't communicate, or the node shows NotReady due to networking issues.

**What it checks:**
- Node annotations: OVN host addresses, host-cidrs, chassis ID
- Chassis registration in SB database and match with node annotations
- ovnkube-controller logs: annotation parse errors, reconciliation loops
- Geneve tunnel state: local_ip mismatches, missing tunnels
- MachineConfigPool status: degraded nodes, pending configs
- nb_cfg sync gap per node

**Usage:**
```bash
./analyze-node-connectivity-mg.sh <must-gather-dir>
./analyze-node-connectivity-mg.sh --no-scrub <must-gather-dir>
```

---

### analyze-node-connectivity-sos.sh

Root-causes node connectivity failures from a sosreport. Complements the must-gather script with host-level data.

**When to use:** You have a sosreport from an affected node and want to check OVS/OVN local state, NIC flaps, or kernel-level issues.

**What it checks:**
- OVS system-id and bridge configuration
- OpenFlow tables on br-int and br-ex
- OVN controller connection status and tunnel configuration
- dmesg: NIC link flaps, driver errors, OOM kills
- OVS/OVN service status and recent restarts

**Usage:**
```bash
./analyze-node-connectivity-sos.sh <sosreport-dir>
./analyze-node-connectivity-sos.sh --no-scrub <sosreport-dir>
```

---

## Utility Scripts

### scrub-must-gather.sh

Creates a scrubbed copy of a must-gather directory with all IPs and hostnames anonymized. Original is untouched.

**When to use:** You need to share a must-gather externally or attach it to a public issue but it contains customer-specific IPs and hostnames.

**What it scrubs:**
- File contents: IPv4 addresses, FQDNs, short hostnames (master-N, worker-N patterns)
- Filenames and directory names containing hostnames
- Handles compressed `.gz` files (decompresses, scrubs, recompresses)
- Skips binary files (`.db`, `.tar.gz`)

**Usage:**
```bash
./scrub-must-gather.sh <must-gather-dir> [output-dir]
```

---

## Sub-tools

### ocp-preflight/ (Ickis)

Pre-install validation for OpenShift. Checks DNS, credentials, infrastructure prerequisites before running `openshift-install`. See [ocp-preflight/README.md](ocp-preflight/README.md).

### oc-traffic/

OVN-Kubernetes network path tracer. Visualizes the OVN logical pipeline for a given traffic flow on a live cluster.
