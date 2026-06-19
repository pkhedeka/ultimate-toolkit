# Ickis — OCP Installation Pre-flight Validator

> *"Scaring up install problems before they scare you!"*
>
> Named after [Ickis](https://en.wikipedia.org/wiki/Aaahh!!!_Real_Monsters) from *Aaahh!!! Real Monsters* — because bad prerequisites are the real monsters of OCP installations.

Validates OpenShift Container Platform installation prerequisites before running `openshift-install`. Catches DNS misconfigurations, credential issues, missing infrastructure, and other common failure causes early — before they become mid-install failures.


## Supported Platforms

- **vSphere** (IPI/UPI)
- **Bare Metal** (IPI/UPI)
- **Agent-Based Installer** (ABI)
- **Single Node OpenShift** (SNO)

## Prerequisites

Required:
- `python3` with `PyYAML` (`dnf install python3-pyyaml`)
- `curl`

Optional (enables more checks):
- `dig` (`bind-utils`) — DNS validation
- `nc` (`nmap-ncat`) — port reachability
- `govc` — vSphere object validation
- `fio` — etcd disk performance
- `podman` — pull secret verification
- `nmap` — DHCP discovery
- `nmstatectl` (`nmstate`) — NMState config validation
- `ipmitool` — BMC IPMI checks

## Usage

### Interactive mode
```bash
./ickis.sh
```

### With install-config.yaml
```bash
./ickis.sh /path/to/install-config.yaml
```

### With install directory (auto-detects configs)
```bash
./ickis.sh /path/to/install-dir/
```

### ABI with agent-config
```bash
./ickis.sh install-config.yaml --agent-config agent-config.yaml
```

### With pull secret
```bash
./ickis.sh install-config.yaml --pull-secret ~/pull-secret.json
```

## Container Usage

### Build
```bash
podman build -t ickis -f Containerfile .
```

### Run with configs mounted
```bash
podman run -it --rm \
  -v /path/to/install-dir:/workspace:Z \
  ickis /workspace/install-config.yaml
```

### Interactive mode in container
```bash
podman run -it --rm ickis
```

## What It Checks

### Common (all platforms)
- DNS A records: `api.<cluster>.<domain>`, `api-int.<cluster>.<domain>`
- DNS wildcard: `*.apps.<cluster>.<domain>`
- DNS PTR records for node IPs
- NTP synchronization
- SSH key presence
- Pull secret validity
- VIP port reachability (6443, 22623, 443, 80)
- install-config.yaml syntax
- etcd disk fsync performance

### vSphere
- vCenter reachability (port 443)
- vCenter TLS certificate (self-signed warning)
- vCenter authentication
- vCenter version (7.0U2+ required)
- Datacenter, cluster, datastore, network, folder, resource pool existence
- Datastore free space (>= 100GB)

### Bare Metal
- BMC connectivity and Redfish API access
- BMC credential validation
- Provisioning/external bridge existence
- Node IP reachability
- Inter-node port accessibility
- DHCP server presence

### Agent-Based Installer / SNO
- Network plugin = OVNKubernetes (required)
- Topology validation (SNO: 1 CP + 0 workers)
- agent-config.yaml syntax
- rendezvousIP reachability
- Host definitions and static IP config
- NMState configuration presence
- apiVIPs / ingressVIPs specification

## Output

Color-coded results:
- **[PASS]** — check passed
- **[FAIL]** — check failed, must fix before installing
- **[WARN]** — potential issue, review recommended
- **[SKIP]** — check skipped (missing tool or data)

Exit code: `0` = all checks passed, `1` = failures found.

## Adding New Platforms

1. Create `lib/platform-<name>.sh` with `run_<name>_checks()` and `prompt_<name>_details()`
2. Source it in `ickis.sh`
3. Add case in `run_platform_checks()`
4. Add to the interactive menu in `interactive_setup()`

## License

Apache License 2.0
