import json
import re
import subprocess
import sys

from .errors import (
    OcTrafficError, PodNotFoundError, OvnQueryError, OvsQueryError,
    InsufficientPermissions,
)
from .models import (
    PodInfo, OvnKubeInfo, OvsPort, BridgeInfo, LogicalSwitchPort,
    LogicalSwitch, LogicalRouterInfo, GatewayRouterInfo, PhysicalNIC,
    Chassis, PortBinding, FlowEntry, PodPath, ClusterInfo,
)
from .cluster import detect_ic_and_db, detect_gateway_mode


# OVN-K naming conventions from types/const.go
OVN_CLUSTER_ROUTER = "ovn_cluster_router"
GW_ROUTER_PREFIX = "GR_"
ROUTER_TO_SWITCH_PREFIX = "rtos-"
SWITCH_TO_ROUTER_PREFIX = "stor-"
JOIN_SWITCH_PREFIX = "join_"
EXT_SWITCH_PREFIX = "ext_"
GW_ROUTER_TO_EXT_PREFIX = "rtoe-"
EXT_TO_GW_ROUTER_PREFIX = "etor-"
GW_ROUTER_TO_JOIN_PREFIX = "rtoj-"
JOIN_TO_GW_ROUTER_PREFIX = "jtor-"
TRANSIT_SWITCH = "transit_switch"
ROUTER_TO_TRANSIT_PREFIX = "rtots-"
TRANSIT_TO_ROUTER_PREFIX = "tstor-"
PHYSNET = "physnet"
K8S_MGMT_INTF = "ovn-k8s-mp0"


def _run_oc(args, timeout=30, verbose=False):
    cmd = ["oc"] + args
    if verbose:
        sys.stderr.write(f"  >> {' '.join(cmd)}\n")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise OcTrafficError(f"oc failed: {' '.join(cmd)}\n{result.stderr.strip()}")
    return result.stdout.strip()


def _oc_exec(pod_name, namespace, container, command, timeout=30, verbose=False):
    cmd = ["oc", "exec", "-n", namespace, pod_name, "-c", container, "--",
           "bash", "-c", command]
    if verbose:
        sys.stderr.write(f"  >> {' '.join(cmd)}\n")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise OvnQueryError(
            f"exec failed in {pod_name}/{container}: {command}\n{result.stderr.strip()}"
        )
    return result.stdout


def collect_pod_path(pod_name, namespace, cluster_info, show_flows=False,
                     verbose=False):
    path = PodPath()
    path.cluster_info = cluster_info

    # 1. Get pod info
    if verbose:
        sys.stderr.write("Collecting pod info...\n")
    path.pod = get_pod_info(pod_name, namespace, verbose)

    # 2. Find ovnkube-node pod on same node
    if verbose:
        sys.stderr.write(f"Finding ovnkube-node pod on {path.pod.node_name}...\n")
    ovnkube_pod = get_ovnkube_pod_on_node(
        path.pod.node_name, cluster_info.ovn_namespace, verbose
    )

    # 3. Detect IC mode, DB URIs
    if verbose:
        sys.stderr.write("Detecting IC mode and database URIs...\n")
    (is_ic, zone_name, ovnk_container, nb_cmd, sb_cmd,
     nb_uri, sb_uri, ssl_keys) = detect_ic_and_db(
        ovnkube_pod, cluster_info.ovn_namespace, verbose
    )
    cluster_info.is_interconnect = is_ic
    cluster_info.zone_name = zone_name

    path.ovnkube = OvnKubeInfo(
        pod_name=ovnkube_pod,
        container_name=ovnk_container,
        nb_command=nb_cmd,
        sb_command=sb_cmd,
        nb_uri=nb_uri,
        sb_uri=sb_uri,
        ssl_cert_keys=ssl_keys,
    )

    # 4. Gateway mode
    path.gateway_mode = detect_gateway_mode(path.pod.node_name, verbose)

    ovn_ns = cluster_info.ovn_namespace

    # 5. OVS interface
    if verbose:
        sys.stderr.write("Querying OVS interface...\n")
    if path.pod.host_network:
        path.ovs_port = OvsPort(
            name=K8S_MGMT_INTF,
            ofport=_get_mp0_ofport(ovnkube_pod, ovn_ns, ovnk_container, verbose),
            iface_id=f"k8s-{path.pod.node_name}",
        )
    else:
        path.ovs_port = get_ovs_interface(
            path.pod, ovnkube_pod, ovn_ns, ovnk_container, verbose
        )

    # 6. br-int info
    if verbose:
        sys.stderr.write("Querying br-int...\n")
    path.br_int = get_bridge_info(
        "br-int", ovnkube_pod, ovn_ns, ovnk_container, verbose
    )

    # 7. Logical switch port + port binding
    if verbose:
        sys.stderr.write("Querying logical switch port...\n")
    fq_name = f"{namespace}_{pod_name}" if not path.pod.host_network else f"k8s-{path.pod.node_name}"
    path.logical_switch_port = get_logical_switch_port(
        fq_name, path.ovnkube, ovnkube_pod, ovn_ns, verbose
    )

    # Port binding (needed for tunnel key)
    path.port_binding = get_port_binding(
        fq_name, path.ovnkube, ovnkube_pod, ovn_ns, verbose
    )
    if path.port_binding.tunnel_key:
        path.logical_switch_port.tunnel_key = path.port_binding.tunnel_key

    # 8. Logical switch — get tunnel key
    path.logical_switch = LogicalSwitch(name=path.pod.node_name)
    ls_tunnel_key = get_datapath_tunnel_key(
        path.pod.node_name, path.ovnkube, ovnkube_pod, ovn_ns, verbose
    )
    path.logical_switch.tunnel_key = ls_tunnel_key

    # 9. Cluster router — rtos MAC + IP
    if verbose:
        sys.stderr.write("Querying cluster router...\n")
    rtos_mac, rtos_ip = get_router_port_mac_and_ip(
        ROUTER_TO_SWITCH_PREFIX + path.pod.node_name,
        path.ovnkube, ovnkube_pod, ovn_ns, verbose
    )
    path.cluster_router = LogicalRouterInfo(
        name=OVN_CLUSTER_ROUTER,
        rtos_port=ROUTER_TO_SWITCH_PREFIX + path.pod.node_name,
        rtos_mac=rtos_mac,
        rtos_ip=rtos_ip,
    )

    # 10. Gateway router
    if verbose:
        sys.stderr.write("Querying gateway router...\n")
    gr_name = GW_ROUTER_PREFIX + path.pod.node_name
    nat_rules = get_nat_rules(gr_name, path.ovnkube, ovnkube_pod, ovn_ns, verbose)
    external_ip = ""
    for rule in nat_rules:
        if "snat" in rule.lower():
            parts = rule.split()
            if len(parts) >= 3:
                external_ip = parts[1]
                break

    path.gateway_router = GatewayRouterInfo(
        name=gr_name,
        nat_rules=nat_rules,
        external_ip=external_ip,
        join_switch=JOIN_SWITCH_PREFIX + path.pod.node_name,
        external_switch=EXT_SWITCH_PREFIX + path.pod.node_name,
    )

    # 11. External bridge name
    if verbose:
        sys.stderr.write("Querying external bridge...\n")
    ext_bridge_name = get_external_bridge_name(
        path.pod.node_name, path.ovnkube, ovnkube_pod, ovn_ns, verbose
    )
    path.external_bridge = BridgeInfo(name=ext_bridge_name or "br-ex")

    # 12. Physical NIC
    if verbose:
        sys.stderr.write("Querying physical NIC...\n")
    path.physical_nic = get_physical_nic(
        path.external_bridge.name, ovnkube_pod, ovn_ns, ovnk_container, verbose
    )

    # 13. Chassis
    if verbose:
        sys.stderr.write("Querying chassis...\n")
    path.chassis = get_chassis(
        path.pod.node_name, path.ovnkube, ovnkube_pod, ovn_ns, verbose
    )

    # 14. Flows (optional)
    if show_flows:
        if verbose:
            sys.stderr.write("Querying OVS flows...\n")
        path.flows = get_ovs_flows(
            path.pod.ip, path.ovs_port.ofport,
            ovnkube_pod, ovn_ns, ovnk_container, verbose
        )

    return path


# --- Individual collectors ---

def get_pod_info(pod_name, namespace, verbose=False):
    try:
        output = _run_oc(
            ["get", "pod", pod_name, "-n", namespace, "-o", "json"],
            verbose=verbose,
        )
    except OcTrafficError:
        raise PodNotFoundError(pod_name, namespace)

    pod_json = json.loads(output)
    spec = pod_json.get("spec", {})
    metadata = pod_json.get("metadata", {})
    status = pod_json.get("status", {})

    host_network = spec.get("hostNetwork", False)

    # Parse OVN pod-networks annotation
    annotations = metadata.get("annotations", {})
    pod_networks = annotations.get("k8s.ovn.org/pod-networks", "")

    ip = ""
    mac = ""
    gateways = []

    if pod_networks:
        try:
            net_info = json.loads(pod_networks)
            default_net = net_info.get("default", {})
            ip_addrs = default_net.get("ip_addresses", [])
            if ip_addrs:
                ip = ip_addrs[0].split("/")[0]
            elif default_net.get("ip_address"):
                ip = default_net["ip_address"].split("/")[0]
            mac = default_net.get("mac_address", "")
            gateways = default_net.get("gateway_ips", [])
            if not gateways and default_net.get("gateway_ip"):
                gateways = [default_net["gateway_ip"]]
        except json.JSONDecodeError:
            pass

    # Fallback: use status.podIP
    if not ip:
        ip = status.get("podIP", "")

    return PodInfo(
        name=pod_name,
        namespace=namespace,
        ip=ip,
        mac=mac,
        node_name=spec.get("nodeName", ""),
        host_network=host_network,
        gateways=gateways,
    )


def get_ovnkube_pod_on_node(node_name, ovn_namespace, verbose=False):
    output = _run_oc(
        ["get", "pods", "-n", ovn_namespace,
         "-l", "app=ovnkube-node",
         "--field-selector", f"spec.nodeName={node_name}",
         "-o", "jsonpath={.items[0].metadata.name}"],
        verbose=verbose,
    )
    if not output:
        raise OcTrafficError(
            f"Cannot find ovnkube-node pod on node {node_name} in namespace {ovn_namespace}"
        )
    return output


def get_ovs_interface(pod_info, ovnkube_pod, ovn_ns, container, verbose=False):
    fq_name = f"{pod_info.namespace}_{pod_info.name}"
    cmd = f"ovs-vsctl --columns name,ofport find interface external_ids:iface-id={fq_name}"
    output = _oc_exec(ovnkube_pod, ovn_ns, container, cmd, verbose=verbose)

    port = OvsPort(iface_id=fq_name)
    for line in output.splitlines():
        parts = line.split(":", 1)
        if len(parts) != 2:
            continue
        key = parts[0].strip()
        val = parts[1].strip().strip('"')
        if key == "name":
            port.name = val
        elif key == "ofport":
            port.ofport = val

    if not port.name:
        raise OvsQueryError(f"Cannot find OVS interface for {fq_name}")
    return port


def _get_mp0_ofport(ovnkube_pod, ovn_ns, container, verbose=False):
    cmd = f"ovs-vsctl get Interface {K8S_MGMT_INTF} ofport"
    output = _oc_exec(ovnkube_pod, ovn_ns, container, cmd, verbose=verbose)
    return output.strip()


def get_bridge_info(bridge_name, ovnkube_pod, ovn_ns, container, verbose=False):
    cmd = f"ovs-vsctl list-ports {bridge_name}"
    try:
        output = _oc_exec(ovnkube_pod, ovn_ns, container, cmd, verbose=verbose)
        ports = [p.strip() for p in output.splitlines() if p.strip()]
    except OvnQueryError:
        ports = []
    return BridgeInfo(name=bridge_name, ports=ports)


def get_logical_switch_port(fq_name, ovnkube_info, ovnkube_pod, ovn_ns,
                            verbose=False):
    cmd = (
        f"ovn-nbctl --no-leader-only {ovnkube_info.nb_command} "
        f"--bare --no-heading --columns=name,type,addresses "
        f"find Logical_Switch_Port name={fq_name}"
    )
    output = _oc_exec(ovnkube_pod, ovn_ns, ovnkube_info.container_name, cmd,
                      verbose=verbose)

    lsp = LogicalSwitchPort(name=fq_name)
    # --bare --no-heading outputs values in column order, one per line
    columns = ["name", "type", "addresses"]
    values = output.splitlines()
    for i, col in enumerate(columns):
        val = values[i].strip() if i < len(values) else ""
        if col == "type":
            lsp.type = val
        elif col == "addresses":
            lsp.addresses = val

    return lsp


def get_router_port_mac(port_name, ovnkube_info, ovnkube_pod, ovn_ns,
                        verbose=False):
    mac, _ = get_router_port_mac_and_ip(port_name, ovnkube_info, ovnkube_pod, ovn_ns, verbose)
    return mac


def get_router_port_mac_and_ip(port_name, ovnkube_info, ovnkube_pod, ovn_ns,
                               verbose=False):
    cmd = (
        f"ovn-sbctl --no-leader-only {ovnkube_info.sb_command} "
        f"--bare --no-heading --column=mac list Port_Binding {port_name}"
    )
    output = _oc_exec(ovnkube_pod, ovn_ns, ovnkube_info.container_name, cmd,
                      verbose=verbose)
    # Format: "0a:58:a8:fe:00:03 100.88.0.3/16"
    mac_ip = output.strip().split()
    mac = mac_ip[0] if mac_ip else ""
    ip = mac_ip[1] if len(mac_ip) > 1 else ""
    return mac, ip


def get_datapath_tunnel_key(ls_name, ovnkube_info, ovnkube_pod, ovn_ns,
                            verbose=False):
    """Get tunnel key for a logical switch datapath from SB."""
    cmd = (
        f"ovn-sbctl --no-leader-only {ovnkube_info.sb_command} "
        f"--bare --no-heading --columns=tunnel_key "
        f"find Datapath_Binding external_ids:name={ls_name}"
    )
    try:
        output = _oc_exec(ovnkube_pod, ovn_ns, ovnkube_info.container_name, cmd,
                          verbose=verbose)
        return output.strip()
    except OvnQueryError:
        return ""


def get_nat_rules(router_name, ovnkube_info, ovnkube_pod, ovn_ns,
                  verbose=False):
    cmd = (
        f"ovn-nbctl --no-leader-only {ovnkube_info.nb_command} "
        f"lr-nat-list {router_name}"
    )
    try:
        output = _oc_exec(ovnkube_pod, ovn_ns, ovnkube_info.container_name, cmd,
                          verbose=verbose)
        rules = [line.strip() for line in output.splitlines() if line.strip()]
        return rules
    except OvnQueryError:
        return []


def get_external_bridge_name(node_name, ovnkube_info, ovnkube_pod, ovn_ns,
                             verbose=False):
    cmd = (
        f"ovn-sbctl --no-leader-only {ovnkube_info.sb_command} "
        f"--bare --no-heading --column=logical_port find Port_Binding "
        f"options:network_name={PHYSNET}"
    )
    try:
        output = _oc_exec(ovnkube_pod, ovn_ns, ovnkube_info.container_name, cmd,
                          verbose=verbose)
        for line in output.splitlines():
            line = line.strip()
            if f"_{node_name}" in line:
                parts = line.split("_", 1)
                if len(parts) == 2:
                    return parts[0]
    except OvnQueryError:
        pass
    return "br-ex"


def get_physical_nic(bridge_name, ovnkube_pod, ovn_ns, container,
                     verbose=False):
    # Get ports on br-ex, find the physical NIC (not patch ports)
    cmd = f"ovs-vsctl list-ports {bridge_name}"
    try:
        output = _oc_exec(ovnkube_pod, ovn_ns, container, cmd, verbose=verbose)
        ports = [p.strip() for p in output.splitlines() if p.strip()]
    except OvnQueryError:
        return PhysicalNIC(name="unknown")

    # Filter out patch ports and internal ports
    nic_name = ""
    for port in ports:
        if port.startswith("patch-") or port.startswith("br-"):
            continue
        # Check if it's a system port (physical NIC)
        type_cmd = f"ovs-vsctl get Interface {port} type"
        try:
            port_type = _oc_exec(ovnkube_pod, ovn_ns, container, type_cmd,
                                 verbose=verbose).strip().strip('"')
            if port_type in ("", "system"):
                nic_name = port
                break
        except OvnQueryError:
            continue

    if not nic_name:
        nic_name = ports[0] if ports else "unknown"

    # Get MAC and MTU
    nic = PhysicalNIC(name=nic_name)
    try:
        mac_cmd = f"ovs-vsctl get Interface {nic_name} mac_in_use"
        nic.mac = _oc_exec(ovnkube_pod, ovn_ns, container, mac_cmd,
                           verbose=verbose).strip().strip('"')
    except OvnQueryError:
        pass

    try:
        mtu_cmd = f"ovs-vsctl get Interface {nic_name} mtu"
        nic.mtu = _oc_exec(ovnkube_pod, ovn_ns, container, mtu_cmd,
                           verbose=verbose).strip()
    except OvnQueryError:
        pass

    try:
        link_cmd = f"ovs-vsctl get Interface {nic_name} link_state"
        state = _oc_exec(ovnkube_pod, ovn_ns, container, link_cmd,
                         verbose=verbose).strip().strip('"')
        nic.state = "UP" if state == "up" else state.upper()
    except OvnQueryError:
        nic.state = "unknown"

    return nic


def get_chassis(node_name, ovnkube_info, ovnkube_pod, ovn_ns, verbose=False):
    cmd = (
        f"ovn-sbctl --no-leader-only {ovnkube_info.sb_command} "
        f"--bare --no-heading --columns=name,hostname,encaps "
        f"find Chassis hostname={node_name}"
    )
    chassis = Chassis(hostname=node_name)
    try:
        output = _oc_exec(ovnkube_pod, ovn_ns, ovnkube_info.container_name, cmd,
                          verbose=verbose)
        # --bare --no-heading outputs values in column order, one per line
        columns = ["name", "hostname", "encaps"]
        values = output.splitlines()
        for i, col in enumerate(columns):
            val = values[i].strip() if i < len(values) else ""
            if col == "name":
                chassis.name = val
            elif col == "hostname":
                chassis.hostname = val
            elif col == "encaps":
                if val:
                    chassis.encap_type = "geneve"
    except OvnQueryError:
        pass
    return chassis


def get_port_binding(fq_name, ovnkube_info, ovnkube_pod, ovn_ns, verbose=False):
    cmd = (
        f"ovn-sbctl --no-leader-only {ovnkube_info.sb_command} "
        f"--bare --no-heading "
        f"--columns=logical_port,type,chassis,tunnel_key "
        f"find Port_Binding logical_port={fq_name}"
    )
    pb = PortBinding(logical_port=fq_name)
    try:
        output = _oc_exec(ovnkube_pod, ovn_ns, ovnkube_info.container_name, cmd,
                          verbose=verbose)
        # --bare --no-heading outputs values in column order, one per line
        columns = ["logical_port", "type", "chassis", "tunnel_key"]
        values = output.splitlines()
        for i, col in enumerate(columns):
            val = values[i].strip() if i < len(values) else ""
            if col == "type":
                pb.type = val
            elif col == "chassis":
                pb.chassis = val
            elif col == "tunnel_key":
                pb.tunnel_key = val
    except OvnQueryError:
        pass
    return pb


def get_ovs_flows(pod_ip, ofport, ovnkube_pod, ovn_ns, container,
                  verbose=False):
    cmd = f"ovs-ofctl dump-flows br-int"
    try:
        output = _oc_exec(ovnkube_pod, ovn_ns, container, cmd,
                          timeout=60, verbose=verbose)
    except OvnQueryError:
        return []

    flows = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("NXST") or line.startswith("OFPST"):
            continue
        # Filter for flows matching pod IP or ofport
        if pod_ip and pod_ip not in line:
            if ofport and f"in_port={ofport}" not in line and f"output:{ofport}" not in line:
                continue

        entry = FlowEntry()
        # Parse table
        m = re.search(r"table=(\d+)", line)
        if m:
            entry.table = m.group(1)
        # Parse priority
        m = re.search(r"priority=(\d+)", line)
        if m:
            entry.priority = m.group(1)
        # Parse packet count
        m = re.search(r"n_packets=(\d+)", line)
        if m:
            entry.n_packets = m.group(1)
        # Parse byte count
        m = re.search(r"n_bytes=(\d+)", line)
        if m:
            entry.n_bytes = m.group(1)
        # Match and actions
        m = re.search(r"actions=(.*)", line)
        if m:
            entry.actions = m.group(1)

        flows.append(entry)

    return flows
