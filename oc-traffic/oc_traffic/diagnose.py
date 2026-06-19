import json
import re
import subprocess
import sys

from .errors import OcTrafficError, OvnQueryError
from .models import (
    DiagCheck, DiagResult, ConnectivityResult, PodPath,
)
from .collector import (
    collect_pod_path, get_pod_info, get_ovnkube_pod_on_node,
    _run_oc, _oc_exec,
)
from .cluster import detect_ic_and_db, detect_gateway_mode


def run_diagnosis(src_pod_name, src_namespace, dst_str, cluster_info,
                  port=None, protocol="tcp", verbose=False):
    """Full diagnosis: collect both paths, check connectivity, check policies."""
    result = DiagResult()

    # Parse destination
    dst_namespace, dst_pod_name, dst_ip = _parse_destination(
        dst_str, src_namespace, verbose
    )

    if verbose:
        sys.stderr.write(f"Diagnosing: {src_namespace}/{src_pod_name} -> {dst_namespace}/{dst_pod_name or dst_ip}\n")

    # Collect source path
    result.src_path = collect_pod_path(
        src_pod_name, src_namespace, cluster_info, verbose=verbose
    )

    # Collect destination path if it's a pod
    if dst_pod_name:
        try:
            result.dst_path = collect_pod_path(
                dst_pod_name, dst_namespace, cluster_info, verbose=verbose
            )
        except OcTrafficError as e:
            result.checks.append(DiagCheck(
                name="Destination pod reachable",
                passed=False,
                detail=str(e),
                severity="error",
            ))

    # Run checks
    _check_route_exists(result, dst_ip or (result.dst_path.pod.ip if result.dst_path else ""), verbose)
    _check_network_policies(result, src_namespace, dst_namespace, verbose)
    _check_acls(result, verbose)
    _check_port_binding(result, verbose)
    _check_ovs_flows(result, dst_ip or (result.dst_path.pod.ip if result.dst_path else ""), verbose)

    # Connectivity tests
    if dst_ip or (result.dst_path and result.dst_path.pod.ip):
        target_ip = dst_ip or result.dst_path.pod.ip
        result.connectivity = _test_connectivity(
            result.src_path, target_ip, port, protocol, verbose
        )

    return result


def _parse_destination(dst_str, default_namespace, verbose=False):
    """Parse destination into (namespace, pod_name, ip)."""
    # Check if IP
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", dst_str):
        return default_namespace, None, dst_str
    if ":" in dst_str and all(c in "0123456789abcdefABCDEF:" for c in dst_str):
        return default_namespace, None, dst_str

    # namespace/pod format
    if "/" in dst_str:
        ns, pod = dst_str.split("/", 1)
        # Resolve pod IP
        try:
            ip = _run_oc(
                ["get", "pod", pod, "-n", ns, "-o", "jsonpath={.status.podIP}"],
                verbose=verbose,
            )
            return ns, pod, ip
        except OcTrafficError:
            return ns, pod, ""

    # Just pod name in same namespace
    try:
        ip = _run_oc(
            ["get", "pod", dst_str, "-n", default_namespace,
             "-o", "jsonpath={.status.podIP}"],
            verbose=verbose,
        )
        return default_namespace, dst_str, ip
    except OcTrafficError:
        return default_namespace, dst_str, ""


def _check_route_exists(result, dst_ip, verbose):
    """Check if OVN router has route to destination."""
    if not dst_ip or not result.src_path:
        return

    ovnkube = result.src_path.ovnkube
    ovn_ns = result.src_path.cluster_info.ovn_namespace

    try:
        cmd = (
            f"ovn-nbctl --no-leader-only {ovnkube.nb_command} "
            f"lr-route-list ovn_cluster_router"
        )
        output = _oc_exec(
            ovnkube.pod_name, ovn_ns, ovnkube.container_name, cmd,
            verbose=verbose,
        )
        # Check if any route covers the destination
        has_route = False
        matching_route = ""
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("IPv") or line.startswith("Route"):
                continue
            if dst_ip in line or "0.0.0.0/0" in line or "::/0" in line:
                has_route = True
                matching_route = line.strip()
                break
            # Check subnet match
            parts = line.split()
            if parts:
                try:
                    import ipaddress
                    network = ipaddress.ip_network(parts[0], strict=False)
                    if ipaddress.ip_address(dst_ip) in network:
                        has_route = True
                        matching_route = line.strip()
                        break
                except (ValueError, IndexError):
                    continue

        result.checks.append(DiagCheck(
            name="Route to destination",
            passed=has_route,
            detail=matching_route if has_route else f"No route to {dst_ip} in ovn_cluster_router",
            severity="info" if has_route else "error",
        ))
    except OvnQueryError as e:
        result.checks.append(DiagCheck(
            name="Route to destination",
            passed=False,
            detail=f"Cannot query routes: {e}",
            severity="warn",
        ))


def _check_network_policies(result, src_ns, dst_ns, verbose):
    """Check NetworkPolicies affecting source (egress) and destination (ingress)."""
    # Source namespace egress policies
    try:
        output = _run_oc(
            ["get", "networkpolicy", "-n", src_ns, "-o", "json"],
            verbose=verbose,
        )
        policies = json.loads(output)
        items = policies.get("items", [])

        egress_policies = []
        for pol in items:
            spec = pol.get("spec", {})
            policy_types = spec.get("policyTypes", [])
            if "Egress" in policy_types:
                name = pol["metadata"]["name"]
                egress_rules = spec.get("egress", [])
                egress_policies.append(f"{name} ({len(egress_rules)} rules)")

        if egress_policies:
            result.checks.append(DiagCheck(
                name="Egress NetworkPolicies on source",
                passed=True,
                detail=f"Found: {', '.join(egress_policies)}",
                severity="warn",
            ))
        else:
            result.checks.append(DiagCheck(
                name="Egress NetworkPolicies on source",
                passed=True,
                detail="No egress policies — all egress allowed",
                severity="info",
            ))
    except OcTrafficError:
        result.checks.append(DiagCheck(
            name="Egress NetworkPolicies on source",
            passed=True,
            detail="Cannot query policies",
            severity="warn",
        ))

    # Destination namespace ingress policies
    try:
        output = _run_oc(
            ["get", "networkpolicy", "-n", dst_ns, "-o", "json"],
            verbose=verbose,
        )
        policies = json.loads(output)
        items = policies.get("items", [])

        ingress_policies = []
        for pol in items:
            spec = pol.get("spec", {})
            policy_types = spec.get("policyTypes", [])
            if "Ingress" in policy_types:
                name = pol["metadata"]["name"]
                ingress_rules = spec.get("ingress", [])
                ingress_policies.append(f"{name} ({len(ingress_rules)} rules)")

        if ingress_policies:
            result.checks.append(DiagCheck(
                name="Ingress NetworkPolicies on destination",
                passed=True,
                detail=f"Found: {', '.join(ingress_policies)}",
                severity="warn",
            ))
        else:
            result.checks.append(DiagCheck(
                name="Ingress NetworkPolicies on destination",
                passed=True,
                detail="No ingress policies — all ingress allowed",
                severity="info",
            ))
    except OcTrafficError:
        pass

    # Check AdminNetworkPolicies (cluster-scoped)
    try:
        output = _run_oc(
            ["get", "adminnetworkpolicy", "-o", "json"],
            verbose=verbose,
        )
        anps = json.loads(output)
        items = anps.get("items", [])
        if items:
            anp_names = [item["metadata"]["name"] for item in items]
            result.checks.append(DiagCheck(
                name="AdminNetworkPolicies",
                passed=True,
                detail=f"Active ANPs: {', '.join(anp_names)}",
                severity="warn",
            ))
    except OcTrafficError:
        pass


def _check_acls(result, verbose):
    """Check OVN ACLs on source logical switch."""
    if not result.src_path:
        return

    ovnkube = result.src_path.ovnkube
    ovn_ns = result.src_path.cluster_info.ovn_namespace
    ls_name = result.src_path.logical_switch.name

    try:
        cmd = (
            f"ovn-nbctl --no-leader-only {ovnkube.nb_command} "
            f"acl-list {ls_name}"
        )
        output = _oc_exec(
            ovnkube.pod_name, ovn_ns, ovnkube.container_name, cmd,
            verbose=verbose,
        )
        acl_lines = [l.strip() for l in output.splitlines() if l.strip()]
        deny_acls = [l for l in acl_lines if "drop" in l.lower() or "reject" in l.lower()]

        result.src_path.acls = acl_lines

        if deny_acls:
            result.checks.append(DiagCheck(
                name="OVN ACLs on source switch",
                passed=True,
                detail=f"{len(acl_lines)} ACLs total, {len(deny_acls)} deny/reject rules",
                severity="warn",
            ))
        else:
            result.checks.append(DiagCheck(
                name="OVN ACLs on source switch",
                passed=True,
                detail=f"{len(acl_lines)} ACLs, no deny rules",
                severity="info",
            ))
    except OvnQueryError:
        pass

    # Destination switch ACLs
    if result.dst_path:
        dst_ls = result.dst_path.logical_switch.name
        try:
            dst_ovnkube = result.dst_path.ovnkube
            cmd = (
                f"ovn-nbctl --no-leader-only {dst_ovnkube.nb_command} "
                f"acl-list {dst_ls}"
            )
            output = _oc_exec(
                dst_ovnkube.pod_name, ovn_ns, dst_ovnkube.container_name, cmd,
                verbose=verbose,
            )
            acl_lines = [l.strip() for l in output.splitlines() if l.strip()]
            deny_acls = [l for l in acl_lines if "drop" in l.lower() or "reject" in l.lower()]

            result.dst_path.acls = acl_lines

            if deny_acls:
                result.checks.append(DiagCheck(
                    name="OVN ACLs on destination switch",
                    passed=True,
                    detail=f"{len(acl_lines)} ACLs total, {len(deny_acls)} deny/reject rules",
                    severity="warn",
                ))
            else:
                result.checks.append(DiagCheck(
                    name="OVN ACLs on destination switch",
                    passed=True,
                    detail=f"{len(acl_lines)} ACLs, no deny rules",
                    severity="info",
                ))
        except OvnQueryError:
            pass


def _check_port_binding(result, verbose):
    """Check port bindings are active on correct chassis."""
    src = result.src_path
    if not src:
        return

    # Source port binding
    bound = bool(src.port_binding.chassis)
    result.checks.append(DiagCheck(
        name="Source port binding",
        passed=bound,
        detail=f"Port {src.port_binding.logical_port} bound to chassis" if bound else "Port NOT bound to any chassis",
        severity="info" if bound else "error",
    ))

    # Destination port binding
    if result.dst_path:
        dst = result.dst_path
        bound = bool(dst.port_binding.chassis)
        result.checks.append(DiagCheck(
            name="Destination port binding",
            passed=bound,
            detail=f"Port {dst.port_binding.logical_port} bound to chassis" if bound else "Port NOT bound to any chassis",
            severity="info" if bound else "error",
        ))

        # Same node or different?
        if src.pod.node_name == dst.pod.node_name:
            result.checks.append(DiagCheck(
                name="Pod locality",
                passed=True,
                detail="Both pods on same node — no tunnel needed",
                severity="info",
            ))
        else:
            result.checks.append(DiagCheck(
                name="Pod locality",
                passed=True,
                detail=f"Different nodes: {src.pod.node_name} -> {dst.pod.node_name} (Geneve tunnel)",
                severity="info",
            ))


def _check_ovs_flows(result, dst_ip, verbose):
    """Check OVS flows exist for this traffic path."""
    src = result.src_path
    if not src or not dst_ip:
        return

    ovnkube = src.ovnkube
    ovn_ns = src.cluster_info.ovn_namespace

    try:
        cmd = f"ovs-ofctl dump-flows br-int"
        output = _oc_exec(
            ovnkube.pod_name, ovn_ns, ovnkube.container_name, cmd,
            timeout=60, verbose=verbose,
        )

        # Check for flows matching destination IP
        matching = [l for l in output.splitlines() if dst_ip in l]
        drop_flows = [l for l in matching if "drop" in l.lower()]

        if drop_flows:
            result.checks.append(DiagCheck(
                name="OVS flows to destination",
                passed=False,
                detail=f"Found {len(drop_flows)} DROP flows matching {dst_ip}",
                severity="error",
            ))
        elif matching:
            total_pkts = 0
            for line in matching:
                m = re.search(r"n_packets=(\d+)", line)
                if m:
                    total_pkts += int(m.group(1))
            result.checks.append(DiagCheck(
                name="OVS flows to destination",
                passed=True,
                detail=f"{len(matching)} flows matching {dst_ip}, {total_pkts} packets",
                severity="info",
            ))
        else:
            result.checks.append(DiagCheck(
                name="OVS flows to destination",
                passed=True,
                detail=f"No direct flows matching {dst_ip} (may use generic routing flows)",
                severity="info",
            ))
    except OvnQueryError:
        pass


def _test_connectivity(src_path, dst_ip, port=None, protocol="tcp",
                       verbose=False):
    """Actually test connectivity from source pod to destination."""
    results = []
    pod = src_path.pod

    # ICMP ping
    try:
        cmd = ["oc", "exec", "-n", pod.namespace, pod.name, "--",
               "ping", "-c", "3", "-W", "2", dst_ip]
        if verbose:
            sys.stderr.write(f"  >> {' '.join(cmd)}\n")
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if proc.returncode == 0:
            # Parse latency
            m = re.search(r"rtt min/avg/max.*= [\d.]+/([\d.]+)/", proc.stdout)
            latency = m.group(1) if m else ""
            results.append(ConnectivityResult(
                test_type="icmp", source=pod.ip, destination=dst_ip,
                success=True, latency_ms=latency,
            ))
        else:
            results.append(ConnectivityResult(
                test_type="icmp", source=pod.ip, destination=dst_ip,
                success=False, error=proc.stderr.strip()[:100],
            ))
    except (subprocess.TimeoutExpired, Exception) as e:
        results.append(ConnectivityResult(
            test_type="icmp", source=pod.ip, destination=dst_ip,
            success=False, error=str(e)[:100],
        ))

    # TCP connect if port specified
    if port:
        try:
            # Use bash TCP check — works in most containers
            tcp_cmd = ["oc", "exec", "-n", pod.namespace, pod.name, "--",
                       "bash", "-c",
                       f"timeout 3 bash -c 'echo > /dev/tcp/{dst_ip}/{port}' 2>&1"]
            if verbose:
                sys.stderr.write(f"  >> {' '.join(tcp_cmd)}\n")
            proc = subprocess.run(tcp_cmd, capture_output=True, text=True, timeout=10)
            results.append(ConnectivityResult(
                test_type="tcp", source=pod.ip, destination=dst_ip,
                port=str(port), success=(proc.returncode == 0),
                error=proc.stderr.strip()[:100] if proc.returncode != 0 else "",
            ))
        except (subprocess.TimeoutExpired, Exception) as e:
            results.append(ConnectivityResult(
                test_type="tcp", source=pod.ip, destination=dst_ip,
                port=str(port), success=False, error=str(e)[:100],
            ))

    # DNS resolution test
    try:
        dns_cmd = ["oc", "exec", "-n", pod.namespace, pod.name, "--",
                   "nslookup", "kubernetes.default.svc.cluster.local"]
        if verbose:
            sys.stderr.write(f"  >> {' '.join(dns_cmd)}\n")
        proc = subprocess.run(dns_cmd, capture_output=True, text=True, timeout=10)
        results.append(ConnectivityResult(
            test_type="dns", source=pod.ip,
            destination="kubernetes.default.svc.cluster.local",
            success=(proc.returncode == 0),
            error=proc.stderr.strip()[:100] if proc.returncode != 0 else "",
        ))
    except (subprocess.TimeoutExpired, Exception) as e:
        results.append(ConnectivityResult(
            test_type="dns", source=pod.ip,
            destination="kubernetes.default.svc.cluster.local",
            success=False, error=str(e)[:100],
        ))

    return results
