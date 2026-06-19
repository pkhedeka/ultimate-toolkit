import json
import sys

from .errors import ServiceNotFoundError, OcTrafficError, OvnQueryError
from .models import ServiceFanOut, EndpointInfo, OvnLoadBalancer


def _run_oc(args, timeout=30, verbose=False):
    import subprocess
    cmd = ["oc"] + args
    if verbose:
        sys.stderr.write(f"  >> {' '.join(cmd)}\n")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise OcTrafficError(f"oc failed: {' '.join(cmd)}\n{result.stderr.strip()}")
    return result.stdout.strip()


def _oc_exec(pod_name, namespace, container, command, timeout=30, verbose=False):
    import subprocess
    cmd = ["oc", "exec", "-n", namespace, pod_name, "-c", container, "--",
           "bash", "-c", command]
    if verbose:
        sys.stderr.write(f"  >> {' '.join(cmd)}\n")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise OvnQueryError(f"exec failed: {command}\n{result.stderr.strip()}")
    return result.stdout


def get_service_fanout(svc_name, namespace, cluster_info, verbose=False):
    # Get service
    try:
        output = _run_oc(
            ["get", "svc", svc_name, "-n", namespace, "-o", "json"],
            verbose=verbose,
        )
    except OcTrafficError:
        raise ServiceNotFoundError(svc_name, namespace)

    svc_json = json.loads(output)
    spec = svc_json.get("spec", {})

    cluster_ip = spec.get("clusterIP", "")
    selector = spec.get("selector", {})
    svc_ports = []
    for p in spec.get("ports", []):
        svc_ports.append({
            "port": p.get("port", ""),
            "targetPort": p.get("targetPort", ""),
            "protocol": p.get("protocol", "TCP"),
            "name": p.get("name", ""),
        })

    fanout = ServiceFanOut(
        name=svc_name,
        namespace=namespace,
        cluster_ip=cluster_ip,
        ports=svc_ports,
        selector=selector,
    )

    # Get endpoint slices
    try:
        ep_output = _run_oc(
            ["get", "endpointslice", "-n", namespace,
             "-l", f"kubernetes.io/service-name={svc_name}",
             "-o", "json"],
            verbose=verbose,
        )
        ep_json = json.loads(ep_output)
        for item in ep_json.get("items", []):
            for endpoint in item.get("endpoints", []):
                addresses = endpoint.get("addresses", [])
                conditions = endpoint.get("conditions", {})
                ready = conditions.get("ready", True)
                target_ref = endpoint.get("targetRef", {})

                for addr in addresses:
                    fanout.endpoints.append(EndpointInfo(
                        pod_name=target_ref.get("name", ""),
                        pod_namespace=target_ref.get("namespace", namespace),
                        pod_ip=addr,
                        node_name=endpoint.get("nodeName", ""),
                        ready=ready,
                    ))
    except OcTrafficError:
        pass

    # Get OVN load balancer info
    fanout.lb_info = _get_ovn_lb_for_service(
        cluster_ip, svc_ports, cluster_info, verbose
    )

    return fanout


def _get_ovn_lb_for_service(cluster_ip, svc_ports, cluster_info, verbose):
    """Find OVN load balancers matching this service's ClusterIP."""
    if not cluster_ip or cluster_ip == "None":
        return []

    ovn_ns = cluster_info.ovn_namespace

    # Find an ovnkube-node pod to query
    try:
        pod_name = _run_oc(
            ["get", "pods", "-n", ovn_ns, "-l", "app=ovnkube-node",
             "-o", "jsonpath={.items[0].metadata.name}"],
            verbose=verbose,
        )
    except OcTrafficError:
        return []

    # Detect container and DB command
    from .cluster import detect_ic_and_db
    try:
        _, _, container, nb_cmd, _, _, _, _ = detect_ic_and_db(
            pod_name, ovn_ns, verbose
        )
    except Exception:
        return []

    # List all load balancers
    cmd = f"ovn-nbctl --no-leader-only {nb_cmd} lb-list"
    try:
        output = _oc_exec(pod_name, ovn_ns, container, cmd,
                          timeout=60, verbose=verbose)
    except OvnQueryError:
        return []

    lbs = []
    for line in output.splitlines():
        if cluster_ip in line:
            parts = line.split()
            if len(parts) >= 3:
                lb = OvnLoadBalancer(uuid=parts[0])
                # Parse VIP -> backends
                for i, part in enumerate(parts):
                    if cluster_ip in part:
                        vip = part
                        backends = parts[i + 1] if i + 1 < len(parts) else ""
                        lb.vips[vip] = backends
                # Protocol detection
                if "tcp" in line.lower():
                    lb.protocol = "tcp"
                elif "udp" in line.lower():
                    lb.protocol = "udp"
                elif "sctp" in line.lower():
                    lb.protocol = "sctp"
                lbs.append(lb)

    return lbs
