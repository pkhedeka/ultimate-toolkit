import sys
import subprocess

from .errors import OvnQueryError, OcTrafficError


def run_ovn_trace(path, destination=None, verbose=False):
    """Run ovn-trace for the given pod path and return output."""
    pod = path.pod
    ovnkube = path.ovnkube
    ovn_ns = path.cluster_info.ovn_namespace

    if pod.host_network:
        inport = f"k8s-{pod.node_name}"
    else:
        inport = f"{pod.namespace}_{pod.name}"

    src_mac = pod.mac
    dst_mac = path.cluster_router.rtos_mac

    if not src_mac or not dst_mac:
        return "Error: Cannot run ovn-trace without MAC addresses. Pod or router MAC not found."

    ip_ver = "ip4"
    if ":" in pod.ip:
        ip_ver = "ip6"

    # Determine destination
    if destination:
        dst_ip = _resolve_destination(destination, pod.namespace, verbose)
        if not dst_ip:
            return f"Error: Cannot resolve destination '{destination}'"
    else:
        # Default: trace to gateway (first gateway IP)
        if pod.gateways:
            dst_ip = pod.gateways[0]
        else:
            return "Error: No destination specified and no gateway found."

    # Build ovn-trace command
    # Check if destination is a service ClusterIP (needs --ct=new)
    is_svc = _is_service_ip(dst_ip, pod.namespace, verbose)

    trace_cmd = (
        f"ovn-trace --no-leader-only {ovnkube.sb_command} {pod.node_name} "
        f"'inport==\"{inport}\" && eth.src=={src_mac} && eth.dst=={dst_mac} "
        f"&& {ip_ver}.src=={pod.ip} && {ip_ver}.dst=={dst_ip} "
        f"&& ip.ttl==64'"
    )

    if is_svc:
        trace_cmd = trace_cmd.replace("'inport", "--ct=new 'inport")

    cmd = ["oc", "exec", "-n", ovn_ns, ovnkube.pod_name,
           "-c", ovnkube.container_name, "--", "bash", "-c", trace_cmd]

    if verbose:
        sys.stderr.write(f"  >> {' '.join(cmd)}\n")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            return f"ovn-trace failed: {result.stderr.strip()}"
        return result.stdout
    except subprocess.TimeoutExpired:
        return "Error: ovn-trace timed out after 60 seconds"
    except Exception as e:
        return f"Error running ovn-trace: {e}"


def _resolve_destination(destination, namespace, verbose=False):
    """Resolve destination to an IP. Could be pod name or IP."""
    import re
    # Check if already an IP
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", destination):
        return destination
    if ":" in destination and all(c in "0123456789abcdefABCDEF:" for c in destination):
        return destination

    # Try to resolve as pod name
    try:
        import json
        cmd = ["oc", "get", "pod", destination, "-n", namespace, "-o",
               "jsonpath={.status.podIP}"]
        if verbose:
            sys.stderr.write(f"  >> {' '.join(cmd)}\n")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass

    # Try with namespace/pod format
    if "/" in destination:
        ns, pod_name = destination.split("/", 1)
        try:
            cmd = ["oc", "get", "pod", pod_name, "-n", ns, "-o",
                   "jsonpath={.status.podIP}"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except Exception:
            pass

    return None


def _is_service_ip(ip, namespace, verbose=False):
    """Check if IP is a service ClusterIP."""
    try:
        cmd = ["oc", "get", "svc", "--all-namespaces", "-o",
               f"jsonpath={{.items[?(@.spec.clusterIP==\"{ip}\")].metadata.name}}"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.returncode == 0 and result.stdout.strip() != ""
    except Exception:
        return False
