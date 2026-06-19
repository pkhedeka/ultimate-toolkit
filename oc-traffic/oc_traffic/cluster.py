import json
import re
import shutil
import subprocess

from .errors import ClusterError, NotOvnKubernetesError, OcNotFoundError, InsufficientPermissions
from .models import ClusterInfo


def _run_oc(args, timeout=30, verbose=False):
    cmd = ["oc"] + args
    if verbose:
        import sys
        sys.stderr.write(f"  >> {' '.join(cmd)}\n")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise ClusterError(f"oc command failed: {' '.join(cmd)}\n{result.stderr.strip()}")
    return result.stdout.strip()


def detect_cluster(ovn_namespace_override=None, verbose=False):
    if not shutil.which("oc"):
        raise OcNotFoundError()

    cni_type = _run_oc(
        ["get", "network.operator.openshift.io", "cluster",
         "-o", "jsonpath={.spec.defaultNetwork.type}"],
        verbose=verbose,
    )
    if cni_type != "OVNKubernetes":
        raise NotOvnKubernetesError(cni_type)

    ovn_namespace = _find_ovn_namespace(ovn_namespace_override, verbose)

    info = ClusterInfo(ovn_namespace=ovn_namespace)
    return info


def _find_ovn_namespace(override, verbose):
    if override:
        return override
    try:
        output = _run_oc(
            ["get", "pods", "--all-namespaces",
             "-l", "app=ovnkube-node",
             "-o", "jsonpath={.items[0].metadata.namespace}"],
            verbose=verbose,
        )
        if output:
            return output
    except ClusterError:
        pass
    return "openshift-ovn-kubernetes"


def detect_ic_and_db(pod_name, ovn_namespace, verbose=False):
    """Detect IC mode and extract DB URIs by execing into ovnkube-node pod.
    Returns (is_ic, zone_name, ovnkube_container, nb_command, sb_command, nb_uri, sb_uri, ssl_cert_keys).
    """
    ovnkube_container = _find_ovnkube_container(pod_name, ovn_namespace, verbose)

    ps_cmd = "ps -eo args | grep '/usr/bin/[o]vnkube'"
    ps_output = _oc_exec(pod_name, ovn_namespace, ovnkube_container, ps_cmd, verbose=verbose)

    is_ic = "--enable-interconnect" in ps_output
    zone_name = ""
    if is_ic:
        m = re.search(r"--zone[= ](\S+)", ps_output)
        if m:
            zone_name = m.group(1)

    # Extract NB address
    nb_uri = "unix:/var/run/ovn/ovnnb_db.sock"
    m = re.search(r"--nb-address[= ](\S+)", ps_output)
    if m:
        nb_uri = m.group(1).replace("://", ":", 1)

    # Extract SB address
    sb_uri = "unix:/var/run/ovn/ovnsb_db.sock"
    m = re.search(r"--sb-address[= ](\S+)", ps_output)
    if m:
        sb_uri = m.group(1).replace("://", ":", 1)

    # Determine protocol and SSL cert keys
    protocol_m = re.search(r"(ssl|tcp|unix)", nb_uri)
    protocol = protocol_m.group(1) if protocol_m else "unix"

    if protocol == "ssl":
        ssl_cert_keys = "-p /ovn-cert/tls.key -c /ovn-cert/tls.crt -C /ovn-ca/ca-bundle.crt "
    else:
        ssl_cert_keys = ""

    nb_command = f"{ssl_cert_keys}--db {nb_uri}"
    sb_command = f"{ssl_cert_keys}--db {sb_uri}"

    return is_ic, zone_name, ovnkube_container, nb_command, sb_command, nb_uri, sb_uri, ssl_cert_keys


def _find_ovnkube_container(pod_name, ovn_namespace, verbose):
    """Find the ovnkube-node or ovnkube-controller container in the pod."""
    output = _run_oc(
        ["get", "pod", pod_name, "-n", ovn_namespace,
         "-o", "jsonpath={.spec.containers[*].name}"],
        verbose=verbose,
    )
    containers = output.split()
    for candidate in ["ovnkube-node", "ovnkube-controller"]:
        if candidate in containers:
            return candidate
    raise ClusterError(
        f"No ovnkube-node or ovnkube-controller container in pod {pod_name}. "
        f"Found: {containers}"
    )


def detect_gateway_mode(node_name, verbose=False):
    """Detect gateway mode from node annotation k8s.ovn.org/l3-gateway-config."""
    try:
        output = _run_oc(
            ["get", "node", node_name,
             "-o", r"jsonpath={.metadata.annotations.k8s\.ovn\.org/l3-gateway-config}"],
            verbose=verbose,
        )
        if not output:
            return "shared"
        parsed = json.loads(output)
        mode = parsed.get("default", {}).get("mode", "shared")
        return mode
    except (json.JSONDecodeError, ClusterError):
        return "shared"


def _oc_exec(pod_name, namespace, container, command, timeout=30, verbose=False):
    cmd = ["oc", "exec", "-n", namespace, pod_name, "-c", container, "--",
           "bash", "-c", command]
    if verbose:
        import sys
        sys.stderr.write(f"  >> {' '.join(cmd)}\n")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise InsufficientPermissions(result.stderr.strip())
    return result.stdout
