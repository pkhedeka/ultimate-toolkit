class OcTrafficError(Exception):
    pass


class ClusterError(OcTrafficError):
    pass


class NotOvnKubernetesError(ClusterError):
    def __init__(self, cni_type="unknown"):
        super().__init__(
            f"Cluster CNI is '{cni_type}', not OVNKubernetes. "
            "oc-traffic only works with OVN-Kubernetes."
        )


class OcNotFoundError(ClusterError):
    def __init__(self):
        super().__init__(
            "'oc' binary not found on PATH. "
            "Install the OpenShift CLI: https://mirror.openshift.com/pub/openshift-v4/clients/ocp/latest/"
        )


class InsufficientPermissions(ClusterError):
    def __init__(self, detail=""):
        msg = "Cannot exec into openshift-ovn-kubernetes pods. Requires cluster-admin or equivalent RBAC."
        if detail:
            msg += f" Detail: {detail}"
        super().__init__(msg)


class PodNotFoundError(OcTrafficError):
    def __init__(self, pod_name, namespace):
        super().__init__(f"Pod '{pod_name}' not found in namespace '{namespace}'.")


class OvnQueryError(OcTrafficError):
    pass


class OvsQueryError(OcTrafficError):
    pass


class ServiceNotFoundError(OcTrafficError):
    def __init__(self, svc_name, namespace):
        super().__init__(f"Service '{svc_name}' not found in namespace '{namespace}'.")
