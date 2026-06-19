from dataclasses import dataclass, field


@dataclass
class ClusterInfo:
    ovn_namespace: str = "openshift-ovn-kubernetes"
    is_interconnect: bool = False
    zone_name: str = ""
    gateway_mode: str = ""  # "shared" or "local"


@dataclass
class PodInfo:
    name: str = ""
    namespace: str = ""
    ip: str = ""
    mac: str = ""
    node_name: str = ""
    host_network: bool = False
    gateways: list = field(default_factory=list)


@dataclass
class OvnKubeInfo:
    pod_name: str = ""
    container_name: str = ""
    nb_command: str = ""
    sb_command: str = ""
    nb_uri: str = ""
    sb_uri: str = ""
    ssl_cert_keys: str = ""


@dataclass
class OvsPort:
    name: str = ""
    ofport: str = ""
    iface_id: str = ""


@dataclass
class BridgeInfo:
    name: str = ""
    ports: list = field(default_factory=list)


@dataclass
class LogicalSwitchPort:
    name: str = ""
    type: str = ""
    addresses: str = ""
    parent_switch: str = ""
    tunnel_key: str = ""


@dataclass
class LogicalSwitch:
    name: str = ""
    subnet: str = ""
    tunnel_key: str = ""


@dataclass
class LogicalRouterInfo:
    name: str = ""
    rtos_port: str = ""
    rtos_mac: str = ""
    rtos_ip: str = ""


@dataclass
class GatewayRouterInfo:
    name: str = ""
    nat_rules: list = field(default_factory=list)
    external_ip: str = ""
    join_switch: str = ""
    external_switch: str = ""
    join_ip: str = ""
    external_port: str = ""


@dataclass
class PhysicalNIC:
    name: str = ""
    mac: str = ""
    mtu: str = ""
    state: str = ""


@dataclass
class Chassis:
    name: str = ""
    hostname: str = ""
    encap_type: str = ""
    encap_ip: str = ""


@dataclass
class PortBinding:
    logical_port: str = ""
    type: str = ""
    chassis: str = ""
    tunnel_key: str = ""


@dataclass
class FlowEntry:
    table: str = ""
    priority: str = ""
    match: str = ""
    actions: str = ""
    n_packets: str = "0"
    n_bytes: str = "0"


@dataclass
class EndpointInfo:
    pod_name: str = ""
    pod_namespace: str = ""
    pod_ip: str = ""
    node_name: str = ""
    ready: bool = True


@dataclass
class ServiceFanOut:
    name: str = ""
    namespace: str = ""
    cluster_ip: str = ""
    ports: list = field(default_factory=list)
    endpoints: list = field(default_factory=list)
    selector: dict = field(default_factory=dict)
    lb_info: list = field(default_factory=list)


@dataclass
class OvnLoadBalancer:
    uuid: str = ""
    name: str = ""
    vips: dict = field(default_factory=dict)
    protocol: str = ""


@dataclass
class ConnectivityResult:
    test_type: str = ""  # "icmp", "tcp", "dns"
    source: str = ""
    destination: str = ""
    port: str = ""
    success: bool = False
    latency_ms: str = ""
    error: str = ""


@dataclass
class DiagCheck:
    name: str = ""
    passed: bool = False
    detail: str = ""
    severity: str = "info"  # "info", "warn", "error"


@dataclass
class DiagResult:
    checks: list = field(default_factory=list)
    connectivity: list = field(default_factory=list)
    src_path: object = None  # PodPath
    dst_path: object = None  # PodPath


@dataclass
class PodPath:
    pod: PodInfo = field(default_factory=PodInfo)
    ovnkube: OvnKubeInfo = field(default_factory=OvnKubeInfo)
    cluster_info: ClusterInfo = field(default_factory=ClusterInfo)
    ovs_port: OvsPort = field(default_factory=OvsPort)
    br_int: BridgeInfo = field(default_factory=BridgeInfo)
    logical_switch_port: LogicalSwitchPort = field(default_factory=LogicalSwitchPort)
    logical_switch: LogicalSwitch = field(default_factory=LogicalSwitch)
    cluster_router: LogicalRouterInfo = field(default_factory=LogicalRouterInfo)
    gateway_router: GatewayRouterInfo = field(default_factory=GatewayRouterInfo)
    external_bridge: BridgeInfo = field(default_factory=BridgeInfo)
    physical_nic: PhysicalNIC = field(default_factory=PhysicalNIC)
    chassis: Chassis = field(default_factory=Chassis)
    port_binding: PortBinding = field(default_factory=PortBinding)
    gateway_mode: str = ""
    # optional
    flows: list = field(default_factory=list)
    trace_output: str = ""
    services: list = field(default_factory=list)
    acls: list = field(default_factory=list)
    network_policies: list = field(default_factory=list)
