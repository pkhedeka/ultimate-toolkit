#!/bin/bash
# YAML config parser for install-config.yaml and agent-config.yaml

parse_install_config() {
    local config_path="$1"

    if [[ ! -f "$config_path" ]]; then
        return 1
    fi

    local parsed
    parsed=$(python3 -c "
import yaml, json, sys
try:
    with open('${config_path}') as f:
        data = yaml.safe_load(f)
except Exception as e:
    print(json.dumps({'error': str(e)}))
    sys.exit(1)

if not isinstance(data, dict):
    print(json.dumps({'error': 'install-config is not a valid YAML mapping'}))
    sys.exit(1)

result = {}
result['cluster_name'] = data.get('metadata', {}).get('name', '')
result['base_domain'] = data.get('baseDomain', '')
result['network_type'] = data.get('networking', {}).get('networkType', 'OVNKubernetes')

cp = data.get('controlPlane', {})
result['control_plane_replicas'] = cp.get('replicas', 3)
compute = data.get('compute', [{}])
result['worker_replicas'] = compute[0].get('replicas', 2) if compute else 2

platform = data.get('platform', {})
platform_keys = [k for k in platform.keys() if k != 'none']
result['platform'] = platform_keys[0] if platform_keys else 'none'
p = result['platform']

if p == 'vsphere':
    vs = platform.get('vsphere', {})
    vcenters = vs.get('vcenters', [])
    if vcenters:
        vc = vcenters[0]
        result['vcenter'] = vc.get('server', '')
        result['vcenter_user'] = vc.get('user', '')
        result['vcenter_password'] = vc.get('password', '')
        dcs = vc.get('datacenters', [])
        result['datacenter'] = dcs[0] if dcs else ''
    else:
        result['vcenter'] = vs.get('vCenter', vs.get('vcenter', ''))
        result['vcenter_user'] = vs.get('username', '')
        result['vcenter_password'] = vs.get('password', '')
        result['datacenter'] = vs.get('datacenter', '')

    fds = vs.get('failureDomains', [])
    if fds:
        fd = fds[0]
        topo = fd.get('topology', {})
        result['datacenter'] = result['datacenter'] or topo.get('datacenter', '')
        result['datastore'] = topo.get('datastore', '').split('/')[-1] if topo.get('datastore') else ''
        result['cluster'] = topo.get('computeCluster', '').split('/')[-1] if topo.get('computeCluster') else ''
        result['network'] = topo.get('networks', [''])[0] if topo.get('networks') else ''
        result['folder'] = topo.get('folder', '')
        result['resourcePool'] = topo.get('resourcePool', '')
    else:
        result['datastore'] = vs.get('defaultDatastore', '')
        result['cluster'] = vs.get('cluster', '')
        result['network'] = vs.get('network', '')
        result['folder'] = vs.get('folder', '')
        result['resourcePool'] = vs.get('resourcePool', '')

    api_vips = vs.get('apiVIPs', vs.get('apiVIP', []))
    if isinstance(api_vips, str): api_vips = [api_vips]
    result['api_vips'] = api_vips
    ingress_vips = vs.get('ingressVIPs', vs.get('ingressVIP', []))
    if isinstance(ingress_vips, str): ingress_vips = [ingress_vips]
    result['ingress_vips'] = ingress_vips

elif p == 'baremetal':
    bm = platform.get('baremetal', {})
    api_vips = bm.get('apiVIPs', [bm.get('apiVIP', '')])
    if isinstance(api_vips, str): api_vips = [api_vips]
    result['api_vips'] = [v for v in api_vips if v]
    ingress_vips = bm.get('ingressVIPs', [bm.get('ingressVIP', '')])
    if isinstance(ingress_vips, str): ingress_vips = [ingress_vips]
    result['ingress_vips'] = [v for v in ingress_vips if v]
    result['provisioning_network_cidr'] = bm.get('provisioningNetworkCIDR', '')
    result['provisioning_bridge'] = bm.get('provisioningBridge', '')
    result['external_bridge'] = bm.get('externalBridge', '')
    hosts = []
    for h in bm.get('hosts', []):
        hosts.append({
            'name': h.get('name', ''),
            'role': h.get('role', ''),
            'bmc_address': h.get('bmc', {}).get('address', ''),
            'bmc_user': h.get('bmc', {}).get('username', ''),
            'bmc_password': h.get('bmc', {}).get('password', ''),
            'boot_mac': h.get('bootMACAddress', ''),
        })
    result['hosts'] = hosts
else:
    result['api_vips'] = []
    result['ingress_vips'] = []

result['has_pull_secret'] = bool(data.get('pullSecret', ''))
result['ssh_key_present'] = bool(data.get('sshKey', ''))
proxy = data.get('proxy', {})
if proxy:
    result['http_proxy'] = proxy.get('httpProxy', '')
    result['https_proxy'] = proxy.get('httpsProxy', '')
    result['no_proxy'] = proxy.get('noProxy', '')
result['has_additional_trust_bundle'] = bool(data.get('additionalTrustBundle', ''))

print(json.dumps(result))
" 2>/dev/null)

    if [[ $? -ne 0 ]] || [[ -z "$parsed" ]]; then
        return 1
    fi

    local error
    error=$(echo "$parsed" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('error',''))" 2>/dev/null)
    if [[ -n "$error" ]]; then
        echo "ERROR: $error" >&2
        return 1
    fi

    echo "$parsed"
    return 0
}

parse_agent_config() {
    local config_path="$1"

    if [[ ! -f "$config_path" ]]; then
        return 1
    fi

    python3 -c "
import yaml, json, sys
try:
    with open('${config_path}') as f:
        data = yaml.safe_load(f)
except Exception as e:
    print(json.dumps({'error': str(e)}))
    sys.exit(1)

result = {}
result['rendezvous_ip'] = data.get('rendezvousIP', '')

hosts = []
for h in data.get('hosts', []):
    host = {
        'hostname': h.get('hostname', ''),
        'role': h.get('role', ''),
        'interfaces': [],
    }
    for iface in h.get('interfaces', []):
        host['interfaces'].append({
            'name': iface.get('name', ''),
            'mac': iface.get('macAddress', ''),
        })
    nm = h.get('networkConfig', {})
    host['has_nmstate'] = bool(nm)
    if nm:
        ifaces = nm.get('interfaces', [])
        for ni in ifaces:
            ipv4 = ni.get('ipv4', {})
            addrs = ipv4.get('address', [])
            if addrs:
                host['static_ip'] = addrs[0].get('ip', '')
                break
    hosts.append(host)

result['hosts'] = hosts
result['host_count'] = len(hosts)

print(json.dumps(result))
" 2>/dev/null
}

get_config_value() {
    local json_data="$1"
    local key="$2"
    echo "$json_data" | python3 -c "import json,sys; d=json.load(sys.stdin); v=d.get('${key}',''); print(v if not isinstance(v, list) else ' '.join(str(x) for x in v))" 2>/dev/null
}

get_config_list() {
    local json_data="$1"
    local key="$2"
    echo "$json_data" | python3 -c "
import json,sys
d = json.load(sys.stdin)
v = d.get('${key}', [])
if isinstance(v, list):
    for item in v:
        print(item)
" 2>/dev/null
}

get_config_hosts() {
    local json_data="$1"
    echo "$json_data" | python3 -c "
import json, sys
d = json.load(sys.stdin)
for h in d.get('hosts', []):
    name = h.get('name', h.get('hostname', ''))
    role = h.get('role', '')
    bmc = h.get('bmc_address', '')
    ip = h.get('static_ip', '')
    print(f'{name}|{role}|{bmc}|{ip}')
" 2>/dev/null
}

validate_yaml_syntax() {
    local config_path="$1"
    python3 -c "
import yaml, sys
try:
    with open('${config_path}') as f:
        yaml.safe_load(f)
    print('valid')
except yaml.YAMLError as e:
    print(f'invalid: {e}')
" 2>/dev/null
}
