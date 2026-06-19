import re
import sys

# ANSI colors
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
CYAN = "\033[36m"
YELLOW = "\033[33m"
RED = "\033[31m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"

DIAGRAM_WIDTH = 80
LANE_WIDTH = 13
BOX_WIDTH = 55
PHYSNET = "physnet"


def _c(text, color, use_color):
    if use_color:
        return f"{color}{text}{RESET}"
    return text


def _visible_len(s):
    return len(re.sub(r'\033\[[^m]*m', '', s))


def _rpad(s, width):
    pad = width - _visible_len(s)
    return s + ' ' * max(0, pad)


def _trunc(s, maxlen):
    if len(s) <= maxlen:
        return s
    return s[:maxlen-2] + '..'


def _lane(label, color, use_color):
    return _c(label, BOLD + color, use_color) + " " * (LANE_WIDTH - len(label))


# ── Swim-lane node diagram ──────────────────────────────────────────

def _render_node_swimlane(path, use_color, label=None):
    W = DIAGRAM_WIDTH
    CW = W - 6

    lines = []
    node = path.pod.node_name

    def bl(content=""):
        return ("  " + _c("│", DIM, use_color) + " "
                + _rpad(content, CW) + " "
                + _c("│", DIM, use_color))

    def sep(label_text=""):
        if label_text:
            pre_len = 12
            arrow = f" ↓ {label_text} "
            rem = CW - pre_len - len(arrow)
            return bl(
                _c("─" * pre_len, DIM, use_color)
                + _c(arrow, YELLOW, use_color)
                + _c("─" * max(0, rem), DIM, use_color))
        return bl(_c("─" * CW, DIM, use_color))

    # top border
    tag_text = f" [{label}]" if label else ""
    fill = W - 7 - len(node) - len(tag_text)
    top = ("  " + _c("┌─ ", DIM, use_color)
           + _c(node, BOLD, use_color)
           + (_c(f" [{label}]", BOLD + YELLOW, use_color) if label else "")
           + " " + _c("─" * max(1, fill) + "┐", DIM, use_color))
    lines.append(top)
    lines.append(bl())

    # ── Pod lane ──
    lines.append(bl(
        _lane("Pod", CYAN, use_color)
        + _c(path.pod.name, BOLD + CYAN, use_color)))

    iface = "ovn-k8s-mp0" if path.pod.host_network else "eth0"
    pod_det = f"{path.pod.ip} · {iface}"
    if path.ovs_port.ofport:
        pod_det += f" · ofport:{path.ovs_port.ofport}"
    lines.append(bl(
        " " * LANE_WIDTH
        + _c(pod_det, DIM, use_color)))

    lines.append(bl())
    lines.append(sep("veth"))
    lines.append(bl())

    # ── OVN lane (tree) ──
    lines.append(bl(
        _lane("OVN", GREEN, use_color)
        + _c(f"LS: {path.logical_switch.name}", CYAN, use_color)))

    # cluster router
    cr_info = "ovn_cluster_router"
    if path.cluster_router.rtos_port:
        cr_info += f" ({_trunc(path.cluster_router.rtos_port, 28)})"
    lines.append(bl(
        " " * LANE_WIDTH
        + _c("  └▶ ", DIM, use_color)
        + _c(cr_info, GREEN, use_color)))

    # gateway router
    lines.append(bl(
        " " * LANE_WIDTH
        + _c("    └▶ ", DIM, use_color)
        + _c(path.gateway_router.name, YELLOW, use_color)))

    # SNAT
    if path.gateway_router.external_ip:
        lines.append(bl(
            " " * LANE_WIDTH
            + _c(f"       SNAT: {path.pod.ip} → {path.gateway_router.external_ip}",
                 DIM, use_color)))

    # IC: transit switch
    if path.cluster_info.is_interconnect:
        zone = path.cluster_info.zone_name or path.pod.node_name
        lines.append(bl(
            " " * LANE_WIDTH
            + _c("       ▸ ", DIM, use_color)
            + _c("transit_switch", MAGENTA, use_color)
            + _c(f" (zone: {_trunc(zone, 22)}, geneve)", DIM, use_color)))

    lines.append(bl())
    ext_sw = _trunc(path.gateway_router.external_switch or "ext_switch", 20)
    lines.append(sep(ext_sw))
    lines.append(bl())

    # ── Physical lane ──
    nic = path.physical_nic
    lines.append(bl(
        _lane("Physical", BLUE, use_color)
        + _c("br-int", BLUE, use_color)
        + _c(" ─── ", DIM, use_color)
        + _c("patch", DIM, use_color)
        + _c(" ─── ", DIM, use_color)
        + _c(path.external_bridge.name, BLUE, use_color)
        + _c(" ──▶ ", DIM, use_color)
        + _c(nic.name, RED + BOLD, use_color)))

    # physical details
    parts = []
    if nic.state:
        parts.append(nic.state)
    if nic.mtu:
        parts.append(f"MTU:{nic.mtu}")
    if path.ovnkube.pod_name:
        parts.append(f"via {path.ovnkube.pod_name}")
    if parts:
        lines.append(bl(
            " " * LANE_WIDTH
            + _c(" · ".join(parts), DIM, use_color)))

    lines.append(bl())

    # bottom border
    lines.append("  " + _c("└" + "─" * (W - 4) + "┘", DIM, use_color))

    return lines


# ── Header ───────────────────────────────────────────────────────────

def render_header(pod, cluster_info, gateway_mode, use_color=True):
    out = []
    out.append("")
    out.append(_c("  oc-traffic", BOLD + CYAN, use_color)
               + _c(" — network path visualizer", DIM, use_color))
    out.append("")
    out.append(f"  Pod: {_c(pod.name, BOLD, use_color)}"
               f" ({_c(pod.ip, GREEN, use_color)})")
    out.append(f"  Namespace: {_c(pod.namespace, CYAN, use_color)}"
               f" | Node: {_c(pod.node_name, CYAN, use_color)}")

    mode_str = gateway_mode or "shared"
    ic_str = "IC" if cluster_info.is_interconnect else "non-IC"
    out.append(f"  Gateway: {_c(mode_str, YELLOW, use_color)}"
               f" | Mode: {_c(ic_str, YELLOW, use_color)}")

    if pod.mac:
        out.append(f"  MAC: {_c(pod.mac, DIM, use_color)}")

    out.append("  " + _c("═" * (DIAGRAM_WIDTH - 4), DIM, use_color))
    return out


# ── Pod path renderer ────────────────────────────────────────────────

def render_pod_path(path, wide=False, use_color=True):
    lines = []

    lines.extend(render_header(path.pod, path.cluster_info,
                               path.gateway_mode, use_color))
    lines.append("")

    lines.extend(_render_node_swimlane(path, use_color))

    # Chassis footer
    if path.chassis.name or path.chassis.encap_type:
        ch = []
        if path.chassis.name:
            ch.append(f"Chassis: {_trunc(path.chassis.name, 20)}")
        if path.chassis.encap_type:
            ch.append(f"Encap: {path.chassis.encap_type}")
        if path.chassis.encap_ip:
            ch.append(f"Tunnel: {path.chassis.encap_ip}")
        lines.append(f"  {_c(' | '.join(ch), DIM, use_color)}")

    # OVS Flows
    if path.flows:
        lines.append("")
        lines.append(_c("  Matching OVS Flows (br-int):", BOLD, use_color))
        lines.append(_c("  " + "─" * 60, DIM, use_color))
        for f in path.flows[:15]:
            lines.append(
                f"  table={f.table} priority={f.priority} "
                f"pkts={f.n_packets} actions={f.actions[:40]}"
            )
        if len(path.flows) > 15:
            lines.append(_c(
                f"  ... and {len(path.flows) - 15} more flows",
                DIM, use_color))

    # Trace output
    if path.trace_output:
        lines.append("")
        lines.append(_c("  OVN Trace Output:", BOLD + MAGENTA, use_color))
        lines.append(_c("  " + "─" * 60, DIM, use_color))
        for tline in path.trace_output.splitlines():
            lines.append(f"  {tline}")

    lines.append("")
    return "\n".join(lines)


# ── Diagnosis renderer ───────────────────────────────────────────────

def render_diagnosis(diag_result, use_color=True):
    lines = []

    lines.append("")
    lines.append(_c("  oc-traffic", BOLD + CYAN, use_color)
                 + _c(" — diagnosis report", DIM, use_color))
    lines.append("")

    src = diag_result.src_path
    dst = diag_result.dst_path

    # Source swim lane
    if src:
        lines.extend(_render_node_swimlane(src, use_color, label="SOURCE"))

    # Tunnel or same-node indicator
    if src and dst:
        if src.pod.node_name == dst.pod.node_name:
            lines.append("")
            lines.append(_c("  (same node — no tunnel needed)", DIM, use_color))
            lines.append("")
        else:
            W = DIAGRAM_WIDTH
            tunnel = " ║ Geneve Tunnel ║ "
            pad = (W - len(tunnel)) // 2
            lines.append("")
            lines.append(
                _c("  " + "─" * pad, DIM, use_color)
                + _c(tunnel, BOLD + MAGENTA, use_color)
                + _c("─" * pad, DIM, use_color))
            lines.append("")

    # Destination swim lane
    if dst:
        lines.extend(_render_node_swimlane(dst, use_color, label="DEST"))

    # Connectivity tests
    if diag_result.connectivity:
        lines.append("")
        lines.append(_c("  Connectivity Tests:", BOLD, use_color))
        lines.append(_c("  " + "─" * 50, DIM, use_color))
        for ct in diag_result.connectivity:
            if ct.success:
                icon = _c("✓", GREEN, use_color)
                status = _c("PASS", GREEN, use_color)
            else:
                icon = _c("✗", RED, use_color)
                status = _c("FAIL", RED, use_color)

            detail = ""
            if ct.test_type == "icmp":
                detail = f"ICMP ping {ct.destination}"
                if ct.latency_ms:
                    detail += f" ({ct.latency_ms}ms)"
            elif ct.test_type == "tcp":
                detail = f"TCP connect {ct.destination}:{ct.port}"
            elif ct.test_type == "dns":
                detail = f"DNS lookup {ct.destination}"

            lines.append(f"  {icon} [{status}] {detail}")
            if ct.error and not ct.success:
                lines.append(
                    f"          {_c(ct.error[:60], DIM, use_color)}")

    # Diagnostic checks
    if diag_result.checks:
        lines.append("")
        lines.append(_c("  Diagnostic Checks:", BOLD, use_color))
        lines.append(_c("  " + "─" * 50, DIM, use_color))
        for check in diag_result.checks:
            if check.passed:
                if check.severity == "warn":
                    icon = _c("!", YELLOW, use_color)
                    status = _c("WARN", YELLOW, use_color)
                else:
                    icon = _c("✓", GREEN, use_color)
                    status = _c("OK", GREEN, use_color)
            else:
                icon = _c("✗", RED, use_color)
                status = _c("FAIL", RED, use_color)

            lines.append(f"  {icon} [{status}] {check.name}")
            if check.detail:
                lines.append(
                    f"          {_c(check.detail[:60], DIM, use_color)}")

    # ACL summary
    if src and src.acls:
        lines.append("")
        lines.append(_c(f"  OVN ACLs on {src.logical_switch.name}:",
                        BOLD, use_color))
        deny = [a for a in src.acls
                if "drop" in a.lower() or "reject" in a.lower()]
        if deny:
            for acl in deny[:5]:
                lines.append(
                    f"    {_c('DENY', RED, use_color)} {acl[:55]}")
        else:
            lines.append(
                f"    {_c('No deny/reject ACLs', GREEN, use_color)}")

    if dst and dst.acls:
        deny = [a for a in dst.acls
                if "drop" in a.lower() or "reject" in a.lower()]
        if deny:
            lines.append(_c(
                f"  OVN ACLs on {dst.logical_switch.name}:",
                BOLD, use_color))
            for acl in deny[:5]:
                lines.append(
                    f"    {_c('DENY', RED, use_color)} {acl[:55]}")

    lines.append("")
    return "\n".join(lines)


# ── Service renderer (uses box style) ────────────────────────────────

def render_box_terminal(title, lines, width=BOX_WIDTH, color="",
                        use_color=True):
    out = []
    inner = width - 4

    top = "  " + _c("┌" + "─" * (width - 2) + "┐", color, use_color)
    out.append(top)

    title_padded = f"  {title}"
    title_padded = title_padded[:inner]
    title_padded = title_padded.ljust(inner)
    out.append("  " + _c("│", color, use_color)
               + f" {_c(title_padded, BOLD + color if use_color else '', use_color)} "
               + _c("│", color, use_color))

    for line in lines:
        line = line[:inner]
        line = line.ljust(inner)
        out.append("  " + _c("│", color, use_color)
                   + f" {line} " + _c("│", color, use_color))

    bottom = "  " + _c("└" + "─" * (width - 2) + "┘", color, use_color)
    out.append(bottom)
    return out


def render_service(fanout, use_color=True):
    lines = []
    lines.append("")
    lines.append(_c("  oc-traffic", BOLD + CYAN, use_color)
                 + _c(" — service fan-out", DIM, use_color))
    lines.append("")
    lines.append(f"  Service: {_c(fanout.name, BOLD, use_color)}"
                 f" ({_c(fanout.cluster_ip, GREEN, use_color)})")
    lines.append(f"  Namespace: {_c(fanout.namespace, CYAN, use_color)}")

    if fanout.ports:
        port_strs = []
        for p in fanout.ports:
            port_strs.append(
                f"{p.get('port','?')}/{p.get('protocol','TCP')}"
                f" -> {p.get('targetPort','?')}")
        lines.append(f"  Ports: {', '.join(port_strs)}")

    if fanout.selector:
        sel_str = ", ".join(f"{k}={v}" for k, v in fanout.selector.items())
        lines.append(f"  Selector: {_c(sel_str, DIM, use_color)}")

    lines.append("  " + _c("═" * (BOX_WIDTH - 2), DIM, use_color))

    # Endpoints box
    ep_lines = []
    ready_count = sum(1 for e in fanout.endpoints if e.ready)
    not_ready_count = len(fanout.endpoints) - ready_count

    for ep in fanout.endpoints:
        status = (_c("●", GREEN, use_color) if ep.ready
                  else _c("○", RED, use_color))
        ready_mark = (_c("ready", GREEN, use_color) if ep.ready
                      else _c("not-ready", RED, use_color))
        ep_lines.append(f"{status} {ep.pod_name} ({ep.pod_ip})")
        ep_lines.append(f"  node: {ep.node_name} [{ready_mark}]")

    if not ep_lines:
        ep_lines = ["No endpoints found"]

    lines.extend(render_box_terminal(
        f"Endpoints ({ready_count} ready, {not_ready_count} not-ready)",
        ep_lines, width=BOX_WIDTH + 10, color=CYAN, use_color=use_color))

    # OVN Load Balancers
    if fanout.lb_info:
        lines.append("")
        for lb in fanout.lb_info:
            lb_lines = []
            if lb.name:
                lb_lines.append(f"name: {lb.name}")
            if lb.protocol:
                lb_lines.append(f"protocol: {lb.protocol}")
            for vip, backends in lb.vips.items():
                lb_lines.append(f"VIP: {vip}")
                if isinstance(backends, str):
                    for b in backends.split(","):
                        lb_lines.append(f"  -> {b.strip()}")
            lines.extend(render_box_terminal(
                "OVN Load Balancer",
                lb_lines, color=YELLOW, use_color=use_color))

    lines.append("")
    return "\n".join(lines)
