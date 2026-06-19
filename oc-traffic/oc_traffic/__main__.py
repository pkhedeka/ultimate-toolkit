import argparse
import sys

from .errors import OcTrafficError
from .cluster import detect_cluster
from .collector import collect_pod_path
from .renderer import render_pod_path, render_service, render_diagnosis
from .service import get_service_fanout
from .trace import run_ovn_trace
from .diagnose import run_diagnosis


def build_parser():
    parser = argparse.ArgumentParser(
        prog="oc-traffic",
        description="OVN-Kubernetes network path visualizer for OpenShift",
    )

    parser.add_argument("command", nargs="?", default="pod",
                        choices=["pod", "service"],
                        help="Command: pod (default) or service")
    parser.add_argument("name", help="Pod or service name")
    parser.add_argument("-n", "--namespace", default=None, help="Namespace")
    parser.add_argument("--to", dest="destination", default=None,
                        help="Destination pod name or IP")
    parser.add_argument("--port", default=None,
                        help="TCP/UDP port number for connectivity test")
    parser.add_argument("--protocol", default="tcp", choices=["tcp", "udp"],
                        help="Protocol for port test (default: tcp)")
    parser.add_argument("--flows", action="store_true",
                        help="Show OVS flow hit counts")
    parser.add_argument("--trace", action="store_true",
                        help="Run ovn-trace and annotate diagram")
    parser.add_argument("--diagnose", action="store_true",
                        help="Run full connectivity diagnosis (requires --to)")
    parser.add_argument("--wide", action="store_true",
                        help="Show extra details (MACs, tunnel keys)")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable color output")
    parser.add_argument("--ovn-namespace", default=None,
                        help="Override OVN namespace")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show oc exec commands being run")

    return parser


def get_current_namespace():
    import subprocess
    try:
        result = subprocess.run(
            ["oc", "project", "-q"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return "default"


def main():
    parser = build_parser()

    # Handle bare pod name without subcommand
    args = sys.argv[1:]
    if args and args[0] not in ("pod", "service", "-h", "--help") and not args[0].startswith("-"):
        args = ["pod"] + args

    parsed = parser.parse_args(args)

    use_color = not parsed.no_color and sys.stdout.isatty()
    verbose = parsed.verbose

    try:
        namespace = parsed.namespace or get_current_namespace()
        cluster_info = detect_cluster(
            ovn_namespace_override=parsed.ovn_namespace,
            verbose=verbose,
        )

        if parsed.command == "service":
            output = handle_service(parsed.name, namespace, cluster_info,
                                    use_color, verbose)
        elif parsed.diagnose:
            if not parsed.destination:
                sys.stderr.write("Error: --diagnose requires --to <destination>\n")
                return 1
            output = handle_diagnose(
                parsed.name, namespace, parsed.destination,
                cluster_info, port=parsed.port, protocol=parsed.protocol,
                use_color=use_color, verbose=verbose,
            )
        else:
            output = handle_pod(
                parsed.name, namespace, cluster_info,
                destination=parsed.destination,
                show_flows=parsed.flows,
                show_trace=parsed.trace,
                wide=parsed.wide,
                use_color=use_color,
                verbose=verbose,
            )

        print(output)
        return 0

    except OcTrafficError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1
    except KeyboardInterrupt:
        return 130


def handle_pod(pod_name, namespace, cluster_info, destination=None,
               show_flows=False, show_trace=False, wide=False,
               use_color=True, verbose=False):
    path = collect_pod_path(pod_name, namespace, cluster_info,
                            show_flows=show_flows, verbose=verbose)

    if show_trace:
        path.trace_output = run_ovn_trace(path, destination, verbose=verbose)

    return render_pod_path(path, wide=wide, use_color=use_color)


def handle_service(svc_name, namespace, cluster_info, use_color=True,
                   verbose=False):
    fanout = get_service_fanout(svc_name, namespace, cluster_info,
                                verbose=verbose)
    return render_service(fanout, use_color=use_color)


def handle_diagnose(pod_name, namespace, destination, cluster_info,
                    port=None, protocol="tcp", use_color=True, verbose=False):
    diag_result = run_diagnosis(
        pod_name, namespace, destination, cluster_info,
        port=port, protocol=protocol, verbose=verbose,
    )
    return render_diagnosis(diag_result, use_color=use_color)


if __name__ == "__main__":
    sys.exit(main())
