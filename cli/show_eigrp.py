#!/usr/bin/env python3
###########################################################################
# Nokia SR Linux CLI Plugin: EIGRP Show Reports
# Supports:
#   show network-instance <name> protocols eigrp summary
#   show network-instance <name> protocols eigrp neighbor [neighbor-ip]
#   show network-instance <name> protocols eigrp routes
#   show network-instance <name> protocols eigrp interfaces [interface-name]
#   show network-instance <name> protocols eigrp topology
#   show network-instance <name> protocols eigrp traffic
###########################################################################
import json
import os
import re
from srlinux.location import build_path
from srlinux.mgmt.cli import RequiredPlugin, CliPlugin, KeyCompleter
from srlinux.syntax import Syntax

STATE_FILES = [
    "/var/run/srl_eigrp_state.json",
    "/tmp/srl_eigrp_state.json",
]


def normalize_interface_name(ifname):
    if not ifname:
        return ""
    m = re.match(r"^e(\d+)-(\d+)(\.\d+)?$", ifname)
    if m:
        sub = m.group(3) if m.group(3) else ""
        return f"ethernet-{m.group(1)}/{m.group(2)}{sub}"
    return ifname


def _intf_path(args):
    netinst = args.get_value_or("network-instance", "name", "*")
    return build_path(f"/network-instance[name={netinst}]/protocols/eigrp/interface[interface-name=*]")


def _nbr_path(args):
    netinst = args.get_value_or("network-instance", "name", "*")
    return build_path(f"/network-instance[name={netinst}]/protocols/eigrp/neighbor[ip-address=*]")


def get_target_instances(state=None, netinst_arg="default"):
    """Returns a list of network-instance names matching the user request.
    If netinst_arg is '*' or empty, discovers all instances with EIGRP configuration or state.
    """
    if netinst_arg and netinst_arg != "*":
        return [netinst_arg]

    found = []
    # 1. From local JSON state file
    for path in STATE_FILES:
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    data = json.load(f)
                    if "instances" in data:
                        for k in data["instances"].keys():
                            if k not in found:
                                found.append(k)
                    elif "network-instance" in data:
                        k = data["network-instance"]
                        if k not in found:
                            found.append(k)
            except Exception:
                pass

    # 2. From server_data_store if available
    if state and hasattr(state, "server_data_store"):
        try:
            path = build_path("/network-instance[name=*]/protocols/eigrp")
            data_str = state.server_data_store.get_json(path, recursive=False)
            if data_str:
                raw = json.loads(data_str)
                if isinstance(raw, list):
                    for item in raw:
                        if isinstance(item, dict) and "name" in item:
                            if item["name"] not in found:
                                found.append(item["name"])
                elif isinstance(raw, dict):
                    for k in raw.keys():
                        if k not in found:
                            found.append(k)
        except Exception:
            pass

    if not found:
        return ["default"]

    # Filter to instances that actually have active EIGRP data
    active = []
    for inst in found:
        d = load_state(state=state, netinst=inst)
        if d and (d.get("autonomous-system") or d.get("interfaces") or d.get("interface") or d.get("neighbors") or d.get("neighbor")):
            active.append(inst)

    return active if active else (found if found else ["default"])


def load_state(state=None, netinst="default"):
    """Loads state first from SR Linux State DB (server_data_store), with fallback to local JSON."""
    local_data = {}
    for path in STATE_FILES:
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    local_data = json.load(f)
                    break
            except Exception:
                pass

    if "instances" in local_data:
        inst_data = local_data["instances"].get(netinst)
        if inst_data:
            local_data = inst_data
        elif netinst != "default":
            local_data = {}

    if state and hasattr(state, "server_data_store"):
        try:
            path = build_path(f"/network-instance[name={netinst}]/protocols/eigrp")
            data_str = state.server_data_store.get_json(path, recursive=True)
            if data_str:
                raw = json.loads(data_str)
                intfs = raw.get("interface", local_data.get("interface", []))
                nbrs = raw.get("neighbor", local_data.get("neighbor", []))
                routes = raw.get("route", local_data.get("route", []))
                topos = raw.get("topology", local_data.get("topology", []))
                traffics = raw.get("traffic", local_data.get("traffic", []))
                return {
                    "autonomous-system": raw.get("autonomous-system") or local_data.get("autonomous-system", 0),
                    "router-id": raw.get("router-id") or local_data.get("router-id", "unspecified"),
                    "admin-state": raw.get("admin-state") or local_data.get("admin-state", "enable"),
                    "oper-state": raw.get("oper-state") or local_data.get("oper-state", "down"),
                    "updated-at": "State DB (synchronized)",
                    "networks": raw.get("network", local_data.get("networks", [])),
                    "static-neighbors": raw.get("static-neighbor", local_data.get("static-neighbors", [])),
                    "static-neighbor": raw.get("static-neighbor", local_data.get("static-neighbor", [])),
                    "interfaces": intfs,
                    "interface": intfs,
                    "neighbors": nbrs,
                    "neighbor": nbrs,
                    "routes": routes,
                    "route": routes,
                    "topology": topos,
                    "traffic": traffics,
                    "rib-scale": raw.get("rib-scale", local_data.get("rib-scale", 128)),
                    "wide-metrics": raw.get("wide-metrics", local_data.get("wide-metrics", True)),
                    "graceful-restart": raw.get("graceful-restart", local_data.get("graceful-restart", {})),
                    "default-interface": raw.get("default-interface", local_data.get("default-interface", {})),
                    "variance": raw.get("variance", local_data.get("variance", 1)),
                    "maximum-paths": raw.get("maximum-paths", local_data.get("maximum-paths", 4)),
                    "maximum-hops": raw.get("maximum-hops", local_data.get("maximum-hops", 100)),
                    "timers": raw.get("timers", local_data.get("timers", {})),
                    "metrics": raw.get("metrics", local_data.get("metrics", {})),
                    "export-policy": raw.get("export-policy", local_data.get("export-policy", "")),
                    "import-policy": raw.get("import-policy", local_data.get("import-policy", "")),
                }
        except Exception:
            pass

    return local_data if local_data else None


class Plugin(CliPlugin):
    """Adds EIGRP show reports under network-instance protocols eigrp."""

    def get_required_plugins(self):
        return [
            RequiredPlugin(module="srlinux", plugin="netinst_reports"),
        ]

    def load(self, cli, **_kwargs):
        network = cli.show_mode.root.get_command("network-instance")
        protocols = network.get_command("protocols")

        # Idempotent command registration prevents "Node 'eigrp' was added twice" collision
        eigrp = protocols.get_command_or_none("eigrp")
        if not eigrp:
            eigrp = protocols.add_command(
                Syntax("eigrp", help="Show EIGRP protocol information"),
                update_location=True
            )

        if not eigrp.has_command("summary"):
            eigrp.add_command(
                Syntax("summary", help="Show EIGRP protocol summary and instance details"),
                update_location=False,
                callback=self.show_summary
            )

        if not eigrp.has_command("neighbor"):
            nbr_syntax = Syntax("neighbor", help="Show EIGRP neighbor table")
            nbr_syntax.add_unnamed_argument("neighbor-ip", default="*", suggestions=KeyCompleter(path=_nbr_path))
            eigrp.add_command(
                nbr_syntax,
                update_location=False,
                callback=self.show_neighbor
            )

        if not eigrp.has_command("routes"):
            eigrp.add_command(
                Syntax("routes", help="Show EIGRP learned routing table"),
                update_location=False,
                callback=self.show_routes
            )

        if not eigrp.has_command("interfaces"):
            ifs_syntax = Syntax("interfaces", help="Show EIGRP participating interfaces")
            ifs_syntax.add_unnamed_argument("interface-name", default="*", suggestions=KeyCompleter(path=_intf_path))
            eigrp.add_command(
                ifs_syntax,
                update_location=False,
                callback=self.show_interfaces
            )

        if not eigrp.has_command("topology"):
            eigrp.add_command(
                Syntax("topology", help="Show EIGRP DUAL topology table"),
                update_location=False,
                callback=self.show_topology
            )

        if not eigrp.has_command("traffic"):
            eigrp.add_command(
                Syntax("traffic", help="Show EIGRP traffic and packet statistics"),
                update_location=False,
                callback=self.show_traffic
            )

    def show_summary(self, state, arguments, output, **kwargs):
        netinst_arg = arguments.get_value_or("network-instance", "name", "default")
        instances = get_target_instances(state=state, netinst_arg=netinst_arg)

        for netinst in instances:
            data = load_state(state=state, netinst=netinst)

            output.print_line("=" * 80)
            output.print_line(f"EIGRP Summary for Network-Instance: {netinst}")
            output.print_line("=" * 80)

            if not data:
                output.print_line("Summary: EIGRP daemon not running or not configured.")
                output.print_line("=" * 80)
                continue

            asn = data.get("autonomous-system", 0)
            rid = data.get("router-id", "unspecified")
            admin = data.get("admin-state", "disable")
            oper = data.get("oper-state", "down")
            updated = data.get("updated-at", "N/A")
            networks = data.get("networks", [])
            nbrs = data.get("neighbors") or data.get("neighbor", [])
            routes = data.get("routes") or data.get("route", [])
            interfaces = data.get("interfaces") or data.get("interface", [])

            output.print_line(f"{'Autonomous System':<24}: {asn}")
            output.print_line(f"{'Router ID':<24}: {rid}")
            output.print_line(f"{'Admin State':<24}: {admin}")
            output.print_line(f"{'Operational State':<24}: {oper}")
            output.print_line(f"{'Configured Networks':<24}: {', '.join(networks) if networks else 'None'}")
            output.print_line(f"{'Participating Interfaces':<24}: {len(interfaces)}")
            output.print_line(f"{'Established Neighbors':<24}: {len(nbrs)}")
            output.print_line(f"{'Learned Routes':<24}: {len(routes)}")
            output.print_line(f"{'RIB Scale':<24}: {data.get('rib-scale', 128)}")
            output.print_line(f"{'Wide Metrics (64-bit)':<24}: {'enabled' if data.get('wide-metrics', True) else 'disabled'}")
            gr = data.get('graceful-restart', {})
            if isinstance(gr, dict):
                gr_oper = gr.get('oper-state', 'down' if gr.get('admin-state') == 'disable' else ('up' if gr else 'disabled'))
            else:
                gr_oper = 'disabled'
            output.print_line(f"{'Graceful Restart':<24}: {gr_oper}")
            output.print_line(f"{'Last Telemetry Update':<24}: {updated}")
            output.print_line("=" * 80)
 
    show_status = show_summary

    def show_neighbor(self, state, arguments, output, **kwargs):
        netinst_arg = arguments.get_value_or("network-instance", "name", "default")
        target_nbr = arguments.get_value_or("neighbor", "neighbor-ip", "*")
        instances = get_target_instances(state=state, netinst_arg=netinst_arg)

        nbr_found_in_any = False
        for netinst in instances:
            data = load_state(state=state, netinst=netinst)
            asn = data.get("autonomous-system", 0) if data else 0
            nbrs = data.get("neighbors") or data.get("neighbor", []) if data else []

            if target_nbr and target_nbr != "*":
                # Detailed single neighbor view
                matched = [n for n in nbrs if n.get("ip-address") == target_nbr]
                if not matched:
                    continue

                nbr_found_in_any = True
                n = matched[0]
                ip = n.get("ip-address", "")
                raw_itf = n.get("interface", "")
                norm_itf = normalize_interface_name(raw_itf)
                st = n.get("state", "Down")
                hold = n.get("hold-time", 0)
                up_raw = str(n.get("uptime", 0))
                up_clean = up_raw[:-1] if up_raw.endswith("s") else up_raw
                srtt = n.get("srtt-ms", 0)
                rto = n.get("rto-ms", 0)

                # Find routes learned from this neighbor
                routes = data.get("routes") or data.get("route", []) if data else []
                learned_routes = [r for r in routes if r.get("next-hop") == ip]

                output.print_line("=" * 80)
                output.print_line(f"EIGRP Neighbor Details: {ip} (Network-Instance: {netinst})")
                output.print_line("=" * 80)
                output.print_line(f"{'Neighbor IP Address':<26}: {ip}")
                output.print_line(f"{'Interface':<26}: {norm_itf} ({raw_itf})")
                output.print_line(f"{'Adjacency State':<26}: {st}")
                output.print_line(f"{'Hold Time':<26}: {hold} seconds")
                output.print_line(f"{'Uptime':<26}: {up_clean} seconds")
                output.print_line(f"{'Smooth RTT (SRTT)':<26}: {srtt} ms")
                output.print_line(f"{'Retransmit Timeout (RTO)':<26}: {rto} ms")
                output.print_line(f"{'BFD State':<26}: {n.get('bfd-state', 'disabled')}")
                output.print_line(f"{'Restart State':<26}: {n.get('restart-state', 'normal')}")
                output.print_line(f"{'Authentication Mode':<26}: {n.get('auth-mode', 'none')}")
                output.print_line(f"{'Autonomous System':<26}: {asn}")
                output.print_line("-" * 80)
                output.print_line(f"Learned Routes via this Neighbor ({len(learned_routes)}):")
                if learned_routes:
                    output.print_line(f"  {'Prefix':<22} {'Metric':<12} {'Wide-Metric':<18} {'Type':<10} {'Preference':<6}")
                    for r in learned_routes:
                        pfx = r.get("prefix", "")
                        metric = str(r.get("metric", 0))
                        wide_metric = str(r.get("wide-metric", 0))
                        rtype = "External" if r.get("external", False) else "Internal"
                        pref = "170" if r.get("external", False) else "90"
                        output.print_line(f"  {pfx:<22} {metric:<12} {wide_metric:<18} {rtype:<10} {pref:<6}")
                else:
                    output.print_line("  None")
                output.print_line("=" * 80)
                continue

            # Summary view
            is_v6 = any(":" in str(n.get("ip-address", "")) for n in nbrs)
            ip_w = 30 if is_v6 else 16
            div_len = 114 if is_v6 else 98
            output.print_line("=" * div_len)
            output.print_line(f"EIGRP Neighbors for Network-Instance: {netinst} (AS: {asn})")
            output.print_line("-" * div_len)
            output.print_line(f"{'Neighbor IP':<{ip_w}} {'Interface':<18} {'State':<8} {'Hold (s)':<10} {'Uptime (s)':<12} {'BFD':<10} {'Auth':<10}")
            output.print_line("-" * div_len)

            if not nbrs:
                output.print_line("No active EIGRP neighbors found.")
            else:
                for n in nbrs:
                    ip = n.get("ip-address", "")
                    itf = normalize_interface_name(n.get("interface", ""))
                    st = n.get("state", "Down")
                    hold = str(n.get("hold-time", 0))
                    up_raw = str(n.get("uptime", 0))
                    up_clean = up_raw[:-1] if up_raw.endswith("s") else up_raw
                    bfd_st = str(n.get("bfd-state", "disabled"))
                    auth_md = str(n.get("auth-mode", "none"))
                    output.print_line(f"{ip:<{ip_w}} {itf:<18} {st:<8} {hold:<10} {up_clean:<12} {bfd_st:<10} {auth_md:<10}")

            output.print_line("-" * div_len)
            output.print_line(f"Total Neighbors: {len(nbrs)}")
            output.print_line("=" * div_len)

        if target_nbr and target_nbr != "*" and not nbr_found_in_any:
            target_scope = netinst_arg if netinst_arg != "*" else "all network-instances"
            output.print_line("=" * 80)
            output.print_line(f"EIGRP Neighbor Details: {target_nbr} ({target_scope})")
            output.print_line("=" * 80)
            output.print_line(f"Neighbor '{target_nbr}' not found in EIGRP neighbor table.")
            output.print_line("=" * 80)

    def show_routes(self, state, arguments, output, **kwargs):
        netinst_arg = arguments.get_value_or("network-instance", "name", "default")
        instances = get_target_instances(state=state, netinst_arg=netinst_arg)

        for netinst in instances:
            data = load_state(state=state, netinst=netinst)
            asn = data.get("autonomous-system", 0) if data else 0
            rib_scale = data.get("rib-scale", 128) if data else 128
            routes = data.get("routes") or data.get("route", []) if data else []
            is_v6 = any(":" in str(r.get("prefix", "")) or ":" in str(r.get("next-hop", "")) for r in routes)
            pfx_w = 28 if is_v6 else 20
            nh_w = 26 if is_v6 else 16
            div_len = 114 if is_v6 else 98

            output.print_line("=" * div_len)
            output.print_line(f"EIGRP Learned Routes for Network-Instance: {netinst} (AS: {asn}, RIB-Scale: {rib_scale})")
            output.print_line("-" * div_len)
            output.print_line(f"{'Prefix':<{pfx_w}} {'Next-Hop':<{nh_w}} {'Metric':<12} {'Wide-Metric':<18} {'Type':<10} {'Pref':<6}")
            output.print_line("-" * div_len)

            if not routes:
                output.print_line("No EIGRP learned routes installed.")
            else:
                for r in routes:
                    pfx = r.get("prefix", "")
                    nh = r.get("next-hop", "")
                    metric = str(r.get("metric", 0))
                    wide_metric = str(r.get("wide-metric", 0))
                    is_ext = r.get("external", False)
                    rtype = "External" if is_ext else "Internal"
                    pref = "170" if is_ext else "90"
                    output.print_line(f"{pfx:<{pfx_w}} {nh:<{nh_w}} {metric:<12} {wide_metric:<18} {rtype:<10} {pref:<6}")

            output.print_line("-" * div_len)
            output.print_line(f"Total Routes: {len(routes)}")
            output.print_line("=" * div_len)

    def show_interfaces(self, state, arguments, output, **kwargs):
        netinst_arg = arguments.get_value_or("network-instance", "name", "default")
        target_if = arguments.get_value_or("interfaces", "interface-name", "*")
        instances = get_target_instances(state=state, netinst_arg=netinst_arg)

        itf_found_in_any = False
        for netinst in instances:
            data = load_state(state=state, netinst=netinst)
            asn = data.get("autonomous-system", 0) if data else 0
            interfaces = data.get("interfaces") or data.get("interface", []) if data else []

            if target_if and target_if != "*":
                # Match target interface by exact name or normalized name
                norm_target = normalize_interface_name(target_if).lower()
                matched = [
                    itf for itf in interfaces
                    if itf.get("interface-name", itf.get("name", "")).lower() == target_if.lower()
                    or normalize_interface_name(itf.get("interface-name", itf.get("name", ""))).lower() == norm_target
                    or normalize_interface_name(itf.get("interface-name", itf.get("name", ""))).lower().startswith(norm_target + ".")
                ]

                if not matched:
                    continue

                itf_found_in_any = True
                itf = matched[0]
                raw_name = itf.get("interface-name", itf.get("name", ""))
                norm_name = normalize_interface_name(raw_name)
                ip = itf.get("ip-address", "")
                plen = itf.get("prefix-length", 32)
                oper = itf.get("oper-state", "Up")
                rid = data.get("router-id", "unspecified") if data else "unspecified"

                # Find neighbors on this interface
                nbrs = data.get("neighbors") or data.get("neighbor", []) if data else []
                nbrs_on_if = [
                    n for n in nbrs
                    if n.get("interface") == raw_name
                    or normalize_interface_name(n.get("interface")) == norm_name
                ]

                # Find traffic statistics for this interface
                traffic_list = data.get("traffic", []) if data else []
                tf_match = [
                    t for t in traffic_list
                    if t.get("interface") == raw_name
                    or normalize_interface_name(t.get("interface")) == norm_name
                ]
                tf = tf_match[0] if tf_match else {}

                output.print_line("=" * 80)
                output.print_line(f"EIGRP Interface Details: {norm_name} (Network-Instance: {netinst})")
                output.print_line("=" * 80)
                output.print_line(f"{'Interface Name':<26}: {norm_name}")
                output.print_line(f"{'Internal Device Name':<26}: {raw_name}")
                output.print_line(f"{'Admin State':<26}: {itf.get('admin-state', 'enable')}")
                output.print_line(f"{'Operational State':<26}: {oper}")
                output.print_line(f"{'Passive Interface':<26}: {'true' if itf.get('passive', False) else 'false'}")
                output.print_line(f"{'IP Address / Prefix':<26}: {ip}/{plen}")
                bfd_raw = itf.get('bfd-state', 'disabled')
                if isinstance(bfd_raw, dict):
                    bfd_str = bfd_raw.get("session-state", "disabled")
                    if "remote-address" in bfd_raw:
                        bfd_str += f" (peer: {bfd_raw['remote-address']})"
                else:
                    bfd_str = str(bfd_raw)
                output.print_line(f"{'BFD State':<26}: {bfd_str}")
                output.print_line(f"{'Authentication Mode':<26}: {itf.get('auth-mode', 'none')}")
                output.print_line(f"{'Autonomous System':<26}: {asn}")
                output.print_line(f"{'Router ID':<26}: {rid}")
                output.print_line(f"{'Active Neighbors':<26}: {len(nbrs_on_if)}")
                if nbrs_on_if:
                    nbr_ips = [n.get("ip-address", "") for n in nbrs_on_if]
                    output.print_line(f"{'  Neighbor IP(s)':<26}: {', '.join(nbr_ips)}")
                output.print_line("-" * 80)
                output.print_line("Interface Traffic Statistics:")
                output.print_line(f"  {'Reliable Multicast':<24}: {tf.get('reliable-multicast', 0)}")
                output.print_line(f"  {'Unreliable Multicast':<24}: {tf.get('unreliable-multicast', 0)}")
                output.print_line(f"  {'Reliable Unicast':<24}: {tf.get('reliable-unicast', 0)}")
                output.print_line(f"  {'Unreliable Unicast':<24}: {tf.get('unreliable-unicast', 0)}")
                output.print_line(f"  {'Retransmissions':<24}: {tf.get('retransmissions', 0)}")
                output.print_line(f"  {'CR Packets':<24}: {tf.get('cr-packets', 0)}")
                output.print_line("=" * 80)
                continue

            # Summary view
            output.print_line("=" * 96)
            output.print_line(f"EIGRP Interfaces for Network-Instance: {netinst} (AS: {asn})")
            output.print_line("-" * 96)
            output.print_line(f"{'Interface':<18} {'IP Address':<18} {'Prefix-Len':<12} {'Oper State':<12} {'Passive':<10} {'BFD':<10} {'Auth':<10}")
            output.print_line("-" * 96)

            if not interfaces:
                output.print_line("No active EIGRP interfaces found.")
            else:
                for itf in interfaces:
                    name = normalize_interface_name(itf.get("interface-name", itf.get("name", "")))
                    ip = itf.get("ip-address", "")
                    plen = str(itf.get("prefix-length", 32))
                    oper = itf.get("oper-state", "Up")
                    passive_str = "true" if itf.get("passive", False) else "false"
                    bfd_raw = itf.get("bfd-state", "disabled")
                    if isinstance(bfd_raw, dict):
                        bfd = str(bfd_raw.get("session-state", "disabled"))
                    else:
                        bfd = str(bfd_raw)
                    auth = str(itf.get("auth-mode", "none"))
                    output.print_line(f"{name:<18} {ip:<18} {plen:<12} {oper:<12} {passive_str:<10} {bfd:<10} {auth:<10}")

            output.print_line("-" * 96)
            output.print_line(f"Total Interfaces: {len(interfaces)}")
            output.print_line("=" * 96)

        if target_if and target_if != "*" and not itf_found_in_any:
            target_scope = netinst_arg if netinst_arg != "*" else "all network-instances"
            output.print_line("=" * 80)
            output.print_line(f"EIGRP Interface Details: {target_if} ({target_scope})")
            output.print_line("=" * 80)
            output.print_line(f"Interface '{target_if}' not found or not participating in EIGRP.")
            output.print_line("=" * 80)

    def show_topology(self, state, arguments, output, **kwargs):
        netinst_arg = arguments.get_value_or("network-instance", "name", "default")
        instances = get_target_instances(state=state, netinst_arg=netinst_arg)

        for netinst in instances:
            data = load_state(state=state, netinst=netinst)
            asn = data.get("autonomous-system", 0) if data else 0
            output.print_line("=" * 80)
            output.print_line(f"EIGRP DUAL Topology Table for Network-Instance: {netinst} (AS: {asn})")
            output.print_line("-" * 80)
            output.print_line("Codes: P - Passive, A - Active, U - Update, Q - Query, R - Reply")
            output.print_line("-" * 80)

            topology = data.get("topology", []) if data else []
            if isinstance(topology, dict):
                topology = list(topology.values())
            if not topology:
                output.print_line("No EIGRP topology entries found.")
            else:
                for p in topology:
                    dest = p.get("destination", "")
                    code = "A" if p.get("active", False) else "P"
                    succ = p.get("successor-count", 0)
                    fd = p.get("feasible-distance", 0)
                    output.print_line(f"{code} {dest}, {succ} successors, FD is {fd}")
                    routes = p.get("routes") or p.get("route", [])
                    if isinstance(routes, dict):
                        routes = list(routes.values())
                    for r in routes:
                        nh = r.get("next-hop", "")
                        itf = normalize_interface_name(r.get("interface", ""))
                        dist = r.get("distance", 0)
                        rd = r.get("reported-distance", 0)
                        tag = "Successor" if r.get("successor", False) else ("Feasible Successor" if r.get("feasible-successor", False) else "")
                        output.print_line(f"    via {nh} ({dist}/{rd}), {itf} {tag}")

            output.print_line("=" * 80)

    def show_traffic(self, state, arguments, output, **kwargs):
        netinst_arg = arguments.get_value_or("network-instance", "name", "default")
        instances = get_target_instances(state=state, netinst_arg=netinst_arg)

        for netinst in instances:
            data = load_state(state=state, netinst=netinst)
            asn = data.get("autonomous-system", 0) if data else 0
            output.print_line("=" * 80)
            output.print_line(f"EIGRP Traffic Statistics for Network-Instance: {netinst} (AS: {asn})")
            output.print_line("-" * 80)
            output.print_line(f"{'Interface':<20} {'Reliable Mcst':<14} {'Unreliable Mcst':<16} {'Reliable Ucst':<14} {'Retransmits':<12}")
            output.print_line("-" * 80)

            traffic = data.get("traffic", []) if data else []
            if not traffic:
                output.print_line("No EIGRP traffic statistics available.")
            else:
                for t in traffic:
                    itf = normalize_interface_name(t.get("interface", ""))
                    rm = str(t.get("reliable-multicast", 0))
                    um = str(t.get("unreliable-multicast", 0))
                    ru = str(t.get("reliable-unicast", 0))
                    rx = str(t.get("retransmissions", 0))
                    output.print_line(f"{itf:<20} {rm:<14} {um:<16} {ru:<14} {rx:<12}")

            output.print_line("-" * 80)
            output.print_line(f"Total Interfaces Monitored: {len(traffic)}")
            output.print_line("=" * 80)


###########################################################################
# State Query & Context Hook for EIGRP
# Ensures exact-path queries in candidate/running/state mode resolve
# correctly through SR Linux's NDK telemetry delivery nodes.
###########################################################################
try:
    from srlinux.mgmt.cli.plugins.info import InfoPrinter, DataStore
    _orig_info_get_data = InfoPrinter.get_data

    def _eigrp_info_get_data(self):
        req_path = self.path
        path_str = str(req_path)
        if self.data_store == DataStore.State and "protocols/eigrp" in path_str:
            parts = []
            in_eigrp = False
            has_exact = False
            for el in req_path.iterate_node_elements():
                if in_eigrp and el.keys:
                    if any(v != "*" for v in el.keys.values()):
                        has_exact = True
                    wild_keys = {k: "*" for k in el.keys}
                    kstr = "".join(f"[{k}={v}]" for k, v in wild_keys.items())
                    parts.append(f"{el.name}{kstr}")
                else:
                    kstr = "".join(f"[{k}={v}]" for k, v in el.keys.items()) if el.keys else ""
                    parts.append(f"{el.name}{kstr}")
                if el.name == "eigrp":
                    in_eigrp = True
            if has_exact:
                wildcard_path = build_path("/" + "/".join(parts))
                saved_path = self.path
                self.path = wildcard_path
                try:
                    return _orig_info_get_data(self)
                finally:
                    self.path = saved_path
        return _orig_info_get_data(self)

    InfoPrinter.get_data = _eigrp_info_get_data
except Exception:
    pass

try:
    from srlinux.mgmt.cli.plugins.any_schema import NodeExistenceChecker
    from srlinux.mgmt.cli.cli_mode import CliMode
    _orig_node_exists = NodeExistenceChecker._exists

    def _eigrp_node_exists(self, path):
        if _orig_node_exists(self, path):
            return True
        path_str = str(path)
        if "protocols/eigrp" in path_str and getattr(self._state, "mode", None) == CliMode.State:
            parts = []
            in_eigrp = False
            has_exact = False
            for el in path.iterate_node_elements():
                if in_eigrp and el.keys:
                    if any(v != "*" for v in el.keys.values()):
                        has_exact = True
                    wild_keys = {k: "*" for k in el.keys}
                    kstr = "".join(f"[{k}={v}]" for k, v in wild_keys.items())
                    parts.append(f"{el.name}{kstr}")
                else:
                    kstr = "".join(f"[{k}={v}]" for k, v in el.keys.items()) if el.keys else ""
                    parts.append(f"{el.name}{kstr}")
                if el.name == "eigrp":
                    in_eigrp = True
            if has_exact:
                wildcard_path = build_path("/" + "/".join(parts))
                all_server_paths = self._state.server_data_store.get_configuration(
                    wildcard_path,
                    recursive=False,
                    include_field_defaults=True,
                    include_container_parents=True,
                    limit=100
                )
                for server_path in all_server_paths:
                    if server_path.is_field and server_path.parent:
                        server_path = server_path.parent
                    if path == server_path:
                        return True
        return False

    NodeExistenceChecker._exists = _eigrp_node_exists
except Exception:
    pass

