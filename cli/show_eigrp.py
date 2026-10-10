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
import ipaddress
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
                intfs = raw.get("interface", [])
                if isinstance(intfs, dict):
                    intfs = [intfs]
                nbrs = raw.get("neighbor", [])
                if isinstance(nbrs, dict):
                    nbrs = [nbrs]
                routes = raw.get("route", [])
                if isinstance(routes, dict):
                    routes = [routes]
                topos = raw.get("topology", [])
                if isinstance(topos, dict):
                    topos = [topos]
                traffics = raw.get("traffic", [])
                if isinstance(traffics, dict):
                    traffics = [traffics]
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


def _match_prefix(route_pfx_str, target_pfx):
    if not target_pfx or target_pfx == "*":
        return True
    if route_pfx_str == target_pfx:
        return True
    try:
        if "/" in target_pfx:
            target_net = ipaddress.ip_network(target_pfx, strict=False)
            route_net = ipaddress.ip_network(route_pfx_str, strict=False)
            if route_net.subnet_of(target_net):
                return True
        else:
            target_ip = ipaddress.ip_address(target_pfx)
            route_net = ipaddress.ip_network(route_pfx_str, strict=False)
            if target_ip in route_net:
                return True
    except Exception:
        pass
    return route_pfx_str.startswith(target_pfx)


def register_route_type_override(route_owner, display_name, has_routes_checker=None):
    """
    Registers a custom routing process with the SR Linux CLI Route Display Pipeline.
    
    This function provides an open, cooperative registration mechanism so any
    NDK routing daemon (e.g. srl_eigrpd, srl_babel, srl_openfabric) can register its
    route_owner string to have its routes displayed with its native protocol name (e.g. 'eigrp')
    instead of generic 'ndk1' across all standard SR Linux route show commands (table,
    detail, summary, and JSON/YAML streams), without modifying any files in /opt/srlinux/.
    
    Other plugins can call this function directly, import it, or invoke:
      DataChildrenOfType.register_route_type_override(route_owner, display_name, has_routes_checker)
    """
    try:
        from srlinux.data.data import DataChildrenOfType

        if not hasattr(DataChildrenOfType, "_srl_route_type_overrides"):
            DataChildrenOfType._srl_route_type_overrides = {}
        if not hasattr(DataChildrenOfType, "_srl_route_summary_checkers"):
            DataChildrenOfType._srl_route_summary_checkers = {}

        DataChildrenOfType._srl_route_type_overrides[route_owner] = display_name
        if has_routes_checker:
            DataChildrenOfType._srl_route_summary_checkers[display_name] = has_routes_checker

        _install_generic_route_wrappers()
    except Exception:
        pass


def _install_generic_route_wrappers():
    """
    Installs the generic, multi-tenant middleware wrappers on SR Linux's shared
    in-memory row construction and formatting classes.
    
    Once installed by the first routing plugin, any subsequent plugins simply
    register into the shared registry without creating duplicate or conflicting wrappers.
    """
    try:
        from srlinux.data.data import DataChildrenOfType

        if getattr(DataChildrenOfType, "_srl_generic_route_hooked", False):
            return

        orig_create = DataChildrenOfType.create

        def generic_hooked_create(self, *args, **kwargs):
            schema_name = getattr(getattr(self, "schema", None), "name", None)
            overrides = getattr(DataChildrenOfType, "_srl_route_type_overrides", {})

            if schema_name == "ip route" and overrides:
                try:
                    keys = self._get_keys(*args, **kwargs)
                    owner = keys.get("route_owner")
                    if owner in overrides and keys.get("route_type") == "ndk1":
                        keys["route_type"] = overrides[owner]
                        current_item = self._get_sanitized_or_none(keys)
                        if current_item:
                            return current_item
                        self._check_modifications_are_allowed()
                        return self._create(False, keys)
                except Exception:
                    pass
            elif schema_name == "routesummary" and overrides:
                try:
                    keys = self._get_keys(*args, **kwargs)
                    if keys.get("route_type") == "ndk1":
                        netinst_name = getattr(getattr(self, "parent", None), "name", "default")
                        checkers = getattr(DataChildrenOfType, "_srl_route_summary_checkers", {})
                        for disp_name, checker in checkers.items():
                            try:
                                if checker(netinst_name):
                                    keys["route_type"] = disp_name
                                    current_item = self._get_sanitized_or_none(keys)
                                    if current_item:
                                        return current_item
                                    self._check_modifications_are_allowed()
                                    return self._create(False, keys)
                            except Exception:
                                pass
                except Exception:
                    pass
            return orig_create(self, *args, **kwargs)

        DataChildrenOfType.create = generic_hooked_create
        DataChildrenOfType._srl_generic_route_hooked = True
        DataChildrenOfType.register_route_type_override = staticmethod(register_route_type_override)
    except Exception:
        pass

    try:
        from srlinux.data.column_formatter import _Formatter
        if not getattr(_Formatter, "_srl_generic_route_hooked", False):
            orig_add = _Formatter.add

            def generic_hooked_add(self, column):
                from srlinux.data.data import DataChildrenOfType
                overrides = getattr(DataChildrenOfType, "_srl_route_type_overrides", {})

                if getattr(column, "schema", None) and getattr(column.schema, "name", None) == "ip route":
                    owner = getattr(column, "route_owner", None)
                    if owner in overrides:
                        try:
                            column._keys.set_sanitized("route_type", overrides[owner])
                        except Exception:
                            pass
                elif getattr(column, "schema", None) and getattr(column.schema, "name", None) == "routesummary":
                    if column._keys.get("route_type") == "ndk1":
                        netinst_name = getattr(getattr(column, "parent", None), "name", "default")
                        checkers = getattr(DataChildrenOfType, "_srl_route_summary_checkers", {})
                        for disp_name, checker in checkers.items():
                            try:
                                if checker(netinst_name):
                                    column._keys.set_sanitized("route_type", disp_name)
                                    break
                            except Exception:
                                pass
                return orig_add(self, column)

            _Formatter.add = generic_hooked_add
            _Formatter._srl_generic_route_hooked = True
    except Exception:
        pass

    try:
        from srlinux.mgmt.cli.plugins.reports.ip_route_detail import IpRouteDetailReport
        if not getattr(IpRouteDetailReport, "_srl_generic_route_hooked", False):
            orig_populate_route_fields = IpRouteDetailReport._populate_route_fields

            def generic_hooked_populate_route_fields(self, data, ip_route, state):
                orig_populate_route_fields(self, data, ip_route, state)
                from srlinux.data.data import DataChildrenOfType
                overrides = getattr(DataChildrenOfType, "_srl_route_type_overrides", {})
                owner = getattr(ip_route, "route_owner", None)
                if owner in overrides:
                    data.route_type = overrides[owner]

            IpRouteDetailReport._populate_route_fields = generic_hooked_populate_route_fields
            IpRouteDetailReport._srl_generic_route_hooked = True
    except Exception:
        pass


class Plugin(CliPlugin):
    """Adds EIGRP show reports under network-instance protocols eigrp, and ipv4/v6 route eigrp."""

    def get_required_plugins(self):
        return [
            RequiredPlugin(module="srlinux", plugin="netinst_reports"),
            RequiredPlugin(module="srlinux", plugin="ip_route_reports"),
        ]

    def load(self, cli, **_kwargs):
        # Register EIGRP with the shared, multi-tenant route display registry
        def _eigrp_has_routes_in_netinst(netinst_name):
            st = load_state(netinst=netinst_name)
            return bool(st and (st.get("routes") or st.get("route")))

        register_route_type_override(
            route_owner="srl_eigrpd",
            display_name="eigrp",
            has_routes_checker=_eigrp_has_routes_in_netinst
        )

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
            routes_cmd = Syntax("routes", help="Show EIGRP learned routing table")
            routes_cmd.add_unnamed_argument("prefix", default="*")
            eigrp.add_command(
                routes_cmd,
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

        # Register eigrp show commands under ipv4 route and ipv6 route
        ipv4 = network.get_command_or_none("ipv4")
        if ipv4:
            ipv4_route = ipv4.get_command_or_none("route")
            if ipv4_route and not ipv4_route.has_command("eigrp"):
                eigrp_v4 = Syntax("eigrp", help="Show EIGRP learned IPv4 routing table")
                eigrp_v4.add_unnamed_argument("prefix", default="*")
                ipv4_route.add_command(
                    eigrp_v4,
                    update_location=False,
                    callback=self.show_routes_v4
                )

        ipv6 = network.get_command_or_none("ipv6")
        if ipv6:
            ipv6_route = ipv6.get_command_or_none("route")
            if ipv6_route and not ipv6_route.has_command("eigrp"):
                eigrp_v6 = Syntax("eigrp", help="Show EIGRP learned IPv6 routing table")
                eigrp_v6.add_unnamed_argument("prefix", default="*")
                ipv6_route.add_command(
                    eigrp_v6,
                    update_location=False,
                    callback=self.show_routes_v6
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
            if oper.lower() != "up":
                down_reason = data.get("oper-down-reason")
                if not down_reason:
                    if admin == "disable":
                        down_reason = "protocol admin disabled"
                    elif asn == 0:
                        down_reason = "autonomous-system not configured"
                    else:
                        down_reason = "instance initializing or inactive"
                output.print_line(f"{'Down Reason':<24}: {down_reason}")
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
            interfaces = data.get("interfaces") or data.get("interface", []) if data else []

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
                if st.lower() != "up":
                    down_reason = n.get("oper-down-reason") or "hold-timer expired or peering down"
                    output.print_line(f"{'Down Reason':<26}: {down_reason}")
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
                proto_oper = data.get("oper-state", "down") if data else "down"
                if proto_oper.lower() != "up":
                    proto_down_reason = data.get("oper-down-reason", "protocol instance inactive") if data else "protocol instance inactive"
                    output.print_line(f"  Reason: Protocol instance is down ({proto_down_reason})")
                elif not interfaces:
                    output.print_line("  Reason: No interfaces participating in EIGRP")
                else:
                    valid_itfs = [i for i in interfaces if isinstance(i, dict)]
                    def is_itf_passive(itf):
                        afs = itf.get("address-family", [])
                        if afs:
                            active_afs = [af for af in afs if af.get("admin-state", "enable") != "disable"]
                            if active_afs:
                                return all(af.get("passive", False) for af in active_afs)
                        return itf.get("passive", False)
                    all_passive = all(is_itf_passive(itf) for itf in valid_itfs) if valid_itfs else False
                    all_down = all(itf.get("oper-state", "down").lower() != "up" for itf in valid_itfs) if valid_itfs else False
                    if all_passive:
                        output.print_line("  Reason: All participating interfaces are passive (hello exchange suppressed)")
                    elif all_down:
                        down_reasons = set(itf.get("oper-down-reason", "interface down") for itf in valid_itfs if itf.get("oper-down-reason"))
                        reasons_str = f" ({', '.join(down_reasons)})" if down_reasons else ""
                        output.print_line(f"  Reason: All participating interfaces are operationally down{reasons_str}")
                    else:
                        output.print_line("  Status: Interfaces active, awaiting peer Hellos (IP protocol 88)")
                        output.print_line("  Tip   : Verify remote peer configuration, CPM filter ('tools ... check-cpm'), and authentication")
                static_nbrs = data.get("static-neighbor") or data.get("static_neighbor", []) if data else []
                if static_nbrs:
                    output.print_line("Configured Static Neighbors:")
                    for sn in static_nbrs:
                        sn_ip = sn.get("ip-address", "")
                        sn_if = normalize_interface_name(sn.get("interface", ""))
                        sn_st = sn.get("oper-state", "down")
                        sn_rsn = sn.get("oper-down-reason", "peer unreachable")
                        output.print_line(f"  - {sn_ip} on {sn_if}: {sn_st} ({sn_rsn})")
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
            output.print_line("Troubleshooting tips:")
            output.print_line(f"  1. Verify peer IP {target_nbr} is on-link and directly reachable.")
            output.print_line("  2. Verify CPM filter allows inbound protocol 88 ('tools ... check-cpm').")
            output.print_line("  3. Verify Autonomous System number, K-values, and authentication keys match.")
            output.print_line("=" * 80)

    def show_routes(self, state, arguments, output, af_filter=None, **kwargs):
        netinst_arg = arguments.get_value_or("network-instance", "name", "default")
        instances = get_target_instances(state=state, netinst_arg=netinst_arg)
        target_pfx = arguments.get_value_or("eigrp", "prefix", "*")
        if not target_pfx or target_pfx == "*":
            target_pfx = arguments.get_value_or("routes", "prefix", "*")

        for netinst in instances:
            data = load_state(state=state, netinst=netinst)
            asn = data.get("autonomous-system", 0) if data else 0
            rib_scale = data.get("rib-scale", 128) if data else 128
            all_routes = data.get("routes") or data.get("route", []) if data else []

            if af_filter == "ipv4":
                routes = [r for r in all_routes if ":" not in str(r.get("prefix", ""))]
                title_af = " IPv4"
            elif af_filter == "ipv6":
                routes = [r for r in all_routes if ":" in str(r.get("prefix", ""))]
                title_af = " IPv6"
            else:
                routes = all_routes
                title_af = ""

            if target_pfx and target_pfx != "*":
                routes = [r for r in routes if _match_prefix(str(r.get("prefix", "")), target_pfx)]

            is_v6 = any(":" in str(r.get("prefix", "")) or ":" in str(r.get("next-hop", "")) for r in routes)
            pfx_w = 28 if is_v6 else 20
            nh_w = 26 if is_v6 else 16
            div_len = 114 if is_v6 else 98

            output.print_line("=" * div_len)
            output.print_line(f"EIGRP Learned{title_af} Routes for Network-Instance: {netinst} (AS: {asn}, RIB-Scale: {rib_scale})")
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

    def show_routes_v4(self, state, arguments, output, **kwargs):
        return self.show_routes(state, arguments, output, af_filter="ipv4", **kwargs)

    def show_routes_v6(self, state, arguments, output, **kwargs):
        return self.show_routes(state, arguments, output, af_filter="ipv6", **kwargs)

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
                if oper.lower() != "up":
                    down_reason = itf.get("oper-down-reason")
                    if not down_reason:
                        if itf.get('admin-state') == 'disable':
                            down_reason = "interface admin disabled"
                        elif not ip:
                            down_reason = "no IP address configured"
                        else:
                            down_reason = "link down or inactive"
                    output.print_line(f"{'Down Reason':<26}: {down_reason}")
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
                auth_val = itf.get('auth-mode', 'none')
                if not auth_val or auth_val == 'none':
                    auth_c = itf.get('authentication', {})
                    if isinstance(auth_c, dict) and auth_c.get('mode'):
                        auth_val = auth_c.get('mode')
                output.print_line(f"{'Authentication Mode':<26}: {auth_val}")
                output.print_line(f"{'Autonomous System':<26}: {asn}")
                output.print_line(f"{'Router ID':<26}: {rid}")
                sa_top = itf.get("summary-address", [])
                if sa_top:
                    sa_strs = [f"{s.get('prefix')} (dist: {s.get('distance', 5)})" for s in sa_top if s.get('prefix')]
                    output.print_line(f"{'Summary Addresses':<26}: {', '.join(sa_strs)}")
                output.print_line(f"{'Active Neighbors':<26}: {len(nbrs_on_if)}")
                if nbrs_on_if:
                    nbr_ips = [n.get("ip-address", "") for n in nbrs_on_if]
                    output.print_line(f"{'  Neighbor IP(s)':<26}: {', '.join(nbr_ips)}")
                afs = itf.get("address-family", [])
                if afs:
                    output.print_line("-" * 80)
                    output.print_line("Address Families:")
                    for af in afs:
                        af_name = af.get("name", "")
                        af_oper = af.get("oper-state", "up")
                        af_pass = "true" if af.get("passive", False) else "false"
                        af_hello = af.get("hello-interval", 5)
                        af_hold = af.get("hold-time", 15)
                        af_sh = "true" if af.get("split-horizon", True) else "false"
                        af_nhs = "true" if af.get("next-hop-self", False) else "false"
                        output.print_line(f"  {af_name}:")
                        output.print_line(f"    {'Admin State':<22}: {af.get('admin-state', 'enable')}")
                        output.print_line(f"    {'Oper State':<22}: {af_oper}")
                        if af_oper.lower() != "up" and af.get("oper-down-reason"):
                            output.print_line(f"    {'Down Reason':<22}: {af.get('oper-down-reason')}")
                        if af.get("ip-address"):
                            af_ip = af.get("ip-address")
                            af_plen = af.get("prefix-length", "")
                            output.print_line(f"    {'IP Address / Prefix':<22}: {af_ip}/{af_plen}")
                        output.print_line(f"    {'Passive':<22}: {af_pass}")
                        output.print_line(f"    {'Hello Interval':<22}: {af_hello}s")
                        output.print_line(f"    {'Hold Time':<22}: {af_hold}s")
                        output.print_line(f"    {'Split Horizon':<22}: {af_sh}")
                        output.print_line(f"    {'Next-Hop-Self':<22}: {af_nhs}")
                        af_auth = af.get("authentication")
                        if isinstance(af_auth, dict):
                            output.print_line(f"    {'Auth Mode':<22}: {af_auth.get('mode', 'none')}")
                        af_bfd = af.get("bfd")
                        if isinstance(af_bfd, dict):
                            output.print_line(f"    {'BFD Admin':<22}: {af_bfd.get('admin-state', 'disable')}")
                        af_bfd_st = af.get("bfd-state")
                        if isinstance(af_bfd_st, dict):
                            st = af_bfd_st.get("session-state", "disabled")
                            if "remote-address" in af_bfd_st:
                                st += f" (peer: {af_bfd_st['remote-address']})"
                            output.print_line(f"    {'BFD State':<22}: {st}")
                        sa_list = af.get("summary-address", [])
                        if sa_list:
                            sa_strs = [f"{s.get('prefix')} (dist: {s.get('distance', 5)})" for s in sa_list if s.get('prefix')]
                            output.print_line(f"    {'Summary Addresses':<22}: {', '.join(sa_strs)}")
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
            has_down = any(itf.get("oper-state", "Up").lower() != "up" for itf in interfaces)
            div_len = 122 if has_down else 96
            output.print_line("=" * div_len)
            output.print_line(f"EIGRP Interfaces for Network-Instance: {netinst} (AS: {asn})")
            output.print_line("-" * div_len)
            if has_down:
                output.print_line(f"{'Interface':<18} {'IP Address':<18} {'Prefix-Len':<12} {'Oper State':<12} {'Down Reason':<26} {'Passive':<9} {'BFD':<9} {'Auth':<8}")
            else:
                output.print_line(f"{'Interface':<18} {'IP Address':<18} {'Prefix-Len':<12} {'Oper State':<12} {'Passive':<10} {'BFD':<10} {'Auth':<10}")
            output.print_line("-" * div_len)

            if not interfaces:
                output.print_line("No active EIGRP interfaces found.")
            else:
                for itf in interfaces:
                    name = normalize_interface_name(itf.get("interface-name", itf.get("name", "")))
                    ip = itf.get("ip-address", "")
                    plen = str(itf.get("prefix-length", 32))
                    oper = itf.get("oper-state", "Up")
                    passive_str = "true" if itf.get("passive", False) else "false"
                    if passive_str == "false":
                        for af in itf.get("address-family", []):
                            if af.get("passive", False):
                                passive_str = "true"
                                break

                    bfd_raw = itf.get("bfd-state", "disabled")
                    if isinstance(bfd_raw, dict):
                        bfd = str(bfd_raw.get("session-state", "disabled"))
                    else:
                        bfd = str(bfd_raw)
                    if bfd == "disabled":
                        for af in itf.get("address-family", []):
                            af_bfd_st = af.get("bfd-state", {})
                            if isinstance(af_bfd_st, dict) and af_bfd_st.get("session-state") and af_bfd_st.get("session-state") != "disabled":
                                bfd = str(af_bfd_st.get("session-state"))
                                break

                    auth = str(itf.get("auth-mode", "none"))
                    if auth == "none":
                        auth_c = itf.get("authentication", {})
                        if isinstance(auth_c, dict) and auth_c.get("mode"):
                            auth = str(auth_c.get("mode"))
                    if auth == "none":
                        for af in itf.get("address-family", []):
                            af_auth = af.get("authentication", {})
                            if isinstance(af_auth, dict) and af_auth.get("mode") and af_auth.get("mode") != "none":
                                auth = str(af_auth.get("mode"))
                                break

                    if has_down:
                        down_rsn = itf.get("oper-down-reason", "") if oper.lower() != "up" else "-"
                        if not down_rsn and oper.lower() != "up":
                            if itf.get('admin-state') == 'disable':
                                down_rsn = "interface admin disabled"
                            elif not ip:
                                down_rsn = "no IP address configured"
                            else:
                                down_rsn = "link down or inactive"
                        output.print_line(f"{name:<18} {ip:<18} {plen:<12} {oper:<12} {down_rsn:<26} {passive_str:<9} {bfd:<9} {auth:<8}")
                    else:
                        output.print_line(f"{name:<18} {ip:<18} {plen:<12} {oper:<12} {passive_str:<10} {bfd:<10} {auth:<10}")

            output.print_line("-" * div_len)
            output.print_line(f"Total Interfaces: {len(interfaces)}")
            output.print_line("=" * div_len)

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

