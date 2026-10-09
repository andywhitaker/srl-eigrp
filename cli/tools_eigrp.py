#!/usr/bin/env python3
###########################################################################
# Nokia SR Linux CLI Plugin: EIGRP Operational Tools
# Supports:
#   tools network-instance <name> protocols eigrp neighbor clear <neighbor-ip>
#   tools network-instance <name> protocols eigrp neighbor reset-all
#   tools network-instance <name> protocols eigrp restart
#   tools network-instance <name> protocols eigrp check-cpm
###########################################################################
import ipaddress
import json
import os
import socket
from srlinux.location.build_path import build_path
from srlinux.mgmt.cli import RequiredPlugin, KeyCompleter
from srlinux.mgmt.cli.tools_plugin import ToolsPlugin
from srlinux.syntax import Syntax

IPC_SOCKET = "/var/run/srl_eigrpd_ipc.sock"


def _nbr_path(args):
    netinst = args.get_value_or("network-instance", "name", "*")
    return build_path(f"/network-instance[name={netinst}]/protocols/eigrp/neighbor[ip-address=*]")


def send_ipc(cmd):
    if not os.path.exists(IPC_SOCKET):
        return {"status": "error", "message": "srl-eigrpd daemon is not running"}
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(3.0)
    try:
        s.connect(IPC_SOCKET)
        s.sendall(json.dumps(cmd).encode() + b"\n")
        raw = s.recv(4096)
        if not raw:
            return {"status": "error", "message": "Empty response from daemon"}
        return json.loads(raw.decode())
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        s.close()


class Plugin(ToolsPlugin):
    """Adds EIGRP operational tools under 'tools network-instance <name> protocols eigrp'."""

    def get_required_plugins(self):
        return [
            RequiredPlugin("tools_mode"),
        ]

    def on_tools_load(self, state):
        root = state.command_tree.tools_mode.root
        netinst = root.get_command_or_none("network-instance")
        if not netinst:
            return
        proto = netinst.get_command_or_none("protocols")
        if not proto:
            return

        # Idempotent command registration prevents "Node 'eigrp' was added twice" collision
        eigrp = proto.get_command_or_none("eigrp")
        if not eigrp:
            eigrp = proto.add_command(
                Syntax("eigrp", help="EIGRP operational commands"),
                update_location=True
            )

        nbr = eigrp.get_command_or_none("neighbor")
        if not nbr:
            nbr = eigrp.add_command(
                Syntax("neighbor", help="Neighbor operations"),
                update_location=True
            )

        if not nbr.has_command("clear"):
            clear_syntax = Syntax("clear", help="Clear a specific neighbor adjacency")
            clear_syntax.add_unnamed_argument("peer-address", suggestions=KeyCompleter(path=_nbr_path))
            nbr.add_command(
                clear_syntax,
                update_location=False,
                callback=self.tools_clear_neighbor
            )

        if not nbr.has_command("reset-all"):
            nbr.add_command(
                Syntax("reset-all", help="Reset and clear all EIGRP neighbor adjacencies"),
                update_location=False,
                callback=self.tools_reset_all_neighbors
            )

        if not nbr.has_command("bfd-down"):
            bfd_syntax = Syntax("bfd-down", help="Simulate BFD session down transition for neighbor")
            bfd_syntax.add_unnamed_argument("peer-address", suggestions=KeyCompleter(path=_nbr_path))
            nbr.add_command(
                bfd_syntax,
                update_location=False,
                callback=self.tools_bfd_down
            )

        gr = eigrp.get_command_or_none("graceful-restart")
        if not gr:
            gr = eigrp.add_command(
                Syntax("graceful-restart", help="Graceful restart operations"),
                update_location=True
            )
        if not gr.has_command("planned-restart"):
            gr.add_command(
                Syntax("planned-restart", help="Trigger planned graceful restart"),
                update_location=False,
                callback=self.tools_planned_restart
            )

        if not eigrp.has_command("restart"):
            eigrp.add_command(
                Syntax("restart", help="Restart EIGRP protocol daemon"),
                update_location=False,
                callback=self.tools_restart
            )

        if not eigrp.has_command("check-cpm"):
            eigrp.add_command(
                Syntax("check-cpm", help="Verify control plane CPM filter acceptance of protocol 88"),
                update_location=False,
                callback=self.tools_check_cpm
            )

    def tools_clear_neighbor(self, state, output, arguments, **kwargs):
        netinst = "default"
        if hasattr(state, "line_commands") and state.line_commands.has_node("network-instance"):
            netinst = state.line_commands.get_node("network-instance").get_or("name", "default")

        peer = None
        if hasattr(arguments, "get_value_or"):
            peer = arguments.get_value_or("clear", "peer-address", None)
        if not peer and arguments.has_node("clear"):
            peer = arguments.get_node("clear").get_or("peer-address", None)
        if not peer and arguments.has_node("neighbor"):
            peer = arguments.get_node("neighbor").get_or("peer-address", None)

        if not peer or peer in ("*", "all"):
            output.print_line("Error: A specific neighbor IP address must be provided. Use 'neighbor reset-all' to clear all neighbors.")
            return

        try:
            ipaddress.ip_address(peer)
        except ValueError:
            output.print_line(f"Error: '{peer}' is not a valid IPv4 address or IPv6 address.")
            return

        cmd = {"action": "clear-neighbor", "netinst": netinst, "neighbor": peer}
        res = send_ipc(cmd)
        if res.get("status") == "ok":
            output.print_line(f"Success: {res.get('message', f'Cleared neighbor {peer}')}")
        else:
            output.print_line(f"Error: {res.get('message', 'Failed to clear neighbor')}")

    def tools_reset_all_neighbors(self, state, output, arguments, **kwargs):
        netinst = "default"
        if hasattr(state, "line_commands") and state.line_commands.has_node("network-instance"):
            netinst = state.line_commands.get_node("network-instance").get_or("name", "default")

        cmd = {"action": "clear-neighbor", "netinst": netinst, "neighbor": "all"}
        res = send_ipc(cmd)
        if res.get("status") == "ok":
            output.print_line(f"Success: {res.get('message', 'Cleared all neighbors')}")
        else:
            output.print_line(f"Error: {res.get('message', 'Failed to clear neighbors')}")

    def tools_bfd_down(self, state, output, arguments, **kwargs):
        netinst = "default"
        if hasattr(state, "line_commands") and state.line_commands.has_node("network-instance"):
            netinst = state.line_commands.get_node("network-instance").get_or("name", "default")

        peer = None
        if hasattr(arguments, "get_value_or"):
            peer = arguments.get_value_or("bfd-down", "peer-address", None)
        if not peer and arguments.has_node("bfd-down"):
            peer = arguments.get_node("bfd-down").get_or("peer-address", None)
        if not peer and arguments.has_node("neighbor"):
            peer = arguments.get_node("neighbor").get_or("peer-address", None)

        if not peer:
            output.print_line("Error: A specific neighbor IP address must be provided.")
            return

        cmd = {"action": "bfd-down", "netinst": netinst, "neighbor": peer}
        res = send_ipc(cmd)
        if res.get("status") == "ok":
            output.print_line(f"Success: {res.get('message', f'BFD down signaled for {peer}')}")
        else:
            output.print_line(f"Error: {res.get('message', 'Failed to signal BFD down')}")

    def tools_planned_restart(self, state, output, arguments, **kwargs):
        netinst = "default"
        if hasattr(state, "line_commands") and state.line_commands.has_node("network-instance"):
            netinst = state.line_commands.get_node("network-instance").get_or("name", "default")

        cmd = {"action": "planned-restart", "netinst": netinst}
        res = send_ipc(cmd)
        if res.get("status") == "ok":
            output.print_line(f"Success: {res.get('message', 'Planned graceful restart triggered')}")
        else:
            output.print_line(f"Error: {res.get('message', 'Failed to trigger planned restart')}")

    def tools_restart(self, state, output, arguments, **kwargs):
        netinst = "default"
        if hasattr(state, "line_commands") and state.line_commands.has_node("network-instance"):
            netinst = state.line_commands.get_node("network-instance").get_or("name", "default")

        res = send_ipc({"action": "restart", "netinst": netinst})
        if res.get("status") == "ok":
            output.print_line(f"Success: {res.get('message', 'EIGRP daemon restarted')}")
        else:
            output.print_line(f"Error: {res.get('message', 'Failed to restart')}")

    def tools_check_cpm(self, state, output, arguments, **kwargs):
        output.print_line("=" * 80)
        output.print_line("Verifying Control Plane Protection (CPM Filter) for EIGRP (IP Protocol 88)...")
        output.print_line("-" * 80)
        try:
            server = state.server_data_store
            # Check IPv4 filter
            path_v4 = build_path("/acl/acl-filter[name=cpm][type=ipv4]")
            data_v4_str = server.get_json(path_v4, recursive=True)
            if data_v4_str:
                data_v4 = json.loads(data_v4_str)
                has_proto_88_v4 = False
                for e in data_v4.get("entry", []):
                    match = e.get("match", {})
                    proto = match.get("protocol") or match.get("ipv4", {}).get("protocol")
                    action = e.get("action", {}).get("accept")
                    if (proto == 88 or proto == "88") and action is not None:
                        has_proto_88_v4 = True
                        seq = e.get("sequence-id", "?")
                        output.print_line(f"[OK] IPv4 Entry {seq}: action accept, match protocol 88.")
                        break
                if has_proto_88_v4:
                    output.print_line("[OK] Inbound IPv4 protocol 88 packets are accepted by CPM filter 'cpm'.")
                else:
                    output.print_line("[WARNING] CPM filter 'cpm' does NOT have an accept entry for IPv4 protocol 88!")
            else:
                output.print_line("[WARNING] IPv4 CPM filter 'cpm' not found.")

            # Check IPv6 filter
            path_v6 = build_path("/acl/acl-filter[name=cpm][type=ipv6]")
            data_v6_str = server.get_json(path_v6, recursive=True)
            if data_v6_str:
                data_v6 = json.loads(data_v6_str)
                has_proto_88_v6 = False
                for e in data_v6.get("entry", []):
                    match = e.get("match", {})
                    proto = match.get("next-header") or match.get("protocol") or match.get("ipv6", {}).get("next-header")
                    action = e.get("action", {}).get("accept")
                    if (proto == 88 or proto == "88") and action is not None:
                        has_proto_88_v6 = True
                        seq = e.get("sequence-id", "?")
                        output.print_line(f"[OK] IPv6 Entry {seq}: action accept, match next-header 88.")
                        break
                if has_proto_88_v6:
                    output.print_line("[OK] Inbound IPv6 next-header 88 packets are accepted by CPM filter 'cpm'.")
                else:
                    output.print_line("[WARNING] CPM filter 'cpm' does NOT have an accept entry for IPv6 next-header 88!")
            else:
                output.print_line("[INFO] IPv6 CPM filter 'cpm' not found.")
        except Exception as e:
            output.print_line(f"Status check error: {e}")
        output.print_line("=" * 80)
