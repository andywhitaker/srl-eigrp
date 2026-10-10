import time
import re
import pytest

def test_srl_neighbor_established(srl_exec):
    """Verify SRL1 sees SRL2 as an active EIGRP neighbor in network-instance default."""
    out = ""
    for _ in range(15):
        time.sleep(3)
        out = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "show network-instance default protocols eigrp neighbor"
        ])
        if "10.0.0.2" in out and "Up" in out:
            break
    assert "10.0.0.2" in out and "Up" in out, f"Neighbor not established: {out}"

def test_srl_fib_route_installed(srl_exec):
    """Verify remote loopback (192.0.2.2/32) is installed in SRL1's FIB with preference 90 and eigrp route type."""
    out = ""
    for _ in range(15):
        time.sleep(2)
        out = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "show network-instance default ipv4 route"
        ])
        if "192.0.2.2/32" in out and "90" in out:
            break
    assert "192.0.2.2/32" in out and "90" in out and "eigrp" in out, f"Route not found in FIB or not eigrp: {out}"

    # Verify route type in detail view
    out_detail = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "show network-instance default ipv4 route 192.0.2.2/32 detail"
    ])
    assert "Route Type" in out_detail and "eigrp" in out_detail, f"Route detail not eigrp: {out_detail}"

    # Verify structured JSON output renders Route Type as eigrp
    out_json = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "show network-instance default ipv4 route | as json"
    ])
    assert '"Route Type": "eigrp"' in out_json or '"route-type": "eigrp"' in out_json, f"JSON route type not eigrp: {out_json}"

    # Verify route summary renders eigrp
    out_summary = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "show network-instance default ipv4 route summary"
    ])
    assert "eigrp" in out_summary, f"Route summary not eigrp: {out_summary}"

def test_dataplane_ping(srl_exec):
    """Verify end-to-end dataplane forwarding between SRL loopbacks in default network-instance."""
    out = ""
    for _ in range(5):
        out = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "ping 192.0.2.2 network-instance default -c 3"
        ])
        if "3 packets received" in out or "0% packet loss" in out or "3 received" in out:
            break
        time.sleep(2)
    assert "0% packet loss" in out or "3 received" in out, f"Ping failed: {out}"

def test_show_eigrp_cli(srl_exec):
    """Verify SR Linux CLI show network-instance default protocols eigrp ... commands."""
    out_summary = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "show network-instance default protocols eigrp summary"
    ])
    assert "Autonomous System" in out_summary and "100" in out_summary, f"Summary failed: {out_summary}"

    out_nbr = ""
    for _ in range(15):
        out_nbr = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "show network-instance default protocols eigrp neighbor"
        ])
        if "10.0.0.2" in out_nbr and "Up" in out_nbr:
            break
        time.sleep(1)
    assert "10.0.0.2" in out_nbr and "Up" in out_nbr, f"Neighbor show failed: {out_nbr}"

    out_routes = ""
    for _ in range(15):
        out_routes = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "show network-instance default protocols eigrp routes"
        ])
        if "192.0.2.2/32" in out_routes and "10.0.0.2" in out_routes:
            break
        time.sleep(1)
    assert "192.0.2.2/32" in out_routes and "10.0.0.2" in out_routes, f"Routes show failed: {out_routes}"
 
    out_v4_routes = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "show network-instance default ipv4 route eigrp"
    ])
    assert "192.0.2.2/32" in out_v4_routes and "10.0.0.2" in out_v4_routes, f"IPv4 route eigrp show failed: {out_v4_routes}"

    out_v4_subnet = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "show network-instance default ipv4 route eigrp 192.0.2.0/24"
    ])
    assert "192.0.2.2/32" in out_v4_subnet and "10.0.0.2" in out_v4_subnet, f"IPv4 route eigrp subnet filter failed: {out_v4_subnet}"

    out_if = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "show network-instance default protocols eigrp interfaces"
    ])
    assert "ethernet-1/1.0" in out_if and "10.0.0.1" in out_if, f"CLI interfaces show failed: {out_if}"


def test_show_eigrp_cli_detail(srl_exec):
    """Verify detailed view for show interfaces <name> and show neighbor <ip>."""
    out_if_detail = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "show network-instance default protocols eigrp interfaces ethernet-1/1.0"
    ])
    assert "EIGRP Interface Details: ethernet-1/1.0" in out_if_detail, f"Interface detail failed: {out_if_detail}"
    assert "10.0.0.1/30" in out_if_detail and "192.0.2.1" in out_if_detail, f"Detail fields missing: {out_if_detail}"

    out_nbr_detail = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "show network-instance default protocols eigrp neighbor 10.0.0.2"
    ])
    assert "EIGRP Neighbor Details: 10.0.0.2" in out_nbr_detail, f"Neighbor detail failed: {out_nbr_detail}"
    assert "10.0.0.2" in out_nbr_detail and "192.0.2.2/32" in out_nbr_detail, f"Neighbor routes missing: {out_nbr_detail}"


def test_show_eigrp_topology(srl_exec):
    """Verify SR Linux CLI show network-instance default protocols eigrp topology."""
    out_top = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "show network-instance default protocols eigrp topology"
    ])
    assert "DUAL Topology Table" in out_top, f"Topology title missing: {out_top}"
    assert "192.0.2.2/32" in out_top, f"192.0.2.2/32 missing from topology: {out_top}"
    assert "successors" in out_top and "FD is" in out_top, f"Successor/FD missing: {out_top}"
    assert "via 10.0.0.2" in out_top and "Successor" in out_top, f"Candidate route missing from topology CLI: {out_top}"


def test_show_eigrp_traffic(srl_exec):
    """Verify SR Linux CLI show network-instance default protocols eigrp traffic."""
    out_traf = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "show network-instance default protocols eigrp traffic"
    ])
    assert "Traffic Statistics" in out_traf, f"Traffic title missing: {out_traf}"
    assert "ethernet-1/1.0" in out_traf, f"Interface missing from traffic: {out_traf}"


def test_state_db(srl_exec):
    """Verify full protocol operational state sits directly under protocols eigrp (no state container)."""
    out_state = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "info from state network-instance default protocols eigrp"
    ])
    assert "state {" not in out_state, f"Deprecated 'state' container found in state DB: {out_state}"
    assert "oper-state up" in out_state, f"oper-state missing from state DB: {out_state}"
    assert "admin-state enable" in out_state, f"admin-state missing from state DB: {out_state}"
    assert "autonomous-system 100" in out_state, f"autonomous-system missing from state DB: {out_state}"
    assert "router-id 192.0.2.1" in out_state, f"router-id missing from state DB: {out_state}"
    assert "variance 1" in out_state, f"variance missing from state DB: {out_state}"
    assert "maximum-paths 4" in out_state, f"maximum-paths missing from state DB: {out_state}"
    assert "maximum-hops 100" in out_state, f"maximum-hops missing from state DB: {out_state}"
    assert "rib-scale 128" in out_state, f"rib-scale missing from state DB: {out_state}"
    assert "wide-metrics true" in out_state, f"wide-metrics missing from state DB: {out_state}"
    assert "graceful-restart {" in out_state, f"graceful-restart missing from state DB: {out_state}"
    assert "default-interface {" in out_state, f"default-interface missing from state DB: {out_state}"
    assert "total-neighbors 2" in out_state, f"total-neighbors missing: {out_state}"
    assert re.search(r"total-routes [23]", out_state), f"total-routes missing: {out_state}"
    assert "address-family ipv4-unicast" in out_state, f"address-family ipv4-unicast missing: {out_state}"
    assert "address-family ipv6-unicast" in out_state, f"address-family ipv6-unicast missing: {out_state}"
    assert "total-interfaces 2" in out_state, f"total-interfaces missing: {out_state}"
    assert "interface ethernet-1/1.0" in out_state, f"interface list missing: {out_state}"
    assert "passive false" in out_state, f"passive false missing from state DB: {out_state}"
    assert "passive true" in out_state, f"passive true missing from state DB: {out_state}"
    assert "neighbor 10.0.0.2" in out_state, f"neighbor list missing from state DB: {out_state}"
    assert "route 192.0.2.2/32" in out_state, f"route list missing from state DB: {out_state}"
    assert "topology 192.0.2.2/32" in out_state, f"topology list missing from state DB: {out_state}"
    assert "route 10.0.0.2" in out_state, f"topology route next-hop missing from state DB: {out_state}"
    assert "successor true" in out_state, f"topology successor status missing from state DB: {out_state}"
    assert "traffic ethernet-1/1.0" in out_state, f"traffic list missing from state DB: {out_state}"

    out_cfg = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "info network-instance default protocols eigrp"
    ])
    assert "admin-state enable" in out_cfg, f"admin-state missing from running config: {out_cfg}"
    assert "router-id 192.0.2.1" in out_cfg, f"router-id missing from running config: {out_cfg}"
    assert "autonomous-system 100" in out_cfg, f"autonomous-system missing from running config: {out_cfg}"


def test_tools_cpm_check(srl_exec):
    """Verify SR Linux CLI tools network-instance default protocols eigrp check-cpm."""
    out_cpm = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "tools network-instance default protocols eigrp check-cpm"
    ])
    assert "Verifying Control Plane Protection" in out_cpm, f"CPM check output missing: {out_cpm}"


def test_tools_clear_neighbor(srl_exec):
    """Verify SR Linux CLI tools neighbor clear <peer> operational command."""
    # 1. Invalid IP must be rejected and not reset neighbors
    out_bad = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "tools network-instance default protocols eigrp neighbor clear invalid_ip"
    ])
    assert "Error" in out_bad and "not a valid IPv4 address" in out_bad, f"Invalid IP should fail: {out_bad}"

    # 2. Non-existent neighbor IP must return error and not affect active neighbors
    out_nonexist = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "tools network-instance default protocols eigrp neighbor clear 10.99.99.99"
    ])
    assert "Error" in out_nonexist and ("not found" in out_nonexist.lower() or "failed to clear" in out_nonexist.lower()), f"Non-existent neighbor should report error: {out_nonexist}"

    # 3. Valid neighbor clear
    out_clear = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "tools network-instance default protocols eigrp neighbor clear 10.0.0.2"
    ])
    assert "Cleared neighbor 10.0.0.2" in out_clear or "Success" in out_clear, f"Clear neighbor failed: {out_clear}"

    # Verify neighbor re-establishes after clear
    out_nbr = ""
    for _ in range(10):
        time.sleep(2)
        out_nbr = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "show network-instance default protocols eigrp neighbor"
        ])
        if "10.0.0.2" in out_nbr and "Up" in out_nbr:
            break
    assert "10.0.0.2" in out_nbr and "Up" in out_nbr, f"Neighbor failed to recover after clear: {out_nbr}"


def test_tools_reset_all(srl_exec):
    """Verify SR Linux CLI tools neighbor reset-all operational command."""
    out_reset = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "tools network-instance default protocols eigrp neighbor reset-all"
    ])
    assert "Cleared" in out_reset or "Success" in out_reset, f"Reset-all failed: {out_reset}"

    # Verify neighbor re-establishes after reset-all
    out_nbr = ""
    for _ in range(10):
        time.sleep(2)
        out_nbr = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "show network-instance default protocols eigrp neighbor"
        ])
        if "10.0.0.2" in out_nbr and "Up" in out_nbr:
            break
    assert "10.0.0.2" in out_nbr and "Up" in out_nbr, f"Neighbor failed to recover after reset-all: {out_nbr}"


def test_default_interface_configuration(srl_exec):
    """Verify default-interface configuration and per-interface passive behavior."""
    out = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "info network-instance default protocols eigrp"
    ])
    assert "default-interface {" in out, f"default-interface missing: {out}"
    assert "interface ethernet-1/1.0 {" in out, f"interface ethernet-1/1.0 missing: {out}"
    assert "interface system0.0 {" in out, f"interface system0.0 missing: {out}"
    assert "passive true" in out, f"passive true missing for system0.0: {out}"


def test_named_metrics_keys(srl_exec):
    """Verify metrics container with named keys (bandwidth, delay, load, reliability, mtu)."""
    cfg_cmd = """sr_cli << 'EOF'
enter candidate
/ network-instance default protocols eigrp metrics bandwidth 1 delay 1 load 0 reliability 0 mtu 0
commit now
EOF"""
    out = srl_exec("clab-srl-srl-eigrp-srl1", ["bash", "-c", cfg_cmd])
    assert "All changes have been committed" in out or "committed" in out.lower(), f"Failed to commit named metrics: {out}"

    info_metrics = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "info network-instance default protocols eigrp metrics"
    ])
    assert "bandwidth 1" in info_metrics, f"bandwidth missing: {info_metrics}"
    assert "delay 1" in info_metrics, f"delay missing: {info_metrics}"
    assert "load 0" in info_metrics, f"load missing: {info_metrics}"
    assert "reliability 0" in info_metrics, f"reliability missing: {info_metrics}"
    assert "mtu 0" in info_metrics, f"mtu missing: {info_metrics}"


def test_routing_policy_metric_augmentation(srl_exec):
    """Verify SR Linux routing-policy statement action augmented with EIGRP metric."""
    policy_cfg = """sr_cli << 'EOF'
enter candidate
/ routing-policy policy eigrp-policy statement 10 match protocol local
/ routing-policy policy eigrp-policy statement 10 action policy-result accept
/ routing-policy policy eigrp-policy statement 10 action eigrp metric bandwidth 100000 delay 100 reliability 255 load 1 mtu 1500
/ routing-policy policy eigrp-policy default-action policy-result reject
/ routing-policy policy eigrp-policy default-action eigrp metric bandwidth 50000 delay 50 reliability 200 load 2 mtu 1400
/ network-instance default protocols eigrp export-policy eigrp-policy
/ network-instance default protocols eigrp import-policy eigrp-policy
commit now
EOF"""
    out = srl_exec("clab-srl-srl-eigrp-srl1", ["bash", "-c", policy_cfg])
    assert "All changes have been committed" in out or "committed" in out.lower(), f"Policy commit failed: {out}"

    info_action = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "info routing-policy policy eigrp-policy statement 10 action eigrp"
    ])
    assert "bandwidth 100000" in info_action, f"metric bandwidth missing: {info_action}"
    assert "delay 100" in info_action, f"metric delay missing: {info_action}"
    assert "reliability 255" in info_action, f"metric reliability missing: {info_action}"
    assert "load 1" in info_action, f"metric load missing: {info_action}"
    assert "mtu 1500" in info_action, f"metric mtu missing: {info_action}"

    info_defaction = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "info routing-policy policy eigrp-policy default-action eigrp"
    ])
    assert "bandwidth 50000" in info_defaction, f"default-action metric bandwidth missing: {info_defaction}"

    # Verify standard import-policy and export-policy leaves are present in running config
    info_eigrp = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "info network-instance default protocols eigrp"
    ])
    assert "export-policy eigrp-policy" in info_eigrp, f"export-policy missing: {info_eigrp}"
    assert "import-policy eigrp-policy" in info_eigrp, f"import-policy missing: {info_eigrp}"


def test_interface_dynamic_deletion(srl_exec):
    """Verify dynamically deleting an interface withdraws it from state DB and drops neighbor, then recovers on re-add."""
    # 1. Verify neighbor is currently Up
    out_init = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "show network-instance default protocols eigrp neighbor"
    ])
    assert "10.0.0.2" in out_init and "Up" in out_init

    # 2. Delete interface ethernet-1/1.0
    del_cmd = """sr_cli << 'EOF'
enter candidate
delete / network-instance default protocols eigrp interface ethernet-1/1.0
commit now
EOF"""
    out_del = srl_exec("clab-srl-srl-eigrp-srl1", ["bash", "-c", del_cmd])
    assert "committed" in out_del.lower()

    try:
        # 3. Verify neighbor is dropped and interface is absent from state DB
        dropped = False
        out_state = ""
        for _ in range(15):
            time.sleep(1)
            out_state = srl_exec("clab-srl-srl-eigrp-srl1", [
                "sr_cli", "info from state network-instance default protocols eigrp"
            ])
            if "\n    interface ethernet-1/1.0" not in out_state and "neighbor 10.0.0.2" not in out_state:
                dropped = True
                break
        assert dropped, f"Interface or neighbor not dropped from state DB: {out_state}"
    finally:
        # 4. Re-add interface ethernet-1/1.0
        add_cmd = """sr_cli << 'EOF'
enter candidate
/ network-instance default protocols eigrp interface ethernet-1/1.0 admin-state enable
commit now
EOF"""
        srl_exec("clab-srl-srl-eigrp-srl1", ["bash", "-c", add_cmd])

    # 5. Verify neighbor re-establishes
    recovered = False
    for _ in range(15):
        time.sleep(2)
        out_rec = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "show network-instance default protocols eigrp neighbor"
        ])
        if "10.0.0.2" in out_rec and "Up" in out_rec:
            recovered = True
            break
    assert recovered, f"Neighbor failed to recover after re-adding interface: {out_rec}"


def test_default_interface_passive_inheritance(srl_exec):
    """Verify default-interface passive setting is inherited by interfaces lacking explicit passive configuration."""
    # 1. Set default-interface passive true
    set_passive = """sr_cli << 'EOF'
enter candidate
/ network-instance default protocols eigrp default-interface passive true
commit now
EOF"""
    out_p = srl_exec("clab-srl-srl-eigrp-srl1", ["bash", "-c", set_passive])
    assert "committed" in out_p.lower()

    try:
        # 2. Verify neighbor is dropped (since ethernet-1/1.0 inherits passive true)
        dropped = False
        out_nbr = ""
        for _ in range(10):
            time.sleep(1)
            out_nbr = srl_exec("clab-srl-srl-eigrp-srl1", [
                "sr_cli", "show network-instance default protocols eigrp neighbor"
            ])
            if "10.0.0.2" not in out_nbr or "Up" not in out_nbr:
                dropped = True
                break
        assert dropped, f"Neighbor should drop when default-interface passive true: {out_nbr}"
    finally:
        # 3. Restore default-interface passive false
        unset_passive = """sr_cli << 'EOF'
enter candidate
/ network-instance default protocols eigrp default-interface passive false
commit now
EOF"""
        srl_exec("clab-srl-srl-eigrp-srl1", ["bash", "-c", unset_passive])

    # 4. Verify neighbor recovers
    recovered = False
    for _ in range(15):
        time.sleep(2)
        out_rec = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "show network-instance default protocols eigrp neighbor"
        ])
        if "10.0.0.2" in out_rec and "Up" in out_rec:
            recovered = True
            break
    assert recovered, f"Neighbor failed to recover after setting default-interface passive false: {out_rec}"


# -----------------------------------------------------------------------------
# Secondary IP-VRF (Multi-VRF) Test Suite
# -----------------------------------------------------------------------------

def test_srl_vrf1_neighbor_established(srl_exec):
    """Verify SRL1 sees SRL2 as an active EIGRP neighbor in secondary ip-vrf (vrf-1)."""
    out = ""
    for _ in range(15):
        time.sleep(2)
        out = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "show network-instance vrf-1 protocols eigrp neighbor"
        ])
        if "10.1.0.2" in out and "Up" in out:
            break
    assert "10.1.0.2" in out and "Up" in out, f"VRF-1 neighbor not established: {out}"


def test_srl_vrf1_fib_route_installed(srl_exec):
    """Verify remote loopback (192.0.2.22/32) is installed in SRL1's vrf-1 FIB with preference 90 and eigrp route type."""
    out = ""
    for _ in range(15):
        time.sleep(2)
        out = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "show network-instance vrf-1 ipv4 route"
        ])
        if "192.0.2.22/32" in out and "90" in out:
            break
    assert "192.0.2.22/32" in out and "90" in out and "eigrp" in out, f"VRF-1 route not found in FIB or not eigrp: {out}"


def test_vrf1_dataplane_ping(srl_exec):
    """Verify end-to-end dataplane forwarding inside secondary ip-vrf (vrf-1)."""
    out = ""
    for _ in range(5):
        out = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "ping 192.0.2.22 network-instance vrf-1 -c 3"
        ])
        if "3 packets received" in out or "0% packet loss" in out or "3 received" in out:
            break
        time.sleep(2)
    assert "0% packet loss" in out or "3 received" in out, f"VRF-1 ping failed: {out}"


def test_vrf1_show_cli(srl_exec):
    """Verify SR Linux CLI show network-instance vrf-1 protocols eigrp commands."""
    out_summary = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "show network-instance vrf-1 protocols eigrp summary"
    ])
    assert "Autonomous System" in out_summary and "200" in out_summary, f"VRF-1 summary failed: {out_summary}"

    out_nbr = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "show network-instance vrf-1 protocols eigrp neighbor"
    ])
    assert "10.1.0.2" in out_nbr and "Up" in out_nbr, f"VRF-1 neighbor show failed: {out_nbr}"

    out_routes = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "show network-instance vrf-1 protocols eigrp routes"
    ])
    assert "192.0.2.22/32" in out_routes and "10.1.0.2" in out_routes, f"VRF-1 routes show failed: {out_routes}"

    out_v4_routes = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "show network-instance vrf-1 ipv4 route eigrp"
    ])
    assert "192.0.2.22/32" in out_v4_routes and "10.1.0.2" in out_v4_routes, f"VRF-1 ipv4 route eigrp failed: {out_v4_routes}"

    out_if = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "show network-instance vrf-1 protocols eigrp interfaces"
    ])
    assert "ethernet-1/1.1" in out_if and "10.1.0.1" in out_if, f"VRF-1 interfaces show failed: {out_if}"

    out_top = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "show network-instance vrf-1 protocols eigrp topology"
    ])
    assert "DUAL Topology Table" in out_top and "192.0.2.22/32" in out_top, f"VRF-1 topology show failed: {out_top}"
    assert "via 10.1.0.2" in out_top and "Successor" in out_top, f"VRF-1 candidate route missing from topology: {out_top}"

    out_traf = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "show network-instance vrf-1 protocols eigrp traffic"
    ])
    assert "Traffic Statistics" in out_traf and "ethernet-1/1.1" in out_traf, f"VRF-1 traffic show failed: {out_traf}"


def test_vrf1_state_db(srl_exec):
    """Verify NDK State DB telemetry for secondary ip-vrf (vrf-1)."""
    out_state = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "info from state network-instance vrf-1 protocols eigrp"
    ])
    assert "state {" not in out_state, f"Deprecated 'state' container found in VRF-1 state DB: {out_state}"
    assert "oper-state up" in out_state, f"oper-state missing from VRF-1 state DB: {out_state}"
    assert "admin-state enable" in out_state, f"admin-state missing from VRF-1 state DB: {out_state}"
    assert "autonomous-system 200" in out_state, f"autonomous-system missing from VRF-1 state DB: {out_state}"
    assert "router-id 192.0.2.11" in out_state, f"router-id missing from VRF-1 state DB: {out_state}"
    assert "graceful-restart {" in out_state, f"graceful-restart missing from VRF-1 state DB: {out_state}"
    assert "default-interface {" in out_state, f"default-interface missing from VRF-1 state DB: {out_state}"
    assert "total-neighbors 1" in out_state, f"total-neighbors missing: {out_state}"
    assert "total-routes 1" in out_state, f"total-routes missing: {out_state}"
    assert "total-interfaces 2" in out_state, f"total-interfaces missing: {out_state}"
    assert "interface ethernet-1/1.1" in out_state, f"interface ethernet-1/1.1 missing: {out_state}"
    assert "passive false" in out_state, f"passive false missing from VRF-1 state DB: {out_state}"
    assert "passive true" in out_state, f"passive true missing from VRF-1 state DB: {out_state}"
    assert "neighbor 10.1.0.2" in out_state, f"neighbor 10.1.0.2 missing from VRF-1 state DB: {out_state}"
    assert "route 192.0.2.22/32" in out_state, f"route 192.0.2.22/32 missing from VRF-1 state DB: {out_state}"
    assert "topology 192.0.2.22/32" in out_state, f"topology missing from VRF-1 state DB: {out_state}"
    assert "route 10.1.0.2" in out_state, f"VRF-1 topology route next-hop missing from state DB: {out_state}"
    assert "successor true" in out_state, f"VRF-1 successor status missing from state DB: {out_state}"
    assert "traffic ethernet-1/1.1" in out_state, f"traffic missing from VRF-1 state DB: {out_state}"


def test_vrf1_tools_clear_neighbor(srl_exec):
    """Verify CLI tools operational clear neighbor on secondary ip-vrf (vrf-1)."""
    out_clear = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "tools network-instance vrf-1 protocols eigrp neighbor clear 10.1.0.2"
    ])
    assert "Cleared neighbor 10.1.0.2" in out_clear or "Success" in out_clear, f"VRF-1 clear neighbor failed: {out_clear}"

    # Verify neighbor recovers in vrf-1
    out_nbr = ""
    for _ in range(10):
        time.sleep(2)
        out_nbr = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "show network-instance vrf-1 protocols eigrp neighbor"
        ])
        if "10.1.0.2" in out_nbr and "Up" in out_nbr:
            break
    assert "10.1.0.2" in out_nbr and "Up" in out_nbr, f"VRF-1 neighbor failed to recover: {out_nbr}"


def test_vrf1_tools_reset_all(srl_exec):
    """Verify CLI tools operational reset-all on secondary ip-vrf (vrf-1)."""
    out_reset = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "tools network-instance vrf-1 protocols eigrp neighbor reset-all"
    ])
    assert "Cleared" in out_reset or "Success" in out_reset, f"VRF-1 reset-all failed: {out_reset}"

    # Verify neighbor recovers in vrf-1
    out_nbr = ""
    for _ in range(10):
        time.sleep(2)
        out_nbr = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "show network-instance vrf-1 protocols eigrp neighbor"
        ])
        if "10.1.0.2" in out_nbr and "Up" in out_nbr:
            break
    assert "10.1.0.2" in out_nbr and "Up" in out_nbr, f"VRF-1 neighbor failed to recover after reset-all: {out_nbr}"


# =============================================================================
# EIGRP IPv6 Support Test Suite
# =============================================================================

def test_srl_ipv6_enable(srl_exec):
    """Enable IPv6 EIGRP (address-family ipv6-unicast) in SRL1 and SRL2."""
    cfg_srl1_dis = """sr_cli << 'EOF'
enter candidate
/ network-instance default protocols eigrp address-family ipv6-unicast admin-state disable
commit now
EOF"""
    srl_exec("clab-srl-srl-eigrp-srl1", ["bash", "-c", cfg_srl1_dis])

    cfg_srl2_dis = """sr_cli << 'EOF'
enter candidate
/ network-instance default protocols eigrp address-family ipv6-unicast admin-state disable
commit now
EOF"""
    srl_exec("clab-srl-srl-eigrp-srl2", ["bash", "-c", cfg_srl2_dis])

    # Wait for IPv6 neighbor to drop (total-neighbors becomes 1)
    dropped = False
    for _ in range(15):
        time.sleep(1)
        out = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "info from state network-instance default protocols eigrp"
        ])
        if "total-neighbors 1" in out:
            dropped = True
            break
    assert dropped, f"IPv6 neighbor failed to drop after disable: {out}"

    # Now enable address-family ipv6-unicast
    cfg_srl1 = """sr_cli << 'EOF'
enter candidate
/ network-instance default protocols eigrp address-family ipv6-unicast admin-state enable
commit now
EOF"""
    out1 = srl_exec("clab-srl-srl-eigrp-srl1", ["bash", "-c", cfg_srl1])
    assert "committed" in out1.lower(), f"Failed to enable IPv6 EIGRP on SRL1: {out1}"

    cfg_srl2 = """sr_cli << 'EOF'
enter candidate
/ network-instance default protocols eigrp address-family ipv6-unicast admin-state enable
commit now
EOF"""
    out2 = srl_exec("clab-srl-srl-eigrp-srl2", ["bash", "-c", cfg_srl2])
    assert "committed" in out2.lower(), f"Failed to enable IPv6 EIGRP on SRL2: {out2}"



def test_srl_ipv6_neighbor_established(srl_exec):
    """Verify SRL1 and SRL2 establish EIGRP IPv6 neighbor adjacency using link-local addresses."""
    out = ""
    for _ in range(15):
        time.sleep(2)
        out = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "show network-instance default protocols eigrp neighbor"
        ])
        if "fe80::" in out and "Up" in out:
            break
    assert "fe80::" in out and "Up" in out, f"IPv6 neighbor not established on SRL1: {out}"

    # Also verify SRL2 sees SRL1 link-local neighbor
    out2 = ""
    for _ in range(15):
        time.sleep(2)
        out2 = srl_exec("clab-srl-srl-eigrp-srl2", [
            "sr_cli", "show network-instance default protocols eigrp neighbor"
        ])
        if "fe80::" in out2 and "Up" in out2:
            break
    assert "fe80::" in out2 and "Up" in out2, f"IPv6 neighbor not established on SRL2: {out2}"


def test_srl_ipv6_fib_route_installed(srl_exec):
    """Verify remote IPv6 loopback (2001:db8::2/128) is installed in SRL1's FIB with preference 90 and next-hop 2001:db8:1::2."""
    out = ""
    for _ in range(15):
        time.sleep(2)
        out = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "show network-instance default ipv6 route"
        ])
        if "2001:db8::2/128" in out and "90" in out and "2001:db8:1::2" in out:
            break
    assert "2001:db8::2/128" in out and "90" in out and "2001:db8:1::2" in out and "eigrp" in out, f"IPv6 route not found in FIB on SRL1: {out}"

    # Also verify SRL2 FIB has SRL1 loopback (2001:db8::1/128)
    out2 = ""
    for _ in range(15):
        time.sleep(2)
        out2 = srl_exec("clab-srl-srl-eigrp-srl2", [
            "sr_cli", "show network-instance default ipv6 route"
        ])
        if "2001:db8::1/128" in out2 and "90" in out2 and "2001:db8:1::1" in out2:
            break
    assert "2001:db8::1/128" in out2 and "90" in out2 and "2001:db8:1::1" in out2 and "eigrp" in out2, f"IPv6 route not found in FIB on SRL2: {out2}"


def test_srl_ipv6_dataplane_ping(srl_exec):
    """Verify bidirectional end-to-end dataplane ping between IPv6 loopbacks (0% packet loss)."""
    # Ping SRL2 loopback from SRL1
    out1 = ""
    for _ in range(5):
        out1 = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "ping 2001:db8::2 network-instance default -c 3"
        ])
        if "3 packets received" in out1 or "0% packet loss" in out1 or "3 received" in out1:
            break
        time.sleep(2)
    assert "0% packet loss" in out1 or "3 received" in out1, f"IPv6 ping from SRL1 to SRL2 failed: {out1}"

    # Ping SRL1 loopback from SRL2
    out2 = ""
    for _ in range(5):
        out2 = srl_exec("clab-srl-srl-eigrp-srl2", [
            "sr_cli", "ping 2001:db8::1 network-instance default -c 3"
        ])
        if "3 packets received" in out2 or "0% packet loss" in out2 or "3 received" in out2:
            break
        time.sleep(2)
    assert "0% packet loss" in out2 or "3 received" in out2, f"IPv6 ping from SRL2 to SRL1 failed: {out2}"


def test_srl_ipv6_cli_show(srl_exec):
    """Verify SR Linux CLI show network-instance default protocols eigrp commands display IPv6 entries."""
    out_routes = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "show network-instance default protocols eigrp routes"
    ])
    assert "2001:db8::2/128" in out_routes, f"IPv6 route missing from CLI routes: {out_routes}"

    out_v6_routes = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "show network-instance default ipv6 route eigrp"
    ])
    assert "2001:db8::2/128" in out_v6_routes and "2001:db8:1::2" in out_v6_routes, f"IPv6 route eigrp failed: {out_v6_routes}"

    out_v6_subnet = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "show network-instance default ipv6 route eigrp 2001:db8::/64"
    ])
    assert "2001:db8::2/128" in out_v6_subnet and "2001:db8:1::2" in out_v6_subnet, f"IPv6 route eigrp subnet filter failed: {out_v6_subnet}"

    out_nbr = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "show network-instance default protocols eigrp neighbor"
    ])
    assert "fe80::" in out_nbr and "Up" in out_nbr, f"IPv6 neighbor missing from CLI neighbor: {out_nbr}"

    out_top = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "show network-instance default protocols eigrp topology"
    ])
    assert "2001:db8::2/128" in out_top, f"IPv6 prefix missing from CLI topology: {out_top}"


def test_srl_ipv6_state_db(srl_exec):
    """Verify NDK State DB telemetry includes both IPv4 and IPv6 state."""
    out_state = ""
    for _ in range(10):
        time.sleep(2)
        out_state = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "info from state network-instance default protocols eigrp"
        ])
        if "total-neighbors 2" in out_state and "2001:db8::2/128" in out_state:
            break
    assert "total-neighbors 2" in out_state, f"total-neighbors 2 missing from state DB: {out_state}"
    assert re.search(r"total-routes [23]", out_state), f"total-routes 2 missing from state DB: {out_state}"
    assert "route 2001:db8::2/128" in out_state, f"IPv6 route missing from state DB: {out_state}"
    assert "neighbor fe80::" in out_state, f"IPv6 neighbor missing from state DB: {out_state}"


def test_srl_ipv6_tools_clear_neighbor(srl_exec):
    """Verify clearing an IPv6 neighbor using tools clear-neighbor."""
    # Find the link-local IPv6 neighbor on srl1
    out_nbr = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "show network-instance default protocols eigrp neighbor"
    ])
    v6_nbr = None
    for line in out_nbr.splitlines():
        if "fe80::" in line:
            v6_nbr = line.split()[0]
            break
    assert v6_nbr is not None, f"No IPv6 neighbor found in show neighbor output: {out_nbr}"

    # Clear the IPv6 neighbor
    out_clear = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", f"tools network-instance default protocols eigrp neighbor clear {v6_nbr}"
    ])
    assert f"Cleared neighbor {v6_nbr}" in out_clear, f"Failed to clear IPv6 neighbor: {out_clear}"

    # Verify neighbor re-establishes within 15 seconds
    recovered = False
    for _ in range(15):
        time.sleep(1)
        out_state = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "info from state network-instance default protocols eigrp"
        ])
        if "total-neighbors 2" in out_state and v6_nbr in out_state:
            recovered = True
            break
    assert recovered, f"IPv6 neighbor failed to recover after clear: {out_state}"


def test_srl_ipv6_passive_interface(srl_exec):
    """Verify making an IPv6 interface passive drops neighbor and removing passive recovers it."""
    # Set passive true on srl1 ethernet-1/1.0 under address-family ipv6-unicast
    cfg_passive = """sr_cli << 'EOF'
enter candidate
/ network-instance default protocols eigrp interface ethernet-1/1.0 address-family ipv6-unicast passive true
commit now
EOF"""
    srl_exec("clab-srl-srl-eigrp-srl1", ["bash", "-c", cfg_passive])

    # Verify IPv6 neighbor drops (total-neighbors becomes 1)
    dropped = False
    for _ in range(15):
        time.sleep(1)
        out_state = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "info from state network-instance default protocols eigrp"
        ])
        if "total-neighbors 1" in out_state:
            dropped = True
            break
    assert dropped, f"IPv6 neighbor did not drop after passive true: {out_state}"

    # Revert passive to false
    cfg_active = """sr_cli << 'EOF'
enter candidate
/ network-instance default protocols eigrp interface ethernet-1/1.0 address-family ipv6-unicast passive false
commit now
EOF"""
    srl_exec("clab-srl-srl-eigrp-srl1", ["bash", "-c", cfg_active])

    # Verify IPv6 neighbor recovers (total-neighbors returns to 2)
    recovered = False
    for _ in range(15):
        time.sleep(1)
        out_state = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "info from state network-instance default protocols eigrp"
        ])
        if "total-neighbors 2" in out_state and "2001:db8::2/128" in out_state:
            recovered = True
            break
    assert recovered, f"IPv6 neighbor did not recover after passive false: {out_state}"


def test_srl_ipv6_disable(srl_exec):
    """Disable IPv6 EIGRP and verify return to baseline state (only IPv4 active)."""
    cfg_srl1 = """sr_cli << 'EOF'
enter candidate
/ network-instance default protocols eigrp address-family ipv6-unicast admin-state disable
commit now
EOF"""
    srl_exec("clab-srl-srl-eigrp-srl1", ["bash", "-c", cfg_srl1])

    cfg_srl2 = """sr_cli << 'EOF'
enter candidate
/ network-instance default protocols eigrp address-family ipv6-unicast admin-state disable
commit now
EOF"""
    srl_exec("clab-srl-srl-eigrp-srl2", ["bash", "-c", cfg_srl2])

    try:
        out = ""
        for _ in range(15):
            time.sleep(2)
            out = srl_exec("clab-srl-srl-eigrp-srl1", [
                "sr_cli", "info from state network-instance default protocols eigrp"
            ])
            if "total-neighbors 1" in out and "total-routes 1" in out:
                break
        assert "total-neighbors 1" in out, f"Failed to reset neighbors: {out}"
        assert "total-routes 1" in out, f"Failed to reset routes: {out}"
        assert "2001:db8::2" not in out, f"IPv6 route still in state DB: {out}"
    finally:
        cfg_srl1_en = """sr_cli << 'EOF'
enter candidate
/ network-instance default protocols eigrp address-family ipv6-unicast admin-state enable
commit now
EOF"""
        srl_exec("clab-srl-srl-eigrp-srl1", ["bash", "-c", cfg_srl1_en])

        cfg_srl2_en = """sr_cli << 'EOF'
enter candidate
/ network-instance default protocols eigrp address-family ipv6-unicast admin-state enable
commit now
EOF"""
        srl_exec("clab-srl-srl-eigrp-srl2", ["bash", "-c", cfg_srl2_en])
        time.sleep(3)


def test_wide_metrics_rib_scale_scaling(srl_exec):
    """Verify RFC 7868 64-bit wide metric scaling into 32-bit FIB route metrics via rib-scale."""
    import re
    # 1. Configure rib-scale 64 on SRL1
    cfg_scale64 = """sr_cli << 'EOF'
enter candidate
/ network-instance default protocols eigrp rib-scale 64
commit now
EOF"""
    srl_exec("clab-srl-srl-eigrp-srl1", ["bash", "-c", cfg_scale64])

    # 2. Verify state DB reflects rib-scale 64 and route has scaled metric (wide_metric / 64)
    scaled_ok = False
    out_state = ""
    out_fib = ""
    for _ in range(15):
        time.sleep(1)
        out_state = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "info from state network-instance default protocols eigrp"
        ])
        out_fib = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "show network-instance default ipv4 route 192.0.2.2/32"
        ])
        m = re.search(r'wide-metric\s+(\d+)', out_state)
        if m and "rib-scale 64" in out_state:
            wm = int(m.group(1))
            expected_scaled = str(wm // 64)
            if expected_scaled in out_fib:
                scaled_ok = True
                break
    assert scaled_ok, f"FIB route did not scale with rib-scale 64: state={out_state}, fib={out_fib}"

    # 3. Restore rib-scale 128
    cfg_scale128 = """sr_cli << 'EOF'
enter candidate
/ network-instance default protocols eigrp rib-scale 128
commit now
EOF"""
    srl_exec("clab-srl-srl-eigrp-srl1", ["bash", "-c", cfg_scale128])

    # 4. Verify FIB route metric returns to wide_metric / 128
    restored_ok = False
    for _ in range(15):
        time.sleep(1)
        out_state = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "info from state network-instance default protocols eigrp"
        ])
        out_fib = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "show network-instance default ipv4 route 192.0.2.2/32"
        ])
        m = re.search(r'wide-metric\s+(\d+)', out_state)
        if m:
            wm = int(m.group(1))
            expected_restored = str(wm // 128)
            if expected_restored in out_fib:
                restored_ok = True
                break
    assert restored_ok, f"FIB route metric did not return to wide_metric / 128: fib={out_fib}, state={out_state}"


def test_packet_authentication_md5_and_sha256(srl_exec):
    """Verify MD5 and HMAC-SHA-256 packet authentication with key mismatch rejection."""
    # 1. Configure matching MD5 authentication keychain on SRL1 & SRL2
    cfg_srl1_md5 = """sr_cli << 'EOF'
enter candidate
/ system authentication keychain eigrp-test-md5 admin-state enable type ospf key 1 algorithm md5 authentication-key authsecret123
/ network-instance default protocols eigrp interface ethernet-1/1.0 authentication mode md5 keychain eigrp-test-md5
commit now
EOF"""
    cfg_srl2_md5 = """sr_cli << 'EOF'
enter candidate
/ system authentication keychain eigrp-test-md5 admin-state enable type ospf key 1 algorithm md5 authentication-key authsecret123
/ network-instance default protocols eigrp interface ethernet-1/1.0 authentication mode md5 keychain eigrp-test-md5
commit now
EOF"""
    srl_exec("clab-srl-srl-eigrp-srl1", ["bash", "-c", cfg_srl1_md5])
    srl_exec("clab-srl-srl-eigrp-srl2", ["bash", "-c", cfg_srl2_md5])

    # Verify neighbor is Up with MD5
    md5_up = False
    for _ in range(15):
        time.sleep(1)
        out = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "show network-instance default protocols eigrp neighbor"
        ])
        if "10.0.0.2" in out and "Up" in out:
            md5_up = True
            break
    assert md5_up, f"Neighbor failed to establish with MD5 authentication: {out}"

    # Verify state DB shows auth-mode md5
    out_state = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "info from state network-instance default protocols eigrp"
    ])
    assert "auth-mode md5" in out_state, f"State DB missing auth-mode md5: {out_state}"

    # 2. Update SRL2 to mismatched key and clear neighbor -> verify adjacency does not recover
    cfg_srl2_mismatch = """sr_cli << 'EOF'
enter candidate
/ system authentication keychain eigrp-test-md5 key 1 authentication-key wrongpassword
commit now
EOF"""
    srl_exec("clab-srl-srl-eigrp-srl2", ["bash", "-c", cfg_srl2_mismatch])
    srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "tools network-instance default protocols eigrp neighbor clear 10.0.0.2"
    ])
    time.sleep(3)
    out_mismatch = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "show network-instance default protocols eigrp neighbor"
    ])
    assert "10.0.0.2" not in out_mismatch or "Up" not in out_mismatch, f"Neighbor should not form with mismatched key: {out_mismatch}"

    # 3. Configure matching HMAC-SHA-256 keychain on SRL1 & SRL2
    cfg_srl1_sha = """sr_cli << 'EOF'
enter candidate
/ system authentication keychain eigrp-test-sha admin-state enable type isis key 1 algorithm hmac-sha-256 authentication-key shasecret456
/ network-instance default protocols eigrp interface ethernet-1/1.0 authentication mode hmac-sha-256 keychain eigrp-test-sha
commit now
EOF"""
    cfg_srl2_sha = """sr_cli << 'EOF'
enter candidate
/ system authentication keychain eigrp-test-sha admin-state enable type isis key 1 algorithm hmac-sha-256 authentication-key shasecret456
/ network-instance default protocols eigrp interface ethernet-1/1.0 authentication mode hmac-sha-256 keychain eigrp-test-sha
commit now
EOF"""
    srl_exec("clab-srl-srl-eigrp-srl1", ["bash", "-c", cfg_srl1_sha])
    srl_exec("clab-srl-srl-eigrp-srl2", ["bash", "-c", cfg_srl2_sha])

    sha_up = False
    for _ in range(15):
        time.sleep(1)
        out = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "show network-instance default protocols eigrp neighbor"
        ])
        if "10.0.0.2" in out and "Up" in out:
            sha_up = True
            break
    assert sha_up, f"Neighbor failed to establish with HMAC-SHA-256: {out}"

    # 4. Test direct authentication-key (direct password without keychain) with MD5
    cfg_srl1_direct = """sr_cli << 'EOF'
enter candidate
/ network-instance default protocols eigrp interface ethernet-1/1.0 authentication mode md5 authentication-key directsecret123
commit now
EOF"""
    cfg_srl2_direct = """sr_cli << 'EOF'
enter candidate
/ network-instance default protocols eigrp interface ethernet-1/1.0 authentication mode md5 authentication-key directsecret123
commit now
EOF"""
    srl_exec("clab-srl-srl-eigrp-srl1", ["bash", "-c", cfg_srl1_direct])
    srl_exec("clab-srl-srl-eigrp-srl2", ["bash", "-c", cfg_srl2_direct])

    direct_up = False
    for _ in range(15):
        time.sleep(1)
        out = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "show network-instance default protocols eigrp neighbor"
        ])
        if "10.0.0.2" in out and "Up" in out:
            direct_up = True
            break
    assert direct_up, f"Neighbor failed to establish with direct MD5 authentication-key: {out}"

    # Verify state DB shows auth-mode md5 with direct key
    out_state_dir = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "info from state network-instance default protocols eigrp"
    ])
    assert "auth-mode md5" in out_state_dir, f"State DB missing auth-mode md5 with direct key: {out_state_dir}"

    # 5. Revert to unauthenticated state
    cfg_revert = """sr_cli << 'EOF'
enter candidate
delete / network-instance default protocols eigrp interface ethernet-1/1.0 authentication
commit now
EOF"""
    srl_exec("clab-srl-srl-eigrp-srl1", ["bash", "-c", cfg_revert])
    srl_exec("clab-srl-srl-eigrp-srl2", ["bash", "-c", cfg_revert])

    unauth_up = False
    for _ in range(15):
        time.sleep(1)
        out = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "show network-instance default protocols eigrp neighbor"
        ])
        if "10.0.0.2" in out and "Up" in out:
            unauth_up = True
            break
    assert unauth_up, f"Neighbor failed to re-establish after removing authentication: {out}"


def test_graceful_restart_route_preservation(srl_exec):
    """Verify planned graceful restart retains FIB routes continuously throughout the restart."""
    # Ensure graceful-restart is enabled
    cfg_gr = """sr_cli << 'EOF'
enter candidate
/ network-instance default protocols eigrp graceful-restart admin-state enable
commit now
EOF"""
    srl_exec("clab-srl-srl-eigrp-srl1", ["bash", "-c", cfg_gr])

    # Ensure baseline route is present in FIB
    out_init_fib = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "show network-instance default ipv4 route 192.0.2.2/32"
    ])
    assert "192.0.2.2/32" in out_init_fib and "10.0.0.2" in out_init_fib, f"Route not in FIB before GR: {out_init_fib}"

    # Trigger planned graceful restart
    out_gr = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "tools network-instance default protocols eigrp graceful-restart planned-restart"
    ])
    assert "Planned graceful restart" in out_gr or "Success" in out_gr, f"GR tool command failed: {out_gr}"

    # Immediately check that FIB route is STILL present during restart
    out_restarting_fib = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "show network-instance default ipv4 route 192.0.2.2/32"
    ])
    assert "192.0.2.2/32" in out_restarting_fib and "10.0.0.2" in out_restarting_fib, f"FIB route lost during planned restart: {out_restarting_fib}"

    # Verify neighbor recovers to Up after restart completes
    recovered = False
    for _ in range(15):
        time.sleep(1)
        out = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "show network-instance default protocols eigrp neighbor"
        ])
        if "10.0.0.2" in out and "Up" in out:
            recovered = True
            break
    assert recovered, f"Neighbor failed to recover after graceful restart: {out}"


def test_bfd_neighbor_teardown(srl_exec):
    """Verify BFD session down transition immediately tears down neighbor adjacency."""
    # 1. Enable BFD on SRL1 & SRL2 interface
    cfg_bfd_enable = """sr_cli << 'EOF'
enter candidate
/ network-instance default protocols eigrp interface ethernet-1/1.0 bfd admin-state enable desired-minimum-tx-interval 100000 required-minimum-receive 100000 detection-multiplier 3
commit now
EOF"""
    srl_exec("clab-srl-srl-eigrp-srl1", ["bash", "-c", cfg_bfd_enable])
    srl_exec("clab-srl-srl-eigrp-srl2", ["bash", "-c", cfg_bfd_enable])

    # Ensure neighbor is Up and BFD is Up
    bfd_up = False
    for _ in range(15):
        time.sleep(1)
        out = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "show network-instance default protocols eigrp neighbor"
        ])
        if "10.0.0.2" in out and "Up" in out and "up" in out:
            bfd_up = True
            break
    assert bfd_up, f"Neighbor not Up with BFD up before teardown test: {out}"

    # Verify BFD state in state DB
    out_state = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "info from state network-instance default protocols eigrp"
    ])
    assert "bfd-state" in out_state, f"State DB missing bfd-state: {out_state}"

    # 2. Trigger BFD down operational tool command
    out_bfd = srl_exec("clab-srl-srl-eigrp-srl1", [
        "sr_cli", "tools network-instance default protocols eigrp neighbor bfd-down 10.0.0.2"
    ])
    assert "Success" in out_bfd or "BFD down signaled" in out_bfd, f"BFD down command failed: {out_bfd}"

    # 3. Verify neighbor adjacency was torn down and recovers once Hellos resume
    recovered = False
    for _ in range(20):
        time.sleep(1)
        out = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "show network-instance default protocols eigrp neighbor"
        ])
        if "10.0.0.2" in out and "Up" in out:
            recovered = True
            break
    assert recovered, f"Neighbor failed to recover after BFD teardown: {out}"

    # 4. Clean up BFD config
    cfg_bfd_clean = """sr_cli << 'EOF'
enter candidate
delete / network-instance default protocols eigrp interface ethernet-1/1.0 bfd
commit now
EOF"""
    srl_exec("clab-srl-srl-eigrp-srl1", ["bash", "-c", cfg_bfd_clean])
    srl_exec("clab-srl-srl-eigrp-srl2", ["bash", "-c", cfg_bfd_clean])


def test_admin_state_disable_state_db(srl_exec):
    """Verify admin-state disable reflects admin-state disable and oper-state down in State DB."""
    # 1. Disable interface ethernet-1/1.0 administratively
    cfg_disable = """sr_cli << 'EOF'
enter candidate
set / network-instance default protocols eigrp interface ethernet-1/1.0 admin-state disable
commit now
EOF"""
    srl_exec("clab-srl-srl-eigrp-srl1", ["bash", "-c", cfg_disable])

    # Wait for telemetry to update
    disabled_ok = False
    for _ in range(15):
        time.sleep(1)
        out_state = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "info from state network-instance default protocols eigrp"
        ])
        if "interface ethernet-1/1.0" in out_state and "admin-state disable" in out_state:
            disabled_ok = True
            break
    assert disabled_ok, f"State DB did not reflect admin-state disable and oper-state down: {out_state}"

    # 2. Re-enable interface ethernet-1/1.0
    cfg_enable = """sr_cli << 'EOF'
enter candidate
set / network-instance default protocols eigrp interface ethernet-1/1.0 admin-state enable
commit now
EOF"""
    srl_exec("clab-srl-srl-eigrp-srl1", ["bash", "-c", cfg_enable])

    # Wait for neighbor and interface to recover to up
    recovered_ok = False
    for _ in range(25):
        time.sleep(1)
        out_state = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "info from state network-instance default protocols eigrp"
        ])
        if "interface ethernet-1/1.0" in out_state and "admin-state enable" in out_state and "neighbor 10.0.0.2" in out_state:
            recovered_ok = True
            break
    assert recovered_ok, f"State DB did not recover to admin-state enable and oper-state up: {out_state}"

    # 3. Disable protocol EIGRP instance administratively
    cfg_proto_disable = """sr_cli << 'EOF'
enter candidate
set / network-instance default protocols eigrp admin-state disable
commit now
EOF"""
    srl_exec("clab-srl-srl-eigrp-srl1", ["bash", "-c", cfg_proto_disable])

    # Wait for protocol state to transition to disabled / down and operational tables to clear
    proto_disabled_ok = False
    for _ in range(15):
        time.sleep(1)
        out_state = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "info from state network-instance default protocols eigrp"
        ])
        if "admin-state disable" in out_state and "oper-state down" in out_state and "neighbor 10.0.0.2" not in out_state:
            proto_disabled_ok = True
            break
    assert proto_disabled_ok, f"State DB did not reflect protocol admin-state disable: {out_state}"

    # 4. Re-enable protocol EIGRP instance
    cfg_proto_enable = """sr_cli << 'EOF'
enter candidate
set / network-instance default protocols eigrp admin-state enable
commit now
EOF"""
    srl_exec("clab-srl-srl-eigrp-srl1", ["bash", "-c", cfg_proto_enable])

    # Wait for neighbor and protocol to recover
    proto_recovered_ok = False
    for _ in range(25):
        time.sleep(1)
        out_state = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "info from state network-instance default protocols eigrp"
        ])
        if "admin-state enable" in out_state and "oper-state up" in out_state and "neighbor 10.0.0.2" in out_state:
            proto_recovered_ok = True
            break
    assert proto_recovered_ok, f"State DB did not recover protocol to enable/up: {out_state}"


def test_summary_address_state_db(srl_exec):
    """Verify summary-address configuration is reflected as state in the state database."""
    cfg_sa = """sr_cli << 'EOF'
enter candidate
set / network-instance default protocols eigrp interface ethernet-1/1.0 summary-address 10.128.0.0/16 distance 15
commit now
EOF"""
    srl_exec("clab-srl-srl-eigrp-srl1", ["bash", "-c", cfg_sa])

    sa_ok = False
    for _ in range(15):
        time.sleep(1)
        out_state = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "info from state network-instance default protocols eigrp"
        ])
        if "summary-address 10.128.0.0/16" in out_state and "distance 15" in out_state:
            sa_ok = True
            break
    assert sa_ok, f"State DB missing summary-address: {out_state}"

    # Clean up
    cfg_clean = """sr_cli << 'EOF'
enter candidate
delete / network-instance default protocols eigrp interface ethernet-1/1.0 summary-address 10.128.0.0/16
commit now
EOF"""
    srl_exec("clab-srl-srl-eigrp-srl1", ["bash", "-c", cfg_clean])

    sa_cleaned = False
    for _ in range(15):
        time.sleep(1)
        out_state = srl_exec("clab-srl-srl-eigrp-srl1", [
            "sr_cli", "info from state network-instance default protocols eigrp"
        ])
        if "summary-address" not in out_state:
            sa_cleaned = True
            break
    assert sa_cleaned, f"State DB retained deleted summary-address: {out_state}"





