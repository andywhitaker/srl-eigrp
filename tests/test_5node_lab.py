import re
import subprocess
import time
import pytest

NODES = [f"clab-eigrp-test-srl{i}" for i in range(1, 6)]

BASELINE_CONFIGS = {
    "clab-eigrp-test-srl1": """
delete / network-instance vrf-1
delete / network-instance default interface lo0.0
delete / network-instance default interface lo0.1
delete / network-instance default interface lo0.10
delete / network-instance default interface lo0.20
delete / interface ethernet-1/1 subinterface 1
delete / interface ethernet-1/1 subinterface 0 vlan
delete / interface ethernet-1/1 vlan-tagging
delete / interface lo0
delete / routing-policy
delete / system authentication
delete / network-instance default protocols ospf
delete / network-instance default protocols bgp
delete / network-instance default protocols isis
delete / network-instance default static-routes
delete / network-instance default next-hop-groups
delete / network-instance default protocols eigrp
delete / interface ethernet-1/1 subinterface 0 ipv6
delete / interface system0 subinterface 0 ipv6
set / interface ethernet-1/1 admin-state enable subinterface 0 ipv4 admin-state enable address 10.1.2.1/24
set / interface system0 subinterface 0 ipv4 admin-state enable address 1.1.1.1/32
set / network-instance default interface ethernet-1/1.0
set / network-instance default interface system0.0
set / network-instance default protocols eigrp admin-state enable autonomous-system 100 router-id 1.1.1.1
set / network-instance default protocols eigrp interface ethernet-1/1.0
set / network-instance default protocols eigrp interface system0.0 address-family ipv4-unicast passive true
""",
    "clab-eigrp-test-srl2": """
delete / network-instance vrf-1
delete / network-instance default interface lo0.0
delete / network-instance default interface lo0.1
delete / network-instance default interface lo0.10
delete / network-instance default interface lo0.20
delete / interface ethernet-1/1 subinterface 1
delete / interface ethernet-1/1 subinterface 0 vlan
delete / interface ethernet-1/1 vlan-tagging
delete / interface lo0
delete / routing-policy
delete / system authentication
delete / network-instance default protocols ospf
delete / network-instance default protocols bgp
delete / network-instance default protocols isis
delete / network-instance default static-routes
delete / network-instance default next-hop-groups
delete / network-instance default protocols eigrp
delete / interface ethernet-1/1 subinterface 0 ipv6
delete / interface ethernet-1/2 subinterface 0 ipv6
delete / interface ethernet-1/3 subinterface 0 ipv6
delete / interface system0 subinterface 0 ipv6
set / interface ethernet-1/1 admin-state enable subinterface 0 ipv4 admin-state enable address 10.1.2.2/24
set / interface ethernet-1/2 admin-state enable subinterface 0 ipv4 admin-state enable address 10.2.3.2/24
set / interface ethernet-1/3 admin-state enable subinterface 0 ipv4 admin-state enable address 10.2.4.2/24
set / interface system0 subinterface 0 ipv4 admin-state enable address 2.2.2.2/32
set / network-instance default interface ethernet-1/1.0
set / network-instance default interface ethernet-1/2.0
set / network-instance default interface ethernet-1/3.0
set / network-instance default interface system0.0
set / network-instance default protocols eigrp admin-state enable autonomous-system 100 router-id 2.2.2.2
set / network-instance default protocols eigrp interface ethernet-1/1.0 address-family ipv4-unicast
set / network-instance default protocols eigrp interface ethernet-1/2.0
set / network-instance default protocols eigrp interface ethernet-1/3.0
set / network-instance default protocols eigrp interface system0.0 address-family ipv4-unicast passive true
""",
    "clab-eigrp-test-srl3": """
delete / network-instance default interface lo0.0
delete / network-instance default interface lo0.1
delete / interface lo0
delete / routing-policy
delete / system authentication
delete / network-instance default protocols eigrp
delete / interface ethernet-1/1 subinterface 0 ipv6
delete / interface ethernet-1/2 subinterface 0 ipv6
delete / interface ethernet-1/3 subinterface 0 ipv6
delete / interface system0 subinterface 0 ipv6
set / interface ethernet-1/1 admin-state enable subinterface 0 ipv4 admin-state enable address 10.2.3.3/24
set / interface ethernet-1/2 admin-state enable subinterface 0 ipv4 admin-state enable address 10.3.4.3/24
set / interface ethernet-1/3 admin-state enable subinterface 0 ipv4 admin-state enable address 10.3.5.3/24
set / interface system0 subinterface 0 ipv4 admin-state enable address 3.3.3.3/32
set / network-instance default interface ethernet-1/1.0
set / network-instance default interface ethernet-1/2.0
set / network-instance default interface ethernet-1/3.0
set / network-instance default interface system0.0
set / network-instance default protocols eigrp admin-state enable autonomous-system 100 router-id 3.3.3.3
set / network-instance default protocols eigrp interface ethernet-1/1.0
set / network-instance default protocols eigrp interface ethernet-1/2.0
set / network-instance default protocols eigrp interface ethernet-1/3.0
set / network-instance default protocols eigrp interface system0.0 address-family ipv4-unicast passive true
""",
    "clab-eigrp-test-srl4": """
delete / network-instance default interface lo0.0
delete / network-instance default interface lo0.1
delete / interface lo0
delete / routing-policy
delete / system authentication
delete / network-instance default protocols eigrp
delete / interface ethernet-1/1 subinterface 0 ipv6
delete / interface ethernet-1/2 subinterface 0 ipv6
delete / interface ethernet-1/3 subinterface 0 ipv6
delete / interface system0 subinterface 0 ipv6
set / interface ethernet-1/1 admin-state enable subinterface 0 ipv4 admin-state enable address 10.3.4.4/24
set / interface ethernet-1/2 admin-state enable subinterface 0 ipv4 admin-state enable address 10.2.4.4/24
set / interface ethernet-1/3 admin-state enable subinterface 0 ipv4 admin-state enable address 10.4.5.4/24
set / interface system0 subinterface 0 ipv4 admin-state enable address 4.4.4.4/32
set / network-instance default interface ethernet-1/1.0
set / network-instance default interface ethernet-1/2.0
set / network-instance default interface ethernet-1/3.0
set / network-instance default interface system0.0
set / network-instance default protocols eigrp admin-state enable autonomous-system 100 router-id 4.4.4.4
set / network-instance default protocols eigrp interface ethernet-1/1.0
set / network-instance default protocols eigrp interface ethernet-1/2.0
set / network-instance default protocols eigrp interface ethernet-1/3.0
set / network-instance default protocols eigrp interface system0.0 address-family ipv4-unicast passive true
""",
    "clab-eigrp-test-srl5": """
delete / network-instance default interface lo0.0
delete / network-instance default interface lo0.1
delete / interface lo0
delete / routing-policy
delete / system authentication
delete / network-instance default protocols eigrp
delete / interface ethernet-1/1 subinterface 0 ipv6
delete / interface ethernet-1/2 subinterface 0 ipv6
delete / interface system0 subinterface 0 ipv6
set / interface ethernet-1/1 admin-state enable subinterface 0 ipv4 admin-state enable address 10.3.5.5/24
set / interface ethernet-1/2 admin-state enable subinterface 0 ipv4 admin-state enable address 10.4.5.5/24
set / interface system0 subinterface 0 ipv4 admin-state enable address 5.5.5.5/32
set / network-instance default interface ethernet-1/1.0
set / network-instance default interface ethernet-1/2.0
set / network-instance default interface system0.0
set / network-instance default protocols eigrp admin-state enable autonomous-system 100 router-id 5.5.5.5
set / network-instance default protocols eigrp address-family ipv4-unicast
set / network-instance default protocols eigrp interface ethernet-1/1.0
set / network-instance default protocols eigrp interface ethernet-1/2.0
set / network-instance default protocols eigrp interface system0.0 address-family ipv4-unicast passive true
""",
}


def apply_cfg(srl_exec, node, cmds):
    script = f"sr_cli << 'EOF'\nenter candidate\ndiscard stay\n{cmds.strip()}\ncommit now\nEOF"
    out = srl_exec(node, ["bash", "-c", script])
    assert "Error:" not in out and "Parsing error:" not in out, f"Config commit failed on {node}:\n{out}"
    return out


def restore_5node_baseline(srl_exec):
    for node, cfg in BASELINE_CONFIGS.items():
        apply_cfg(srl_exec, node, cfg)


def wait_for_5node_convergence(srl_exec, timeout=30):
    expected_nbrs = {
        "clab-eigrp-test-srl1": ["10.1.2.2"],
        "clab-eigrp-test-srl2": ["10.1.2.1", "10.2.3.3", "10.2.4.4"],
        "clab-eigrp-test-srl3": ["10.2.3.2", "10.3.4.4", "10.3.5.5"],
        "clab-eigrp-test-srl4": ["10.2.4.2", "10.3.4.3", "10.4.5.5"],
        "clab-eigrp-test-srl5": ["10.3.5.3", "10.4.5.4"],
    }
    deadline = time.time() + timeout
    while time.time() < deadline:
        all_ok = True
        for node, nbrs in expected_nbrs.items():
            out = srl_exec(node, ["sr_cli", "show network-instance default protocols eigrp neighbor"])
            for ip in nbrs:
                if ip not in out or "Up" not in out:
                    all_ok = False
                    break
            if not all_ok:
                break
        if all_ok:
            out_srl5 = srl_exec("clab-eigrp-test-srl5", ["sr_cli", "show network-instance default protocols eigrp topology"])
            out_srl1 = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "show network-instance default protocols eigrp topology"])
            if "1.1.1.1/32, 2 successors" in out_srl5 and "5.5.5.5/32, 1 successors" in out_srl1:
                return True
        time.sleep(1)
    return False


@pytest.fixture(scope="module", autouse=True)
def setup_and_teardown_5node_lab(srl_exec):
    res = subprocess.run(["docker", "ps", "-q", "-f", "name=clab-eigrp-test-srl1"], capture_output=True, text=True)
    if not res.stdout.strip():
        pytest.skip("5-node lab (clab-eigrp-test-srl1..srl5) is not running")
    restore_5node_baseline(srl_exec)
    assert wait_for_5node_convergence(srl_exec, timeout=40), "5-node lab failed initial baseline convergence"
    yield
    restore_5node_baseline(srl_exec)
    assert wait_for_5node_convergence(srl_exec, timeout=40), "5-node lab failed final baseline convergence restoration"


def test_5node_neighbors_and_topology(srl_exec):
    """Verify all 5 nodes establish expected adjacencies and converge multi-hop topology."""
    assert wait_for_5node_convergence(srl_exec, timeout=30)

    # Verify SRL2 has 2 ECMP successors to 5.5.5.5/32 and 10.3.4.0/24
    out_srl2 = srl_exec("clab-eigrp-test-srl2", ["sr_cli", "show network-instance default protocols eigrp topology"])
    assert "P 5.5.5.5/32, 2 successors, FD is 2621440" in out_srl2, f"SRL2 missing 2 ECMP successors for 5.5.5.5/32: {out_srl2}"
    assert "P 10.3.4.0/24, 2 successors, FD is 1966080" in out_srl2, f"SRL2 missing 2 ECMP successors for 10.3.4.0/24: {out_srl2}"

    # Verify SRL5 has 2 ECMP successors to 1.1.1.1/32 and 2.2.2.2/32
    out_srl5 = srl_exec("clab-eigrp-test-srl5", ["sr_cli", "show network-instance default protocols eigrp topology"])
    assert "P 1.1.1.1/32, 2 successors, FD is 3276800" in out_srl5, f"SRL5 missing 2 ECMP successors for 1.1.1.1/32: {out_srl5}"
    assert "P 2.2.2.2/32, 2 successors, FD is 2621440" in out_srl5, f"SRL5 missing 2 ECMP successors for 2.2.2.2/32: {out_srl5}"


def test_5node_dataplane_ping(srl_exec):
    """Verify end-to-end multi-hop dataplane ping across all 5 loopbacks."""
    for target in ["2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"]:
        out = srl_exec("clab-eigrp-test-srl1", ["sr_cli", f"ping {target} network-instance default -c 3"])
        assert "0% packet loss" in out or "3 received" in out or "3 packets received" in out, f"Ping to {target} failed: {out}"

    out_rev = srl_exec("clab-eigrp-test-srl5", ["sr_cli", "ping 1.1.1.1 network-instance default -c 3"])
    assert "0% packet loss" in out_rev or "3 received" in out_rev or "3 packets received" in out_rev, f"Reverse ping failed: {out_rev}"


def test_5node_ecmp_fib_and_maximum_paths(srl_exec):
    """Verify ECMP next-hop groups in SR Linux FIB and maximum-paths enforcement across the diamond."""
    out_fib2 = srl_exec("clab-eigrp-test-srl2", ["sr_cli", "show network-instance default ipv4 route 5.5.5.5/32"])
    assert "10.2.3.3" in out_fib2 and "10.2.4.4" in out_fib2 and "eigrp" in out_fib2, f"SRL2 FIB missing ECMP next-hops: {out_fib2}"

    out_fib5 = srl_exec("clab-eigrp-test-srl5", ["sr_cli", "show network-instance default ipv4 route 1.1.1.1/32"])
    assert "10.3.5.3" in out_fib5 and "10.4.5.4" in out_fib5 and "eigrp" in out_fib5, f"SRL5 FIB missing ECMP next-hops: {out_fib5}"

    try:
        # Restrict maximum-paths to 1 on SRL2 -> only 1 successor should remain in topology and FIB,
        # while the second equal-cost path becomes a Feasible Successor!
        apply_cfg(srl_exec, "clab-eigrp-test-srl2", "set / network-instance default protocols eigrp address-family ipv4-unicast maximum-paths 1")
        ok = False
        out_top = ""
        for _ in range(15):
            time.sleep(1)
            out_top = srl_exec("clab-eigrp-test-srl2", ["sr_cli", "show network-instance default protocols eigrp topology"])
            if "P 5.5.5.5/32, 1 successors, FD is 2621440" in out_top and "Feasible Successor" in out_top:
                ok = True
                break
        assert ok, f"maximum-paths 1 did not reduce 5.5.5.5/32 to 1 successor + 1 Feasible Successor: {out_top}"

        out_fib_single = srl_exec("clab-eigrp-test-srl2", ["sr_cli", "show network-instance default ipv4 route 5.5.5.5/32"])
        nh_count = sum(1 for nh in ["10.2.3.3", "10.2.4.4"] if nh in out_fib_single)
        assert nh_count == 1, f"Expected 1 next-hop in FIB with maximum-paths 1, got: {out_fib_single}"
    finally:
        apply_cfg(srl_exec, "clab-eigrp-test-srl2", "delete / network-instance default protocols eigrp address-family ipv4-unicast maximum-paths")

    restored = False
    for _ in range(15):
        time.sleep(1)
        out_top = srl_exec("clab-eigrp-test-srl2", ["sr_cli", "show network-instance default protocols eigrp topology"])
        if "P 5.5.5.5/32, 2 successors, FD is 2621440" in out_top:
            restored = True
            break
    assert restored, f"Failed to restore 2 ECMP successors after deleting maximum-paths: {out_top}"


def test_5node_feasible_successor_and_variance(srl_exec):
    """Verify Feasible Successor selection (RD < FD), strict non-FS rejection when RD == FD,
    and unequal-cost load balancing promotion via variance."""
    try:
        # Increase delay on SRL2 ethernet-1/3.0 (towards SRL4) to 20 (200us)
        apply_cfg(srl_exec, "clab-eigrp-test-srl2", "set / network-instance default protocols eigrp interface ethernet-1/3.0 delay 20")

        fs_ok = False
        out_top = ""
        out_state = ""
        for _ in range(15):
            time.sleep(1)
            out_top = srl_exec("clab-eigrp-test-srl2", ["sr_cli", "show network-instance default protocols eigrp topology"])
            out_state = srl_exec("clab-eigrp-test-srl2", ["sr_cli", "info from state network-instance default protocols eigrp topology prefix 5.5.5.5/32"])
            if (
                "P 5.5.5.5/32, 1 successors, FD is 2621440" in out_top
                and "via 10.2.4.4 (3276800/1966080), ethernet-1/3.0 Feasible Successor" in out_top
                and "feasible-successor true" in out_state
            ):
                fs_ok = True
                break
        assert fs_ok, f"Feasible Successor not properly selected for 5.5.5.5/32: top={out_top}, state={out_state}"

        # Verify self-originated connected routes on SRL2 did not lose their Successor flag (RD must remain 0)
        # or double-add interface delay during eigrp_topology_metric_update()
        assert "P 2.2.2.2/32, 1 successors, FD is 1310720" in out_top and "via 0.0.0.0 (1310720/0), system0.0 Successor" in out_top, (
            f"Connected route 2.2.2.2/32 corrupted after metric update on SRL2: {out_top}"
        )
        assert "P 10.2.4.0/24, 1 successors, FD is 1966080" in out_top and "via 0.0.0.0 (1966080/0), ethernet-1/3.0 Successor" in out_top, (
            f"Connected route 10.2.4.0/24 double-added delay or lost Successor after metric update on SRL2: {out_top}"
        )

        # Verify 3.3.3.3/32 via 10.2.4.4 (RD 1966080 == FD 1966080) is NOT marked as Feasible Successor
        out_state_3 = srl_exec("clab-eigrp-test-srl2", ["sr_cli", "info from state network-instance default protocols eigrp topology prefix 3.3.3.3/32"])
        assert "feasible-successor true" not in out_state_3, f"3.3.3.3/32 via 10.2.4.4 (RD == FD) must not be Feasible Successor: {out_state_3}"
        block_3 = out_top.split("P 3.3.3.3/32")[1].split("P ")[0] if "P 3.3.3.3/32" in out_top else ""
        assert "Feasible Successor" not in block_3, f"3.3.3.3/32 CLI topology block must not show Feasible Successor: {block_3}"

        # Verify FIB for 5.5.5.5/32 currently has only 10.2.3.3 (since variance is 1)
        out_fib_v1 = srl_exec("clab-eigrp-test-srl2", ["sr_cli", "show network-instance default ipv4 route 5.5.5.5/32"])
        assert "10.2.3.3" in out_fib_v1 and "10.2.4.4" not in out_fib_v1, f"FIB should only have 10.2.3.3 at variance=1: {out_fib_v1}"

        # Configure variance 2 and traffic-share-balanced true on SRL2
        apply_cfg(
            srl_exec,
            "clab-eigrp-test-srl2",
            """
            set / network-instance default protocols eigrp address-family ipv4-unicast variance 2
            set / network-instance default protocols eigrp address-family ipv4-unicast traffic-share-balanced true
            """,
        )

        ucmp_ok = False
        for _ in range(15):
            time.sleep(1)
            out_top = srl_exec("clab-eigrp-test-srl2", ["sr_cli", "show network-instance default protocols eigrp topology"])
            out_fib_v2 = srl_exec("clab-eigrp-test-srl2", ["sr_cli", "show network-instance default ipv4 route 5.5.5.5/32"])
            if (
                "P 5.5.5.5/32, 2 successors, FD is 2621440" in out_top
                and "10.2.3.3" in out_fib_v2
                and "10.2.4.4" in out_fib_v2
            ):
                ucmp_ok = True
                break
        assert ucmp_ok, f"Variance 2 did not promote Feasible Successor 10.2.4.4 to FIB multipath: top={out_top}, fib={out_fib_v2}"

        # Verify 3.3.3.3/32 (where 10.2.4.4 is NOT a Feasible Successor) still has ONLY 1 successor even with variance 2!
        assert "P 3.3.3.3/32, 1 successors, FD is 1966080" in out_top, f"Infeasible path must not become successor under variance 2: {out_top}"
        out_fib_3 = srl_exec("clab-eigrp-test-srl2", ["sr_cli", "show network-instance default ipv4 route 3.3.3.3/32"])
        assert "10.2.3.3" in out_fib_3 and "10.2.4.4" not in out_fib_3, f"Infeasible path installed in FIB for 3.3.3.3/32: {out_fib_3}"
    finally:
        apply_cfg(
            srl_exec,
            "clab-eigrp-test-srl2",
            """
            delete / network-instance default protocols eigrp address-family ipv4-unicast variance
            delete / network-instance default protocols eigrp address-family ipv4-unicast traffic-share-balanced
            delete / network-instance default protocols eigrp interface ethernet-1/3.0 delay
            """,
        )
        assert wait_for_5node_convergence(srl_exec, timeout=20)


def test_5node_fs_instant_failover_vs_active_query(srl_exec):
    """Verify that when the primary successor fails:
    - Destinations with a Feasible Successor (5.5.5.5/32, 10.3.4.0/24) fail over immediately in PASSIVE state without going ACTIVE.
    - Destinations without a Feasible Successor (3.3.3.3/32, 10.3.5.0/24) transition PASSIVE -> ACTIVE, send QUERY, receive REPLY, and converge to PASSIVE."""
    try:
        # 1. Establish Feasible Successor on SRL2 via ethernet-1/3.0 (delay 20)
        apply_cfg(srl_exec, "clab-eigrp-test-srl2", "set / network-instance default protocols eigrp interface ethernet-1/3.0 delay 20")
        for _ in range(15):
            time.sleep(1)
            out_top = srl_exec("clab-eigrp-test-srl2", ["sr_cli", "show network-instance default protocols eigrp topology"])
            if "via 10.2.4.4 (3276800/1966080), ethernet-1/3.0 Feasible Successor" in out_top:
                break

        # 2. Clear event log on SRL2 so we capture the exact failover events
        srl_exec("clab-eigrp-test-srl2", ["sr_cli", "tools network-instance default protocols eigrp event-log clear"])

        # 3. Bring down primary successor interface ethernet-1/2.0 on SRL2
        apply_cfg(srl_exec, "clab-eigrp-test-srl2", "set / network-instance default protocols eigrp interface ethernet-1/2.0 admin-state disable")

        # 4. Wait for both 5.5.5.5/32 and 3.3.3.3/32 to converge via 10.2.4.4
        converged = False
        out_top = ""
        for _ in range(15):
            time.sleep(1)
            out_top = srl_exec("clab-eigrp-test-srl2", ["sr_cli", "show network-instance default protocols eigrp topology"])
            if (
                "P 5.5.5.5/32, 1 successors" in out_top
                and "via 10.2.4.4 (3276800/1966080), ethernet-1/3.0 Successor" in out_top
                and "P 3.3.3.3/32, 1 successors, FD is 3276800" in out_top
            ):
                converged = True
                break
        assert converged, f"Failover to 10.2.4.4 did not converge: {out_top}"

        # 5. Inspect SRL2 event log:
        #    - 5.5.5.5/32 had a Feasible Successor -> FC sat, NO DUAL state change to ACTIVE!
        #    - 3.3.3.3/32 had NO Feasible Successor -> FC not sat, DUAL state change PASSIVE -> ACTIVE_1 -> PASSIVE!
        out_ev = srl_exec("clab-eigrp-test-srl2", ["sr_cli", "show network-instance default protocols eigrp event-log"])
        assert "FC sat rdbmet/succmet: 1966080 2621440" in out_ev, f"Missing FC sat for 5.5.5.5/32 FS failover: {out_ev}"
        assert "DUAL state change 5.5.5.5/32" not in out_ev, f"5.5.5.5/32 had a Feasible Successor and must NOT go ACTIVE: {out_ev}"
        assert "DUAL state change 3.3.3.3/32 Old: PASSIVE New: ACTIVE_1" in out_ev, f"3.3.3.3/32 had no FS and should enter ACTIVE_1: {out_ev}"
        assert "DUAL state change 3.3.3.3/32 Old: ACTIVE_1 New: PASSIVE" in out_ev, f"3.3.3.3/32 should return to PASSIVE after REPLY: {out_ev}"

        # 6. Verify end-to-end dataplane ping from SRL1 to SRL3 and SRL5 through the backup path
        for target in ["3.3.3.3", "5.5.5.5"]:
            out_ping = srl_exec("clab-eigrp-test-srl1", ["sr_cli", f"ping {target} network-instance default -c 3"])
            assert "0% packet loss" in out_ping or "3 received" in out_ping or "3 packets received" in out_ping, (
                f"Ping to {target} failed after failover: {out_ping}"
            )
    finally:
        apply_cfg(
            srl_exec,
            "clab-eigrp-test-srl2",
            """
            set / network-instance default protocols eigrp interface ethernet-1/2.0 admin-state enable
            delete / network-instance default protocols eigrp interface ethernet-1/3.0 delay
            """,
        )

    assert wait_for_5node_convergence(srl_exec, timeout=25)
    out_top_restored = srl_exec("clab-eigrp-test-srl2", ["sr_cli", "show network-instance default protocols eigrp topology"])
    assert "P 3.3.3.3/32, 1 successors, FD is 1966080" in out_top_restored, (
        f"3.3.3.3/32 did not preempt back to single successor FD 1966080: {out_top_restored}"
    )
    assert "P 5.5.5.5/32, 2 successors, FD is 2621440" in out_top_restored, (
        f"5.5.5.5/32 did not return to 2 ECMP successors FD 2621440: {out_top_restored}"
    )


def test_5node_peer_restart_recovery(srl_exec):
    """Verify restarting srl_eigrpd while neighbor hold timers are active properly detects peer restart
    (even when consecutive restarts reuse INIT sequence 1), re-arms t_holddown, and resyncs full topology."""
    # 1. Restart SRL5 and verify dual-path recovery across SRL3 and SRL4
    srl_exec("clab-eigrp-test-srl5", ["sr_cli", "tools system app-management application srl_eigrpd restart"])
    assert wait_for_5node_convergence(srl_exec, timeout=25), "SRL5 failed to recover full 2-path topology after daemon restart"

    # 2. Restart SRL1 twice in succession so SRL1 sends INIT with sequence=1 after SRL2 has already seen sequence=1
    srl_exec("clab-eigrp-test-srl2", ["sr_cli", "tools network-instance default protocols eigrp event-log clear"])
    srl_exec("clab-eigrp-test-srl1", ["sr_cli", "tools system app-management application srl_eigrpd restart"])
    assert wait_for_5node_convergence(srl_exec, timeout=25), "SRL1 failed to recover topology after first daemon restart"

    srl_exec("clab-eigrp-test-srl1", ["sr_cli", "tools system app-management application srl_eigrpd restart"])
    assert wait_for_5node_convergence(srl_exec, timeout=25), "SRL1 failed to recover topology after second consecutive daemon restart (INIT seq 1 reuse)"

    out_srl2_ev = srl_exec("clab-eigrp-test-srl2", ["sr_cli", "show network-instance default protocols eigrp event-log"])
    assert "reason=peer-restart" in out_srl2_ev or "NSF peer restarted" in out_srl2_ev, (
        f"SRL2 did not log peer-restart on SRL1 restart: {out_srl2_ev}"
    )
    out_srl2_nbr = srl_exec("clab-eigrp-test-srl2", ["sr_cli", "info from state network-instance default protocols eigrp neighbor 10.1.2.1"])
    assert "hold-time" in out_srl2_nbr and "hold-time 0" not in out_srl2_nbr, (
        f"SRL2 neighbor 10.1.2.1 hold timer left disarmed after peer restart: {out_srl2_nbr}"
    )


IPV6_CFGS = {
    "clab-eigrp-test-srl1": """
        set / interface ethernet-1/1 subinterface 0 ipv6 admin-state enable address 2001:db8:12::1/64
        set / interface system0 subinterface 0 ipv6 admin-state enable address 2001:db8::1/128
        set / network-instance default protocols eigrp address-family ipv4-unicast admin-state enable
        set / network-instance default protocols eigrp address-family ipv6-unicast admin-state enable
        set / network-instance default protocols eigrp interface system0.0 address-family ipv6-unicast passive true
    """,
    "clab-eigrp-test-srl2": """
        set / interface ethernet-1/1 subinterface 0 ipv6 admin-state enable address 2001:db8:12::2/64
        set / interface ethernet-1/2 subinterface 0 ipv6 admin-state enable address 2001:db8:23::2/64
        set / interface ethernet-1/3 subinterface 0 ipv6 admin-state enable address 2001:db8:24::2/64
        set / interface system0 subinterface 0 ipv6 admin-state enable address 2001:db8::2/128
        set / network-instance default protocols eigrp address-family ipv4-unicast admin-state enable
        set / network-instance default protocols eigrp address-family ipv6-unicast admin-state enable
        set / network-instance default protocols eigrp interface system0.0 address-family ipv6-unicast passive true
    """,
    "clab-eigrp-test-srl3": """
        set / interface ethernet-1/1 subinterface 0 ipv6 admin-state enable address 2001:db8:23::3/64
        set / interface ethernet-1/2 subinterface 0 ipv6 admin-state enable address 2001:db8:34::3/64
        set / interface ethernet-1/3 subinterface 0 ipv6 admin-state enable address 2001:db8:35::3/64
        set / interface system0 subinterface 0 ipv6 admin-state enable address 2001:db8::3/128
        set / network-instance default protocols eigrp address-family ipv4-unicast admin-state enable
        set / network-instance default protocols eigrp address-family ipv6-unicast admin-state enable
        set / network-instance default protocols eigrp interface system0.0 address-family ipv6-unicast passive true
    """,
    "clab-eigrp-test-srl4": """
        set / interface ethernet-1/1 subinterface 0 ipv6 admin-state enable address 2001:db8:34::4/64
        set / interface ethernet-1/2 subinterface 0 ipv6 admin-state enable address 2001:db8:24::4/64
        set / interface ethernet-1/3 subinterface 0 ipv6 admin-state enable address 2001:db8:45::4/64
        set / interface system0 subinterface 0 ipv6 admin-state enable address 2001:db8::4/128
        set / network-instance default protocols eigrp address-family ipv4-unicast admin-state enable
        set / network-instance default protocols eigrp address-family ipv6-unicast admin-state enable
        set / network-instance default protocols eigrp interface system0.0 address-family ipv6-unicast passive true
    """,
    "clab-eigrp-test-srl5": """
        set / interface ethernet-1/1 subinterface 0 ipv6 admin-state enable address 2001:db8:35::5/64
        set / interface ethernet-1/2 subinterface 0 ipv6 admin-state enable address 2001:db8:45::5/64
        set / interface system0 subinterface 0 ipv6 admin-state enable address 2001:db8::5/128
        set / network-instance default protocols eigrp address-family ipv4-unicast admin-state enable
        set / network-instance default protocols eigrp address-family ipv6-unicast admin-state enable
        set / network-instance default protocols eigrp interface system0.0 address-family ipv6-unicast passive true
    """,
}


def test_5node_ipv6_eigrp_diamond(srl_exec):
    """Verify IPv6 EIGRP link-local peering, multi-hop ECMP across the diamond, Feasible Successor selection, and IPv6 dataplane ping."""
    try:
        for node, cfg in IPV6_CFGS.items():
            apply_cfg(srl_exec, node, cfg)

        # Wait for SRL1 to learn 2001:db8::5/128 and SRL2 to have 2 ECMP successors for 2001:db8::5/128
        v6_ok = False
        out_srl2_top = ""
        out_srl1_fib = ""
        for _ in range(30):
            time.sleep(1)
            out_srl2_top = srl_exec("clab-eigrp-test-srl2", ["sr_cli", "show network-instance default protocols eigrp topology"])
            out_srl1_fib = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "show network-instance default ipv6 route 2001:db8::5/128"])
            if "P 2001:db8::5/128, 2 successors" in out_srl2_top and "2001:db8::5/128" in out_srl1_fib and "eigrp" in out_srl1_fib:
                v6_ok = True
                break
        assert v6_ok, f"IPv6 diamond convergence failed: srl2_top={out_srl2_top}, srl1_fib={out_srl1_fib}"

        # Verify end-to-end IPv6 ping from SRL1 to SRL5 (2001:db8::5)
        out_ping = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "ping 2001:db8::5 network-instance default -c 3"])
        assert "0% packet loss" in out_ping or "3 received" in out_ping or "3 packets received" in out_ping, f"IPv6 ping failed: {out_ping}"

        # Test IPv6 Feasible Successor on SRL2 by setting delay 20 on ethernet-1/3.0
        apply_cfg(srl_exec, "clab-eigrp-test-srl2", "set / network-instance default protocols eigrp interface ethernet-1/3.0 delay 20")
        v6_fs_ok = False
        for _ in range(15):
            time.sleep(1)
            out_srl2_state = srl_exec(
                "clab-eigrp-test-srl2",
                ["sr_cli", "info from state network-instance default protocols eigrp topology prefix 2001:db8::5/128"],
            )
            if "successor-count 1" in out_srl2_state and "feasible-successor true" in out_srl2_state:
                v6_fs_ok = True
                break
        assert v6_fs_ok, f"IPv6 Feasible Successor not selected on SRL2: {out_srl2_state}"
    finally:
        restore_5node_baseline(srl_exec)
        assert wait_for_5node_convergence(srl_exec, timeout=30)


def test_5node_authentication_md5_sha256_and_direct_key(srl_exec):
    """Verify MD5 keychain, key mismatch rejection, HMAC-SHA-256 keychain, and direct authentication-key on 5-node lab."""
    try:
        # 1. MD5 keychain on SRL1 <-> SRL2
        apply_cfg(
            srl_exec,
            "clab-eigrp-test-srl1",
            """
            set / system authentication keychain kc-md5 admin-state enable type ospf key 1 algorithm md5 authentication-key secret123
            set / network-instance default protocols eigrp interface ethernet-1/1.0 address-family ipv4-unicast authentication mode md5 keychain kc-md5
            """,
        )
        apply_cfg(
            srl_exec,
            "clab-eigrp-test-srl2",
            """
            set / system authentication keychain kc-md5 admin-state enable type ospf key 1 algorithm md5 authentication-key secret123
            set / network-instance default protocols eigrp interface ethernet-1/1.0 address-family ipv4-unicast authentication mode md5 keychain kc-md5
            """,
        )

        md5_ok = False
        for _ in range(15):
            time.sleep(1)
            out = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "show network-instance default protocols eigrp neighbor"])
            if "10.1.2.2" in out and "Up" in out and "md5" in out:
                md5_ok = True
                break
        assert md5_ok, f"MD5 authentication failed on SRL1: {out}"

        # 2. Key mismatch rejection
        apply_cfg(
            srl_exec,
            "clab-eigrp-test-srl2",
            "set / system authentication keychain kc-md5 key 1 authentication-key wrongkey999",
        )
        srl_exec("clab-eigrp-test-srl1", ["sr_cli", "tools network-instance default protocols eigrp neighbor clear 10.1.2.2"])
        time.sleep(3)
        out_mis = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "show network-instance default protocols eigrp neighbor"])
        assert "10.1.2.2" not in out_mis or "Up" not in out_mis, f"Neighbor formed despite mismatched MD5 key: {out_mis}"

        # 3. HMAC-SHA-256 keychain
        apply_cfg(
            srl_exec,
            "clab-eigrp-test-srl1",
            """
            set / system authentication keychain kc-sha admin-state enable type isis key 1 algorithm hmac-sha-256 authentication-key shasecret456
            set / network-instance default protocols eigrp interface ethernet-1/1.0 address-family ipv4-unicast authentication mode hmac-sha-256 keychain kc-sha
            """,
        )
        apply_cfg(
            srl_exec,
            "clab-eigrp-test-srl2",
            """
            set / system authentication keychain kc-sha admin-state enable type isis key 1 algorithm hmac-sha-256 authentication-key shasecret456
            set / network-instance default protocols eigrp interface ethernet-1/1.0 address-family ipv4-unicast authentication mode hmac-sha-256 keychain kc-sha
            """,
        )
        sha_ok = False
        for _ in range(15):
            time.sleep(1)
            out = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "show network-instance default protocols eigrp neighbor"])
            if "10.1.2.2" in out and "Up" in out and "hmac-sha-256" in out:
                sha_ok = True
                break
        assert sha_ok, f"HMAC-SHA-256 authentication failed on SRL1: {out}"

        # 4. Direct authentication-key
        apply_cfg(
            srl_exec,
            "clab-eigrp-test-srl1",
            """
            delete / network-instance default protocols eigrp interface ethernet-1/1.0 address-family ipv4-unicast authentication keychain
            set / network-instance default protocols eigrp interface ethernet-1/1.0 address-family ipv4-unicast authentication mode md5 authentication-key directpass123
            """,
        )
        apply_cfg(
            srl_exec,
            "clab-eigrp-test-srl2",
            """
            delete / network-instance default protocols eigrp interface ethernet-1/1.0 address-family ipv4-unicast authentication keychain
            set / network-instance default protocols eigrp interface ethernet-1/1.0 address-family ipv4-unicast authentication mode md5 authentication-key directpass123
            """,
        )
        dir_ok = False
        for _ in range(15):
            time.sleep(1)
            out = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "show network-instance default protocols eigrp neighbor"])
            if "10.1.2.2" in out and "Up" in out and "md5" in out:
                dir_ok = True
                break
        assert dir_ok, f"Direct key authentication failed on SRL1: {out}"

        # 5. Explicit authentication mode none transition while direct key is still present
        for node in ["clab-eigrp-test-srl1", "clab-eigrp-test-srl2"]:
            apply_cfg(
                srl_exec,
                node,
                "set / network-instance default protocols eigrp interface ethernet-1/1.0 address-family ipv4-unicast authentication mode none",
            )
        none_ok = False
        for _ in range(15):
            time.sleep(1)
            out = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "show network-instance default protocols eigrp neighbor"])
            if "10.1.2.2" in out and "Up" in out and "none" in out:
                none_ok = True
                break
        assert none_ok, f"Explicit authentication mode none transition failed on SRL1: {out}"
    finally:
        for node in ["clab-eigrp-test-srl1", "clab-eigrp-test-srl2"]:
            apply_cfg(
                srl_exec,
                node,
                """
                delete / network-instance default protocols eigrp interface ethernet-1/1.0 address-family ipv4-unicast authentication
                delete / system authentication keychain kc-md5
                delete / system authentication keychain kc-sha
                """,
            )
        assert wait_for_5node_convergence(srl_exec, timeout=25)


def test_5node_bfd_and_graceful_restart(srl_exec):
    """Verify BFD neighbor teardown and planned Graceful Restart route preservation on the 5-node lab."""
    try:
        # 1. Enable BFD on SRL1 & SRL2 ethernet-1/1.0
        bfd_cfg = "set / network-instance default protocols eigrp interface ethernet-1/1.0 address-family ipv4-unicast bfd admin-state enable desired-minimum-tx-interval 100000 required-minimum-receive 100000 detection-multiplier 3"
        apply_cfg(srl_exec, "clab-eigrp-test-srl1", bfd_cfg)
        apply_cfg(srl_exec, "clab-eigrp-test-srl2", bfd_cfg)

        out_bfd = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "tools network-instance default protocols eigrp neighbor bfd-down 10.1.2.2"])
        assert "Success" in out_bfd or "BFD down signaled" in out_bfd, f"BFD down command failed: {out_bfd}"

        recovered = False
        for _ in range(20):
            time.sleep(1)
            out = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "show network-instance default protocols eigrp neighbor"])
            if "10.1.2.2" in out and "Up" in out:
                recovered = True
                break
        assert recovered, f"Neighbor failed to recover after BFD teardown: {out}"

        # 2. Planned Graceful Restart on SRL1 preserves 5.5.5.5/32 in FIB
        apply_cfg(srl_exec, "clab-eigrp-test-srl1", "set / network-instance default protocols eigrp graceful-restart admin-state enable")
        for _ in range(15):
            out_fib = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "show network-instance default ipv4 route 5.5.5.5/32"])
            if "5.5.5.5/32" in out_fib and "10.1.2.2" in out_fib:
                break
            time.sleep(1)

        out_gr = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "tools network-instance default protocols eigrp graceful-restart planned-restart"])
        assert "Planned graceful restart" in out_gr or "Success" in out_gr, f"GR tool command failed: {out_gr}"

        out_during_gr = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "show network-instance default ipv4 route 5.5.5.5/32"])
        assert "5.5.5.5/32" in out_during_gr and "10.1.2.2" in out_during_gr, f"FIB route 5.5.5.5/32 lost during GR: {out_during_gr}"
    finally:
        for node in ["clab-eigrp-test-srl1", "clab-eigrp-test-srl2"]:
            apply_cfg(srl_exec, node, "delete / network-instance default protocols eigrp interface ethernet-1/1.0 address-family ipv4-unicast bfd")
        apply_cfg(srl_exec, "clab-eigrp-test-srl1", "delete / network-instance default protocols eigrp graceful-restart")
        assert wait_for_5node_convergence(srl_exec, timeout=25)


def test_5node_summary_address_and_auto_summary(srl_exec):
    """Verify summary-address component suppression across the diamond, summary metric accumulation
    (advertising local total_metric rather than predecessor RD), no split-horizon self-poisoning,
    Internal TLV type when summarizing external redistributed routes, no component leak on QUERY,
    and classful auto-summary propagation to SRL5."""
    try:
        # 1. Configure summary-address 10.0.0.0/8 on SRL2 ethernet-1/1.0 towards SRL1
        #    (Covers 10.1.2.0/24 on ethernet-1/1.0 itself -> verifies no split-horizon self-poisoning)
        apply_cfg(
            srl_exec,
            "clab-eigrp-test-srl2",
            "set / network-instance default protocols eigrp interface ethernet-1/1.0 address-family ipv4-unicast summary-address 10.0.0.0/8 distance 15",
        )

        sum_ok = False
        out_srl1_routes = ""
        for _ in range(20):
            time.sleep(1)
            out_srl1_routes = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "show network-instance default protocols eigrp routes"])
            if "10.0.0.0/8" in out_srl1_routes and "10.3.5.0/24" not in out_srl1_routes:
                sum_ok = True
                break
        assert sum_ok, f"SRL1 did not receive summary 10.0.0.0/8 with component suppression: {out_srl1_routes}"

        # 2. Replace 10.0.0.0/8 with summary-address 10.3.0.0/16 on SRL2 ethernet-1/1.0
        #    (Covers remote components 10.3.4.0/24 and 10.3.5.0/24 learned from SRL3/SRL4 with RD=1310720, SRL2 FD=1966080)
        #    -> Verify SRL2 advertises its accumulated distance 1966080 so SRL1 installs 10.3.0.0/16 with 2-hop FD=2621440 (RD=1966080)
        apply_cfg(
            srl_exec,
            "clab-eigrp-test-srl2",
            """
            delete / network-instance default protocols eigrp interface ethernet-1/1.0 address-family ipv4-unicast summary-address 10.0.0.0/8
            set / network-instance default protocols eigrp interface ethernet-1/1.0 address-family ipv4-unicast summary-address 10.3.0.0/16 distance 15
            """,
        )
        sum16_ok = False
        out_srl1_top = ""
        for _ in range(20):
            time.sleep(1)
            out_srl1_top = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "show network-instance default protocols eigrp topology"])
            if (
                "P 10.3.0.0/16, 1 successors, FD is 2621440" in out_srl1_top
                and "(2621440/1966080)" in out_srl1_top
                and "10.3.4.0/24" not in out_srl1_top
                and "10.3.5.0/24" not in out_srl1_top
            ):
                sum16_ok = True
                break
        assert sum16_ok, f"SRL1 did not learn summary 10.3.0.0/16 with accumulated 2-hop FD 2621440 (RD 1966080): {out_srl1_top}"

        # 3. Summarize an external redistributed route (172.16.99.0/24 -> 172.16.0.0/16) on SRL2 ethernet-1/1.0
        #    -> Verify SRL1 learns 172.16.0.0/16 as an Internal EIGRP route (Pref 90), not External (170), and suppresses 172.16.99.0/24
        apply_cfg(
            srl_exec,
            "clab-eigrp-test-srl2",
            """
            set / network-instance default next-hop-groups group nhg-sum-ext admin-state enable nexthop 1 ip-address 10.2.3.3 admin-state enable
            set / network-instance default static-routes route 172.16.99.0/24 admin-state enable next-hop-group nhg-sum-ext
            set / routing-policy policy sum-ext-pol statement 10 match protocol static
            set / routing-policy policy sum-ext-pol statement 10 action policy-result accept
            set / network-instance default protocols eigrp address-family ipv4-unicast default-metric bandwidth 100000 delay 100 reliability 255 load 1 mtu 1500
            set / network-instance default protocols eigrp address-family ipv4-unicast export-policy sum-ext-pol
            set / network-instance default protocols eigrp interface ethernet-1/1.0 address-family ipv4-unicast summary-address 172.16.0.0/16 distance 15
            """,
        )
        sum_ext_ok = False
        out_srl1_routes = ""
        for _ in range(20):
            time.sleep(1)
            out_srl1_routes = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "show network-instance default protocols eigrp routes"])
            if "172.16.0.0/16" in out_srl1_routes and "172.16.99.0/24" not in out_srl1_routes:
                for line in out_srl1_routes.splitlines():
                    if "172.16.0.0/16" in line and "Internal" in line and "90" in line:
                        sum_ext_ok = True
                        break
            if sum_ext_ok:
                break
        assert sum_ext_ok, f"Summary 172.16.0.0/16 over redistributed external route was not advertised as Internal (Pref 90): {out_srl1_routes}"

        # 4. Trigger component QUERY across the diamond (disable/enable SRL3 ethernet-1/2.0) while summary 10.3.0.0/16 is active
        #    -> Verify suppressed components 10.3.4.0/24 and 10.3.5.0/24 do not leak onto SRL1
        apply_cfg(srl_exec, "clab-eigrp-test-srl3", "set / network-instance default protocols eigrp interface ethernet-1/2.0 admin-state disable")
        time.sleep(2)
        apply_cfg(srl_exec, "clab-eigrp-test-srl3", "set / network-instance default protocols eigrp interface ethernet-1/2.0 admin-state enable")
        time.sleep(3)
        out_srl1_after_q = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "show network-instance default protocols eigrp routes"])
        assert "10.3.0.0/16" in out_srl1_after_q and "10.3.4.0/24" not in out_srl1_after_q and "10.3.5.0/24" not in out_srl1_after_q, (
            f"Suppressed components leaked to SRL1 after QUERY activity: {out_srl1_after_q}"
        )

        # 5. Configure auto-summary true on SRL1 -> 1.1.1.1/32 across 10.1.2.0/24 summarizes to 1.0.0.0/8 all the way to SRL5!
        apply_cfg(srl_exec, "clab-eigrp-test-srl1", "set / network-instance default protocols eigrp address-family ipv4-unicast auto-summary true")
        autosum_ok = False
        out_srl5_routes = ""
        for _ in range(20):
            time.sleep(1)
            out_srl5_routes = srl_exec("clab-eigrp-test-srl5", ["sr_cli", "show network-instance default protocols eigrp routes"])
            if "1.0.0.0/8" in out_srl5_routes:
                autosum_ok = True
                break
        assert autosum_ok, f"Classful auto-summary 1.0.0.0/8 did not propagate from SRL1 to SRL5: {out_srl5_routes}"
    finally:
        restore_5node_baseline(srl_exec)
        assert wait_for_5node_convergence(srl_exec, timeout=25)


def test_5node_redistribution_ospf_bgp_isis_static(srl_exec):
    """Verify redistribution of static (IPv4/IPv6), OSPFv2, OSPFv3, BGP (IPv4/IPv6), and IS-IS (IPv4/IPv6) routes on SRL2 and multi-hop propagation across the diamond to SRL5."""
    try:
        for node, cfg in IPV6_CFGS.items():
            apply_cfg(srl_exec, node, cfg)

        # 1. Configure SRL1 as the external protocol peer (OSPFv2, OSPFv3, BGP v4/v6, IS-IS v4/v6) advertising distinct prefixes to SRL2
        apply_cfg(
            srl_exec,
            "clab-eigrp-test-srl1",
            """
            set / interface lo0 admin-state enable
            set / interface lo0 subinterface 10 admin-state enable ipv4 admin-state enable address 172.16.10.1/32
            set / interface lo0 subinterface 10 ipv6 admin-state enable address 2001:db8:10::1/128
            set / interface lo0 subinterface 20 admin-state enable ipv4 admin-state enable address 172.16.20.1/32
            set / interface lo0 subinterface 20 ipv6 admin-state enable address 2001:db8:20::1/128
            set / network-instance default interface lo0.10
            set / network-instance default interface lo0.20
            set / network-instance default next-hop-groups group nhg-bgp4 admin-state enable nexthop 1 ip-address 10.1.2.2 admin-state enable
            set / network-instance default static-routes route 172.16.40.0/24 admin-state enable next-hop-group nhg-bgp4
            set / network-instance default next-hop-groups group nhg-bgp6 admin-state enable nexthop 1 ip-address 2001:db8:12::2 admin-state enable
            set / network-instance default static-routes route 2001:db8:40::/64 admin-state enable next-hop-group nhg-bgp6
            set / routing-policy policy bgp-export statement 10 match protocol static
            set / routing-policy policy bgp-export statement 10 action policy-result accept
            set / network-instance default protocols ospf instance ospf2 admin-state enable version ospf-v2 router-id 1.1.1.1 area 0.0.0.0 interface ethernet-1/1.0 admin-state enable interface-type point-to-point
            set / network-instance default protocols ospf instance ospf2 area 0.0.0.0 interface lo0.10 admin-state enable interface-type point-to-point
            set / network-instance default protocols ospf instance ospf3 admin-state enable version ospf-v3 router-id 1.1.1.1 address-family ipv6-unicast
            set / network-instance default protocols ospf instance ospf3 area 0.0.0.0 interface ethernet-1/1.0 admin-state enable interface-type point-to-point
            set / network-instance default protocols ospf instance ospf3 area 0.0.0.0 interface lo0.10 admin-state enable interface-type point-to-point
            set / network-instance default protocols isis instance isis1 admin-state enable net [ 49.0001.0000.0000.0001.00 ]
            set / network-instance default protocols isis instance isis1 ipv4-unicast admin-state enable
            set / network-instance default protocols isis instance isis1 ipv6-unicast admin-state enable
            set / network-instance default protocols isis instance isis1 interface ethernet-1/1.0 admin-state enable circuit-type point-to-point ipv4-unicast admin-state enable
            set / network-instance default protocols isis instance isis1 interface ethernet-1/1.0 ipv6-unicast admin-state enable
            set / network-instance default protocols isis instance isis1 interface lo0.20 admin-state enable circuit-type point-to-point ipv4-unicast admin-state enable
            set / network-instance default protocols isis instance isis1 interface lo0.20 ipv6-unicast admin-state enable
            set / network-instance default protocols bgp admin-state enable autonomous-system 65001 router-id 1.1.1.1
            set / network-instance default protocols bgp afi-safi ipv4-unicast admin-state enable
            set / network-instance default protocols bgp afi-safi ipv6-unicast admin-state enable
            set / network-instance default protocols bgp ebgp-default-policy import-reject-all false export-reject-all false
            set / network-instance default protocols bgp group pg1 admin-state enable peer-as 65002 export-policy [ bgp-export ]
            set / network-instance default protocols bgp group pg1 afi-safi ipv4-unicast admin-state enable
            set / network-instance default protocols bgp group pg1 afi-safi ipv6-unicast admin-state enable
            set / network-instance default protocols bgp neighbor 10.1.2.2 admin-state enable peer-group pg1
            set / network-instance default protocols bgp neighbor 2001:db8:12::2 admin-state enable peer-group pg1
            """,
        )

        # 2. Configure SRL2 to peer with SRL1 via OSPFv2, OSPFv3, BGP (v4/v6), IS-IS (v4/v6), plus static routes (v4/v6), and redistribute all into EIGRP
        apply_cfg(
            srl_exec,
            "clab-eigrp-test-srl2",
            """
            set / network-instance default next-hop-groups group nhg-static4 admin-state enable nexthop 1 ip-address 10.1.2.1 admin-state enable
            set / network-instance default static-routes route 172.16.30.0/24 admin-state enable next-hop-group nhg-static4
            set / network-instance default next-hop-groups group nhg-static6 admin-state enable nexthop 1 ip-address 2001:db8:12::1 admin-state enable
            set / network-instance default static-routes route 2001:db8:30::/64 admin-state enable next-hop-group nhg-static6
            set / network-instance default protocols ospf instance ospf2 admin-state enable version ospf-v2 router-id 2.2.2.2 area 0.0.0.0 interface ethernet-1/1.0 admin-state enable interface-type point-to-point
            set / network-instance default protocols ospf instance ospf3 admin-state enable version ospf-v3 router-id 2.2.2.2 address-family ipv6-unicast
            set / network-instance default protocols ospf instance ospf3 area 0.0.0.0 interface ethernet-1/1.0 admin-state enable interface-type point-to-point
            set / network-instance default protocols isis instance isis1 admin-state enable net [ 49.0001.0000.0000.0002.00 ]
            set / network-instance default protocols isis instance isis1 ipv4-unicast admin-state enable
            set / network-instance default protocols isis instance isis1 ipv6-unicast admin-state enable
            set / network-instance default protocols isis instance isis1 interface ethernet-1/1.0 admin-state enable circuit-type point-to-point ipv4-unicast admin-state enable
            set / network-instance default protocols isis instance isis1 interface ethernet-1/1.0 ipv6-unicast admin-state enable
            set / network-instance default protocols bgp admin-state enable autonomous-system 65002 router-id 2.2.2.2
            set / network-instance default protocols bgp afi-safi ipv4-unicast admin-state enable
            set / network-instance default protocols bgp afi-safi ipv6-unicast admin-state enable
            set / network-instance default protocols bgp ebgp-default-policy import-reject-all false export-reject-all false
            set / network-instance default protocols bgp group pg1 admin-state enable peer-as 65001
            set / network-instance default protocols bgp group pg1 afi-safi ipv4-unicast admin-state enable
            set / network-instance default protocols bgp group pg1 afi-safi ipv6-unicast admin-state enable
            set / network-instance default protocols bgp neighbor 10.1.2.1 admin-state enable peer-group pg1
            set / network-instance default protocols bgp neighbor 2001:db8:12::1 admin-state enable peer-group pg1
            set / routing-policy policy redist-pol statement 10 match protocol static
            set / routing-policy policy redist-pol statement 10 action policy-result accept eigrp metric bandwidth 100000 delay 100 reliability 255 load 1 mtu 1500
            set / routing-policy policy redist-pol statement 20 match protocol ospfv2
            set / routing-policy policy redist-pol statement 20 action policy-result accept
            set / routing-policy policy redist-pol statement 30 match protocol ospfv3
            set / routing-policy policy redist-pol statement 30 action policy-result accept
            set / routing-policy policy redist-pol statement 40 match protocol isis
            set / routing-policy policy redist-pol statement 40 action policy-result accept
            set / routing-policy policy redist-pol statement 50 match protocol bgp
            set / routing-policy policy redist-pol statement 50 action policy-result accept eigrp metric bandwidth 50000 delay 200 reliability 255 load 1 mtu 1500
            set / network-instance default protocols eigrp address-family ipv4-unicast default-metric bandwidth 100000 delay 100 reliability 255 load 1 mtu 1500
            set / network-instance default protocols eigrp address-family ipv6-unicast default-metric bandwidth 100000 delay 100 reliability 255 load 1 mtu 1500
            set / network-instance default protocols eigrp address-family ipv4-unicast export-policy redist-pol
            set / network-instance default protocols eigrp address-family ipv6-unicast export-policy redist-pol
            """,
        )

        expected_prefixes = [
            "172.16.10.1/32",      # OSPFv2
            "2001:db8:10::1/128",  # OSPFv3
            "172.16.20.1/32",      # IS-IS IPv4
            "2001:db8:20::1/128",  # IS-IS IPv6
            "172.16.30.0/24",      # Static IPv4
            "2001:db8:30::/64",    # Static IPv6
            "172.16.40.0/24",      # BGP IPv4
            "2001:db8:40::/64",    # BGP IPv6
        ]

        redist_ok = False
        out_srl5_routes = ""
        out_srl5_top = ""
        for _ in range(60):
            time.sleep(1)
            out_srl5_routes = srl_exec("clab-eigrp-test-srl5", ["sr_cli", "show network-instance default protocols eigrp routes"])
            out_srl5_top = srl_exec("clab-eigrp-test-srl5", ["sr_cli", "show network-instance default protocols eigrp topology"])
            if all(pfx in out_srl5_routes for pfx in expected_prefixes) and all(
                f"P {pfx}, 2 successors" in out_srl5_top for pfx in expected_prefixes
            ):
                redist_ok = True
                break
        assert redist_ok, (
            f"Not all redistributed external routes (OSPFv2, OSPFv3, IS-IS v4/v6, BGP v4/v6, Static v4/v6) "
            f"reached SRL5 with 2 ECMP successors: routes={out_srl5_routes}\ntop={out_srl5_top}"
        )
        assert "External" in out_srl5_routes and "170" in out_srl5_routes

        # Verify that triggering eigrp_topology_metric_update() on SRL2 (via interface delay update) preserves
        # self-originated redistributed route successor status (RD=0) and scaled delay (FD=13107200 for bw=100000, delay=100)
        apply_cfg(srl_exec, "clab-eigrp-test-srl2", "set / network-instance default protocols eigrp interface ethernet-1/3.0 delay 20")
        time.sleep(2)
        out_srl2_top = srl_exec("clab-eigrp-test-srl2", ["sr_cli", "show network-instance default protocols eigrp topology"])
        assert "P 172.16.30.0/24, 1 successors, FD is 13107200" in out_srl2_top and "(13107200/0)" in out_srl2_top, (
            f"Self-originated redistributed route 172.16.30.0/24 lost Successor or scaled delay after metric update on SRL2: {out_srl2_top}"
        )
        apply_cfg(srl_exec, "clab-eigrp-test-srl2", "delete / network-instance default protocols eigrp interface ethernet-1/3.0 delay")

        # 3. Verify withdrawal when export-policy is removed on SRL2
        apply_cfg(
            srl_exec,
            "clab-eigrp-test-srl2",
            """
            delete / network-instance default protocols eigrp address-family ipv4-unicast export-policy
            delete / network-instance default protocols eigrp address-family ipv6-unicast export-policy
            """,
        )
        withdrawn_ok = False
        for _ in range(25):
            time.sleep(1)
            out_srl5_routes = srl_exec("clab-eigrp-test-srl5", ["sr_cli", "show network-instance default protocols eigrp routes"])
            if all(pfx not in out_srl5_routes for pfx in expected_prefixes):
                withdrawn_ok = True
                break
        assert withdrawn_ok, f"Redistributed routes were not withdrawn from SRL5: {out_srl5_routes}"
    finally:
        for node in ["clab-eigrp-test-srl1", "clab-eigrp-test-srl2"]:
            apply_cfg(
                srl_exec,
                node,
                """
                delete / network-instance default protocols ospf
                delete / network-instance default protocols isis
                delete / network-instance default protocols bgp
                delete / network-instance default static-routes
                delete / network-instance default next-hop-groups
                delete / routing-policy policy redist-pol
                delete / routing-policy policy bgp-export
                delete / network-instance default interface lo0.10
                delete / network-instance default interface lo0.20
                delete / interface lo0
                """,
            )
        restore_5node_baseline(srl_exec)
        assert wait_for_5node_convergence(srl_exec, timeout=25)


def test_5node_secondary_vrf1(srl_exec):
    """Verify secondary ip-vrf (vrf-1) IPv4 and IPv6 EIGRP peering, FIB installation, CLI telemetry, and dataplane ping on 5-node lab."""
    try:
        apply_cfg(
            srl_exec,
            "clab-eigrp-test-srl1",
            """
            set / interface ethernet-1/1 vlan-tagging true
            set / interface ethernet-1/1 subinterface 0 vlan encap single-tagged vlan-id 1
            set / interface ethernet-1/1 subinterface 1 admin-state enable vlan encap single-tagged vlan-id 100
            set / interface ethernet-1/1 subinterface 1 ipv4 admin-state enable address 10.100.12.1/24
            set / interface ethernet-1/1 subinterface 1 ipv6 admin-state enable address 2001:db8:100:12::1/64
            set / interface lo0 admin-state enable subinterface 1 admin-state enable ipv4 admin-state enable address 192.0.2.11/32
            set / interface lo0 subinterface 1 ipv6 admin-state enable address 2001:db8:100::11/128
            set / network-instance vrf-1 type ip-vrf admin-state enable
            set / network-instance vrf-1 interface ethernet-1/1.1
            set / network-instance vrf-1 interface lo0.1
            set / network-instance vrf-1 protocols eigrp admin-state enable autonomous-system 200 router-id 192.0.2.11
            set / network-instance vrf-1 protocols eigrp address-family ipv4-unicast admin-state enable
            set / network-instance vrf-1 protocols eigrp address-family ipv6-unicast admin-state enable
            set / network-instance vrf-1 protocols eigrp interface ethernet-1/1.1 address-family ipv4-unicast admin-state enable
            set / network-instance vrf-1 protocols eigrp interface ethernet-1/1.1 address-family ipv6-unicast admin-state enable
            set / network-instance vrf-1 protocols eigrp interface lo0.1 address-family ipv4-unicast passive true
            set / network-instance vrf-1 protocols eigrp interface lo0.1 address-family ipv6-unicast passive true
            """,
        )
        apply_cfg(
            srl_exec,
            "clab-eigrp-test-srl2",
            """
            set / interface ethernet-1/1 vlan-tagging true
            set / interface ethernet-1/1 subinterface 0 vlan encap single-tagged vlan-id 1
            set / interface ethernet-1/1 subinterface 1 admin-state enable vlan encap single-tagged vlan-id 100
            set / interface ethernet-1/1 subinterface 1 ipv4 admin-state enable address 10.100.12.2/24
            set / interface ethernet-1/1 subinterface 1 ipv6 admin-state enable address 2001:db8:100:12::2/64
            set / interface lo0 admin-state enable subinterface 1 admin-state enable ipv4 admin-state enable address 192.0.2.22/32
            set / interface lo0 subinterface 1 ipv6 admin-state enable address 2001:db8:100::22/128
            set / network-instance vrf-1 type ip-vrf admin-state enable
            set / network-instance vrf-1 interface ethernet-1/1.1
            set / network-instance vrf-1 interface lo0.1
            set / network-instance vrf-1 protocols eigrp admin-state enable autonomous-system 200 router-id 192.0.2.22
            set / network-instance vrf-1 protocols eigrp address-family ipv4-unicast admin-state enable
            set / network-instance vrf-1 protocols eigrp address-family ipv6-unicast admin-state enable
            set / network-instance vrf-1 protocols eigrp interface ethernet-1/1.1 address-family ipv4-unicast admin-state enable
            set / network-instance vrf-1 protocols eigrp interface ethernet-1/1.1 address-family ipv6-unicast admin-state enable
            set / network-instance vrf-1 protocols eigrp interface lo0.1 address-family ipv4-unicast passive true
            set / network-instance vrf-1 protocols eigrp interface lo0.1 address-family ipv6-unicast passive true
            """,
        )

        vrf_ok = False
        out_routes = ""
        out_fib4 = ""
        out_fib6 = ""
        for _ in range(30):
            time.sleep(1)
            out_routes = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "show network-instance vrf-1 protocols eigrp routes"])
            out_fib4 = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "show network-instance vrf-1 ipv4 route 192.0.2.22/32"])
            out_fib6 = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "show network-instance vrf-1 ipv6 route 2001:db8:100::22/128"])
            if (
                "192.0.2.22/32" in out_routes
                and "2001:db8:100::22/128" in out_routes
                and "192.0.2.22/32" in out_fib4
                and "10.100.12.2" in out_fib4
                and "eigrp" in out_fib4
                and "2001:db8:100:12::2" in out_fib6
                and "eigrp" in out_fib6
            ):
                vrf_ok = True
                break
        assert vrf_ok, f"VRF-1 IPv4/IPv6 routes not installed in SRL1 FIB: routes={out_routes}\nv4={out_fib4}\nv6={out_fib6}"

        out_vrf_sum = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "show network-instance vrf-1 protocols eigrp summary"])
        assert "200" in out_vrf_sum and "192.0.2.11" in out_vrf_sum

        out_ping4 = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "ping 192.0.2.22 network-instance vrf-1 -c 3"])
        assert "0% packet loss" in out_ping4 or "3 received" in out_ping4 or "3 packets received" in out_ping4, f"VRF-1 IPv4 ping failed: {out_ping4}"

        out_ping6 = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "ping6 2001:db8:100::22 network-instance vrf-1 -c 3"])
        assert "0% packet loss" in out_ping6 or "3 received" in out_ping6 or "3 packets received" in out_ping6, f"VRF-1 IPv6 ping failed: {out_ping6}"
    finally:
        for node in ["clab-eigrp-test-srl1", "clab-eigrp-test-srl2"]:
            apply_cfg(
                srl_exec,
                node,
                """
                delete / network-instance vrf-1
                delete / interface ethernet-1/1 subinterface 1
                delete / interface ethernet-1/1 subinterface 0 vlan
                delete / interface ethernet-1/1 vlan-tagging
                delete / interface lo0
                """,
            )
        restore_5node_baseline(srl_exec)
        assert wait_for_5node_convergence(srl_exec, timeout=25)


def test_5node_timers_maxprefix_bwpercent_ribscale_and_tools(srl_exec):
    """Verify timers, passive-interface, split-horizon, next-hop-self, bandwidth-percent, rib-scale, maximum-prefix (warning-only and hard limit), AF toggle, operational tools, and show/State DB on 5-node lab."""
    try:
        # 1. check-cpm
        out_cpm = srl_exec("clab-eigrp-test-srl2", ["sr_cli", "tools network-instance default protocols eigrp check-cpm"])
        assert "Verifying Control Plane Protection" in out_cpm and "[OK]" in out_cpm

        # 2. rib-scale 64 on SRL5
        apply_cfg(srl_exec, "clab-eigrp-test-srl5", "set / network-instance default protocols eigrp rib-scale 64")
        scaled_ok = False
        for _ in range(15):
            time.sleep(1)
            out_fib = srl_exec("clab-eigrp-test-srl5", ["sr_cli", "show network-instance default ipv4 route 1.1.1.1/32"])
            if "51200" in out_fib:  # 3276800 / 64 == 51200
                scaled_ok = True
                break
        assert scaled_ok, f"rib-scale 64 did not scale 3276800 to 51200 on SRL5: {out_fib}"

        # 3. Custom timers (hello-interval 2, hold-time 6, active-time 2), bandwidth-percent 250, split-horizon false, next-hop-self true on SRL1
        apply_cfg(
            srl_exec,
            "clab-eigrp-test-srl1",
            """
            set / network-instance default protocols eigrp timers active-time 2
            set / network-instance default protocols eigrp interface ethernet-1/1.0 address-family ipv4-unicast hello-interval 2 hold-time 6 bandwidth-percent 250 split-horizon false next-hop-self true
            """,
        )
        apply_cfg(
            srl_exec,
            "clab-eigrp-test-srl2",
            "set / network-instance default protocols eigrp interface ethernet-1/1.0 address-family ipv4-unicast hello-interval 2 hold-time 6",
        )
        if_ok = False
        out_if = ""
        for _ in range(15):
            time.sleep(1)
            out_if = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "show network-instance default protocols eigrp interfaces ethernet-1/1.0"])
            if (
                "250%" in out_if
                and "Hello Interval        : 2s" in out_if
                and "Hold Time             : 6s" in out_if
                and "Split Horizon         : false" in out_if
                and "Next-Hop-Self         : true" in out_if
            ):
                if_ok = True
                break
        assert if_ok, f"Interface parameters (timers, bandwidth-percent, split-horizon, next-hop-self) not reflected in CLI: {out_if}"

        # 4. Maximum-prefix warning-only true (retains routes) vs warning-only false (caps topology table)
        apply_cfg(
            srl_exec,
            "clab-eigrp-test-srl1",
            "set / network-instance default protocols eigrp address-family ipv4-unicast maximum-prefix limit 3 threshold 50 warning-only true",
        )
        time.sleep(2)
        out_warn_top = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "show network-instance default protocols eigrp topology"])
        warn_p_count = len(re.findall(r"^P\s+", out_warn_top, re.MULTILINE))
        assert warn_p_count >= 10, f"warning-only true unexpectedly dropped topology prefixes (count={warn_p_count}): {out_warn_top}"

        apply_cfg(
            srl_exec,
            "clab-eigrp-test-srl1",
            "set / network-instance default protocols eigrp address-family ipv4-unicast maximum-prefix limit 3 threshold 50 warning-only false",
        )
        limit_ok = False
        for _ in range(15):
            time.sleep(1)
            out_top = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "show network-instance default protocols eigrp topology"])
            p_count = len(re.findall(r"^P\s+", out_top, re.MULTILINE))
            if p_count <= 3:
                limit_ok = True
                break
        assert limit_ok, f"Strict maximum-prefix limit 3 did not cap topology entries on SRL1: {out_top}"

        apply_cfg(srl_exec, "clab-eigrp-test-srl1", "delete / network-instance default protocols eigrp address-family ipv4-unicast maximum-prefix")
        out_tclr = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "tools network-instance default protocols eigrp topology clear"])
        assert "Success" in out_tclr or "Cleared" in out_tclr
        assert wait_for_5node_convergence(srl_exec, timeout=20)

        # 4b. Verify maximum-prefix route replacement and re-advertisement admission (Defect 3):
        #     SRL2 has 11 baseline prefixes. Set limit 12 on SRL2, advertise 192.0.2.101/32 from SRL1 (12/12 admitted),
        #     replace 192.0.2.101/32 with 192.0.2.102/32 in a single commit (must NOT count poisoned 192.0.2.101/32 as a 13th prefix),
        #     then re-add 192.0.2.101/32 while 192.0.2.102/32 is still present (must reject 192.0.2.101/32 at 12/12).
        apply_cfg(
            srl_exec,
            "clab-eigrp-test-srl2",
            "set / network-instance default protocols eigrp address-family ipv4-unicast maximum-prefix limit 12 threshold 75 warning-only false",
        )
        apply_cfg(
            srl_exec,
            "clab-eigrp-test-srl1",
            """
            set / network-instance default next-hop-groups group nhg-mp admin-state enable nexthop 1 ip-address 10.1.2.2 admin-state enable
            set / routing-policy policy mp-pol statement 10 match protocol static
            set / routing-policy policy mp-pol statement 10 action policy-result accept
            set / network-instance default protocols eigrp address-family ipv4-unicast default-metric bandwidth 100000 delay 100 reliability 255 load 1 mtu 1500
            set / network-instance default protocols eigrp address-family ipv4-unicast export-policy mp-pol
            set / network-instance default static-routes route 192.0.2.101/32 admin-state enable next-hop-group nhg-mp
            """,
        )
        mp_first_ok = False
        out_srl2_top = ""
        for _ in range(15):
            time.sleep(1)
            out_srl2_top = srl_exec("clab-eigrp-test-srl2", ["sr_cli", "show network-instance default protocols eigrp topology"])
            if "P 192.0.2.101/32, 1 successors" in out_srl2_top:
                mp_first_ok = True
                break
        assert mp_first_ok, f"SRL2 did not admit 12th prefix 192.0.2.101/32 under limit 12: {out_srl2_top}"

        apply_cfg(
            srl_exec,
            "clab-eigrp-test-srl1",
            """
            delete / network-instance default static-routes route 192.0.2.101/32
            set / network-instance default static-routes route 192.0.2.102/32 admin-state enable next-hop-group nhg-mp
            """,
        )
        mp_replace_ok = False
        for _ in range(15):
            time.sleep(1)
            out_srl2_top = srl_exec("clab-eigrp-test-srl2", ["sr_cli", "show network-instance default protocols eigrp topology"])
            if "P 192.0.2.102/32, 1 successors" in out_srl2_top and "192.0.2.101/32" not in out_srl2_top:
                mp_replace_ok = True
                break
        assert mp_replace_ok, f"SRL2 rejected replacement prefix 192.0.2.102/32 due to poisoned 192.0.2.101/32 counting toward limit 12: {out_srl2_top}"

        apply_cfg(
            srl_exec,
            "clab-eigrp-test-srl1",
            "set / network-instance default static-routes route 192.0.2.101/32 admin-state enable next-hop-group nhg-mp",
        )
        time.sleep(3)
        out_srl2_top = srl_exec("clab-eigrp-test-srl2", ["sr_cli", "show network-instance default protocols eigrp topology"])
        assert "P 192.0.2.102/32, 1 successors" in out_srl2_top and "192.0.2.101/32" not in out_srl2_top, (
            f"Re-advertised 13th prefix 192.0.2.101/32 bypassed maximum-prefix limit 12 on SRL2: {out_srl2_top}"
        )

        apply_cfg(
            srl_exec,
            "clab-eigrp-test-srl1",
            """
            delete / network-instance default protocols eigrp address-family ipv4-unicast export-policy
            delete / network-instance default protocols eigrp address-family ipv4-unicast default-metric
            delete / routing-policy policy mp-pol
            delete / network-instance default static-routes
            delete / network-instance default next-hop-groups
            """,
        )
        apply_cfg(srl_exec, "clab-eigrp-test-srl2", "delete / network-instance default protocols eigrp address-family ipv4-unicast maximum-prefix")

        # 5. Enable IPv6 across all 5 nodes, then verify passive-interface suppression/recovery and rapid IPv6 AF toggle
        for node, cfg in IPV6_CFGS.items():
            apply_cfg(srl_exec, node, cfg)

        v6_ready = False
        for _ in range(25):
            time.sleep(1)
            out_nbr = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "show network-instance default protocols eigrp neighbor"])
            if "10.1.2.2" in out_nbr and "fe80::" in out_nbr:
                v6_ready = True
                break
        assert v6_ready, f"IPv6 neighbor did not come up on SRL1: {out_nbr}"

        apply_cfg(
            srl_exec,
            "clab-eigrp-test-srl1",
            """
            set / network-instance default protocols eigrp interface ethernet-1/1.0 address-family ipv4-unicast passive true
            set / network-instance default protocols eigrp interface ethernet-1/1.0 address-family ipv6-unicast passive true
            """,
        )
        srl_exec("clab-eigrp-test-srl1", ["sr_cli", "tools network-instance default protocols eigrp neighbor reset-all"])
        time.sleep(2)
        out_pass_nbr = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "show network-instance default protocols eigrp neighbor"])
        assert "No active EIGRP neighbors found" in out_pass_nbr or "passive" in out_pass_nbr.lower(), f"Neighbors still active when all interfaces passive: {out_pass_nbr}"

        apply_cfg(
            srl_exec,
            "clab-eigrp-test-srl1",
            """
            set / network-instance default protocols eigrp interface ethernet-1/1.0 address-family ipv4-unicast passive false
            set / network-instance default protocols eigrp interface ethernet-1/1.0 address-family ipv6-unicast passive false
            """,
        )
        pass_rec = False
        for _ in range(25):
            time.sleep(1)
            out_nbr = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "show network-instance default protocols eigrp neighbor"])
            if "10.1.2.2" in out_nbr and "fe80::" in out_nbr:
                pass_rec = True
                break
        assert pass_rec, f"Neighbors did not recover after disabling passive on SRL1: {out_nbr}"

        # Rapid IPv6 address-family disable/enable toggle on SRL1
        apply_cfg(
            srl_exec,
            "clab-eigrp-test-srl1",
            "set / network-instance default protocols eigrp address-family ipv6-unicast admin-state disable",
        )
        apply_cfg(
            srl_exec,
            "clab-eigrp-test-srl1",
            "set / network-instance default protocols eigrp address-family ipv6-unicast admin-state enable",
        )
        v6_rec = False
        for _ in range(25):
            time.sleep(1)
            out_v6 = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "show network-instance default ipv6 route 2001:db8::5/128"])
            if "2001:db8::5/128" in out_v6 and "eigrp" in out_v6:
                v6_rec = True
                break
        assert v6_rec, f"IPv6 route 2001:db8::5/128 did not recover after rapid AF toggle on SRL1: {out_v6}"

        # 6. Operational tools: statistics clear, event-log clear, neighbor clear, graceful-shutdown
        out_sclr = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "tools network-instance default protocols eigrp statistics clear"])
        assert "Success" in out_sclr or "Cleared" in out_sclr, f"statistics clear failed: {out_sclr}"

        out_eclr = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "tools network-instance default protocols eigrp event-log clear"])
        assert "Success" in out_eclr or "Cleared" in out_eclr, f"event-log clear failed: {out_eclr}"

        out_nclr = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "tools network-instance default protocols eigrp neighbor clear 10.1.2.2"])
        assert "Success" in out_nclr or "Cleared" in out_nclr, f"neighbor clear failed: {out_nclr}"

        out_gshut = srl_exec("clab-eigrp-test-srl1", ["sr_cli", "tools network-instance default protocols eigrp graceful-shutdown"])
        assert "Success" in out_gshut or "Goodbye" in out_gshut, f"graceful-shutdown failed: {out_gshut}"

        assert wait_for_5node_convergence(srl_exec, timeout=25)

        # 7. Show CLI & State DB telemetry verification
        out_sum = srl_exec("clab-eigrp-test-srl3", ["sr_cli", "show network-instance default protocols eigrp summary"])
        assert "Operational State       : up" in out_sum and "3.3.3.3" in out_sum
        out_tf = srl_exec("clab-eigrp-test-srl3", ["sr_cli", "show network-instance default protocols eigrp traffic"])
        assert "ethernet-1/1.0" in out_tf
        out_state = srl_exec("clab-eigrp-test-srl3", ["sr_cli", "info from state network-instance default protocols eigrp oper-state"])
        assert "up" in out_state
    finally:
        restore_5node_baseline(srl_exec)
        srl_exec("clab-eigrp-test-srl1", ["sr_cli", "tools network-instance default protocols eigrp topology clear"])
        assert wait_for_5node_convergence(srl_exec, timeout=25)

