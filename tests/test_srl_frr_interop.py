import subprocess
import time
import pytest

def is_frr_lab_running():
    try:
        res = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", "clab-srl-frr-eigrp-frr1"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        return res.returncode == 0 and res.stdout.strip() == "true"
    except Exception:
        return False

pytestmark = pytest.mark.skipif(
    not is_frr_lab_running(),
    reason="FRR interop lab (clab-srl-frr-eigrp) is not deployed",
)

def test_frr_neighbor_established(srl_exec):
    """Verify FRR sees SRL1 as an active EIGRP neighbor."""
    out = ""
    for _ in range(15):
        time.sleep(3)
        out = srl_exec("clab-srl-frr-eigrp-frr1", ["vtysh", "-c", "show ip eigrp neighbors"])
        if "10.0.0.1" in out:
            break
    assert "10.0.0.1" in out, f"SRL1 neighbor missing in FRR: {out}"

def test_frr_route_in_srl_fib(srl_exec):
    """Verify FRR's loopback (192.0.2.2/32) is installed in SRL1's FIB."""
    out = ""
    for _ in range(15):
        time.sleep(2)
        out = srl_exec("clab-srl-frr-eigrp-srl1", [
            "sr_cli", "show network-instance default ipv4 route"
        ])
        if "192.0.2.2/32" in out and ("10.0.0.2" in out or "ndk1" in out):
            break
    assert "192.0.2.2/32" in out, f"FRR route not in SRL FIB: {out}"

def test_srl_route_in_frr_rib(srl_exec):
    """Verify SRL1's loopback (192.0.2.1/32) is installed in FRR's RIB."""
    out = ""
    for _ in range(15):
        time.sleep(2)
        out = srl_exec("clab-srl-frr-eigrp-frr1", ["vtysh", "-c", "show ip route eigrp"])
        if "192.0.2.1" in out:
            break
    assert "192.0.2.1" in out, f"SRL1 route missing in FRR RIB: {out}"

def test_dataplane_ping_srl_to_frr(srl_exec):
    """Verify dataplane ping from SRL1 to FRR loopback."""
    out = ""
    for _ in range(5):
        out = srl_exec("clab-srl-frr-eigrp-srl1", [
            "sr_cli", "ping 192.0.2.2 network-instance default -c 3"
        ])
        if "0% packet loss" in out or "3 received" in out:
            break
        time.sleep(2)
    assert "0% packet loss" in out or "3 received" in out, f"Ping SRL->FRR failed: {out}"

def test_dataplane_ping_frr_to_srl(srl_exec):
    """Verify dataplane ping from FRR to SRL1 loopback."""
    out = ""
    for _ in range(5):
        out = srl_exec("clab-srl-frr-eigrp-frr1", [
            "ping", "-c", "3", "192.0.2.1"
        ])
        if "0% packet loss" in out or "3 received" in out:
            break
        time.sleep(2)
    assert "0% packet loss" in out or "3 received" in out, f"Ping FRR->SRL failed: {out}"

def test_show_eigrp_cli_frr(srl_exec):
    """Verify SRL1 CLI show reports for FRR peering."""
    out_summary = srl_exec("clab-srl-frr-eigrp-srl1", [
        "sr_cli", "show network-instance default protocols eigrp summary"
    ])
    assert "Autonomous System" in out_summary and "100" in out_summary, f"CLI summary show failed: {out_summary}"

    out_nbr = srl_exec("clab-srl-frr-eigrp-srl1", [
        "sr_cli", "show network-instance default protocols eigrp neighbor"
    ])
    assert "10.0.0.2" in out_nbr and "Up" in out_nbr, f"CLI neighbor show failed: {out_nbr}"

    out_routes = srl_exec("clab-srl-frr-eigrp-srl1", [
        "sr_cli", "show network-instance default protocols eigrp routes"
    ])
    assert "192.0.2.2/32" in out_routes and "10.0.0.2" in out_routes, f"CLI routes show failed: {out_routes}"

    out_if = srl_exec("clab-srl-frr-eigrp-srl1", [
        "sr_cli", "show network-instance default protocols eigrp interfaces"
    ])
    assert "ethernet-1/1.0" in out_if and "10.0.0.1" in out_if, f"CLI interfaces show failed: {out_if}"

