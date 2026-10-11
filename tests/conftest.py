import pytest
import subprocess
import os

@pytest.fixture(scope="session")
def srl_exec():
    def _exec(container, cmd):
        full_cmd = ["docker", "exec", container] + cmd
        res = subprocess.run(full_cmd, capture_output=True, text=True, check=True)
        return res.stdout
    return _exec

@pytest.fixture(scope="session", autouse=True)
def restore_baselines_on_start(srl_exec):
    """Ensure running SRL nodes have baseline configurations applied cleanly before tests run."""
    try:
        res = subprocess.run(["docker", "ps", "-q", "-f", "name=clab-srl-srl-eigrp-srl1"], capture_output=True, text=True)
        if res.stdout.strip():
            with open("configs/srl1.cli", "r") as f:
                srl1_cfg = f.read()
            with open("configs/srl2.cli", "r") as f:
                srl2_cfg = f.read()
            srl_exec("clab-srl-srl-eigrp-srl1", ["bash", "-c", f"sr_cli << 'EOF'\nenter candidate\n{srl1_cfg}\ncommit now\nEOF"])
            srl_exec("clab-srl-srl-eigrp-srl2", ["bash", "-c", f"sr_cli << 'EOF'\nenter candidate\n{srl2_cfg}\ncommit now\nEOF"])
    except Exception:
        pass
