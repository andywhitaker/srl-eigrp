import pytest
import subprocess

@pytest.fixture(scope="session")
def srl_exec():
    def _exec(container, cmd):
        full_cmd = ["docker", "exec", container] + cmd
        res = subprocess.run(full_cmd, capture_output=True, text=True, check=True)
        return res.stdout
    return _exec
