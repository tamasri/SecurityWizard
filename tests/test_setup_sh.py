import subprocess
import sys

import pytest


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only behaviour (file replace semantics / a real bash)")
def test_setup_sh_syntax():
    result = subprocess.run(["bash", "-n", "setup.sh"], capture_output=True, text=True)
    assert result.returncode == 0, f"bash -n failed: {result.stderr}"


def test_setup_sh_contains_key_strings():
    with open("setup.sh", "r", encoding="utf-8") as f:
        content = f.read()
    assert "python3-venv" in content
    assert "import fastapi, uvicorn" in content
    assert "import main" in content
    assert "NoNewPrivileges=yes" in content
    assert "ProtectSystem=strict" in content
    assert "ProtectHome=read-only" in content
    assert "PrivateTmp=yes" in content
    assert "ReadWritePaths=/var/backups/securitywizard /etc /var/log" in content
    assert "CapabilityBoundingSet=" in content
    assert "RestrictAddressFamilies=" in content
    assert "SECURITYWIZARD_DRY_RUN_ONLY=1" in content
    assert "StartLimitIntervalSec=" in content
    assert "StartLimitBurst=" in content
    assert "set -e" not in content


def test_setup_sh_apt_update_not_fatal():
    with open("setup.sh", "r", encoding="utf-8") as f:
        content = f.read()
    assert "apt-get update ||" in content


def test_setup_sh_verifies_venv_python():
    with open("setup.sh", "r", encoding="utf-8") as f:
        content = f.read()
    assert "./venv/bin/python" in content
    assert "venv/bin/python" in content
