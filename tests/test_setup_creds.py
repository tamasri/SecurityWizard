import pathlib
import subprocess
import sys

import pytest

SETUP = pathlib.Path(__file__).resolve().parents[1] / "setup.sh"


@pytest.mark.skipif(sys.platform == "win32", reason="needs a real bash")
def test_setup_script_is_valid_bash():
    assert subprocess.run(["bash", "-n", str(SETUP)], capture_output=True, text=True).returncode == 0


def test_setup_explains_where_the_initial_credentials_are():
    text = SETUP.read_text(encoding="utf-8")
    assert "initial-credentials.txt" in text
    assert "journalctl -u securitywizard" in text
    assert "not forced" in text


def test_service_creates_the_directories_that_systemd_requires():
    text = SETUP.read_text(encoding="utf-8")
    assert text.index("mkdir -p /var/backups/securitywizard") < text.index(
        "cat > /etc/systemd/system/securitywizard.service"
    )
