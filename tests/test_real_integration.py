"""Integration tests that use the real modules together (no mocking of our own helpers).

These exist because unit tests with hand-made fakes once hid real crashes: a missing Config method
and a command-result type that could not be unpacked.
"""

import re

import config
import scanner
from checks_docker import analyze_container

EXCEPTION_MARKERS = re.compile(
    r"(Traceback|AttributeError|TypeError|KeyError|NameError|IndexError|ValueError|cannot unpack|object has no attribute|not iterable|unexpected keyword)"
)


def test_config_exposes_every_allowlist_lookup_the_checks_use():
    cfg = config.Config()
    for method in (
        "allowed_listener",
        "allowed_docker_sock",
        "allowed_docker_privileged",
        "allowed_public_port",
        "allowed_sudo_rule",
        "allowed_suid",
    ):
        assert callable(getattr(cfg, method)), method


def test_container_analysis_works_with_the_default_configuration():
    """No allowlist_fn passed: exercises the real Config lookups for privileged and docker.sock containers."""
    config.reset_config()
    inspect = {
        "Name": "/proxy",
        "HostConfig": {"Privileged": True, "NetworkMode": "host", "PidMode": "host", "CapAdd": ["SYS_ADMIN"]},
        "Config": {"User": ""},
        "Mounts": [{"Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock", "RW": True}],
    }
    ids = {f["id"] for f in analyze_container(inspect)}
    assert {"DOC-002", "DOC-003", "DOC-004", "DOC-006"} <= ids


def test_a_real_scan_never_skips_a_check_because_of_a_python_error(monkeypatch):
    """Checks may be skipped when a tool is missing, but never because our own code raised."""
    monkeypatch.setenv("SECURITYWIZARD_CHECK_TIMEOUT", "25")  # keep slow filesystem walks bounded
    result = scanner.run_full_scan()
    crashed = [
        (c["id"], str(c.get("current_value", ""))[:120])
        for c in result["checks"]
        if c["status"] == "SKIPPED"
        and EXCEPTION_MARKERS.search(
            " ".join([str(c.get("current_value", ""))] + [str(d) for d in c.get("details", [])])
        )
    ]
    assert not crashed, crashed
