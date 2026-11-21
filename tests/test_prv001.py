"""Tests for PRV-001 SUID/SGID hunter (checks_privilege.py)."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from checks_privilege import _check_suid_sgid, build_find_cmd
from common import (
    STATUS_CRITICAL,
    STATUS_PASS,
    STATUS_SKIPPED,
    STATUS_WARNING,
)

# ---------------------------------------------------------------------------
# build_find_cmd tests
# ---------------------------------------------------------------------------


def test_build_find_cmd_paths_first():
    """Paths must appear before -xdev and before any expression."""
    paths = ["/usr/bin", "/usr/sbin", "/bin"]
    cmd = build_find_cmd(paths)
    # cmd[0] is "find", then the three paths
    assert cmd[0] == "find"
    assert cmd[1] == "/usr/bin"
    assert cmd[2] == "/usr/sbin"
    assert cmd[3] == "/bin"
    # -xdev comes after all paths
    assert cmd[4] == "-xdev"


def test_build_find_cmd_prune_exclusions():
    """All required prune exclusions must be present."""
    cmd = build_find_cmd(["/usr/bin"])
    expected_exclusions = [
        "/proc",
        "/sys",
        "/var/lib/docker",
        "/var/lib/containerd",
        "/snap",
        "/var/snap",
        "/var/lib/snapd",
    ]
    for ex in expected_exclusions:
        # Each exclusion appears as -path <ex> -prune -o
        idx = cmd.index("-path")
        while idx != -1:
            if cmd[idx + 1] == ex:
                assert cmd[idx + 2] == "-prune"
                assert cmd[idx + 3] == "-o"
                break
            idx = cmd.index("-path", idx + 1)
        else:
            pytest.fail("Exclusion %r not found in cmd: %s" % (ex, cmd))


def test_build_find_cmd_ends_with_perm_type():
    """The expression must end with -perm /6000 -type f."""
    cmd = build_find_cmd(["/usr/bin"])
    assert cmd[-4] == "-perm"
    assert cmd[-3] == "/6000"
    assert cmd[-2] == "-type"
    assert cmd[-1] == "f"


# ---------------------------------------------------------------------------
# _check_suid_sgid classification tests
# ---------------------------------------------------------------------------


def _make_config(allowed=None):
    """Return a mock config whose allowed_suid() uses the given set."""
    allowed = allowed or set()

    class _Cfg:
        def allowed_suid(self, path):
            return path in allowed

    return _Cfg()


def test_prv001_all_safe_dpkg(monkeypatch, tmp_path):
    """All binaries are dpkg-owned → PASS."""
    fake_find_out = "/usr/bin/sudo\n/usr/bin/passwd\n/usr/bin/mount\n"
    fake_dpkg_list = tmp_path / "sudo.list"
    fake_dpkg_list.write_text("/usr/bin/sudo\n/usr/bin/passwd\n/usr/bin/mount\n")

    monkeypatch.setattr("checks_privilege.os.path.isdir", lambda p: p in ("/usr/bin", "/bin"))
    monkeypatch.setattr("checks_privilege.run_cmd", lambda args, timeout=120: (0, fake_find_out, ""))
    monkeypatch.setattr(
        "checks_privilege.glob.glob",
        lambda pattern: [str(fake_dpkg_list)] if pattern == "/var/lib/dpkg/info/*.list" else [],
    )
    monkeypatch.setattr("checks_privilege.get_config", lambda: _make_config())

    result = _check_suid_sgid()
    assert result["status"] == STATUS_PASS
    assert result["id"] == "PRV-001"


def test_prv001_risky_gtfo(monkeypatch, tmp_path):
    """A risky GTFO binary (bash) is found → CRITICAL."""
    fake_find_out = "/usr/bin/bash\n/usr/bin/sudo\n"
    fake_dpkg_list = tmp_path / "sudo.list"
    fake_dpkg_list.write_text("/usr/bin/sudo\n")

    monkeypatch.setattr("checks_privilege.os.path.isdir", lambda p: p in ("/usr/bin", "/bin"))
    monkeypatch.setattr("checks_privilege.run_cmd", lambda args, timeout=120: (0, fake_find_out, ""))
    monkeypatch.setattr(
        "checks_privilege.glob.glob",
        lambda pattern: [str(fake_dpkg_list)] if pattern == "/var/lib/dpkg/info/*.list" else [],
    )
    monkeypatch.setattr("checks_privilege.get_config", lambda: _make_config())

    result = _check_suid_sgid()
    assert result["status"] == STATUS_CRITICAL
    assert "bash" in result["current_value"]


def test_prv001_unknown_not_dpkg(monkeypatch, tmp_path):
    """A binary not in baseline, not dpkg-owned, not risky → WARNING."""
    fake_find_out = "/opt/customtool\n/usr/bin/sudo\n"
    fake_dpkg_list = tmp_path / "sudo.list"
    fake_dpkg_list.write_text("/usr/bin/sudo\n")

    monkeypatch.setattr("checks_privilege.os.path.isdir", lambda p: p in ("/usr/bin", "/bin", "/opt"))
    monkeypatch.setattr("checks_privilege.run_cmd", lambda args, timeout=120: (0, fake_find_out, ""))
    monkeypatch.setattr(
        "checks_privilege.glob.glob",
        lambda pattern: [str(fake_dpkg_list)] if pattern == "/var/lib/dpkg/info/*.list" else [],
    )
    monkeypatch.setattr("checks_privilege.get_config", lambda: _make_config())

    result = _check_suid_sgid()
    assert result["status"] == STATUS_WARNING
    assert "customtool" in result["current_value"]


def test_prv001_allowed_suid_skips(monkeypatch, tmp_path):
    """A binary in the user allowlist is treated as ALLOWED, not unknown."""
    fake_find_out = "/opt/mytool\n/usr/bin/sudo\n"
    fake_dpkg_list = tmp_path / "sudo.list"
    fake_dpkg_list.write_text("/usr/bin/sudo\n")

    monkeypatch.setattr("checks_privilege.os.path.isdir", lambda p: p in ("/usr/bin", "/bin", "/opt"))
    monkeypatch.setattr("checks_privilege.run_cmd", lambda args, timeout=120: (0, fake_find_out, ""))
    monkeypatch.setattr(
        "checks_privilege.glob.glob",
        lambda pattern: [str(fake_dpkg_list)] if pattern == "/var/lib/dpkg/info/*.list" else [],
    )
    monkeypatch.setattr("checks_privilege.get_config", lambda: _make_config(allowed={"/opt/mytool"}))

    result = _check_suid_sgid()
    assert result["status"] == STATUS_PASS
    assert any("ALLOWED" in d for d in result["details"])


def test_prv001_find_failure_skipped(monkeypatch):
    """When find fails, the check returns SKIPPED with the stderr reason."""
    monkeypatch.setattr("checks_privilege.os.path.isdir", lambda p: p in ("/usr/bin", "/bin"))
    monkeypatch.setattr("checks_privilege.run_cmd", lambda args, timeout=120: (1, "", "Permission denied"))

    result = _check_suid_sgid()
    assert result["status"] == STATUS_SKIPPED
    assert "Permission denied" in result["current_value"]


def test_prv001_no_paths_skipped(monkeypatch):
    """When no scan paths exist, the check returns SKIPPED."""
    monkeypatch.setattr("checks_privilege.os.path.isdir", lambda p: False)

    result = _check_suid_sgid()
    assert result["status"] == STATUS_SKIPPED
    assert "No scan paths found" in result["current_value"]
