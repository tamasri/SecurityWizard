import pytest

import checks_access
from common import STATUS_INFO, STATUS_SKIPPED, STATUS_WARNING


def _make_rsa_key(bits=2048):
    """Create a fake RSA authorized_keys line."""
    # Simulate a base64-encoded RSA key blob
    import base64

    # For RSA, the blob structure is: length(e) | e | length(n) | n
    # We'll just use a fixed base64 string that decodes to something
    blob = b"\x00\x00\x00\x03\x01\x00\x01\x00\x00\x01\x00" + b"\x00" * (bits // 8)
    return "ssh-rsa " + base64.b64encode(blob).decode() + " test@example.com"


def _make_ed25519_key():
    import base64

    blob = b"\x00" * 32
    return "ssh-ed25519 " + base64.b64encode(blob).decode() + " ed25519@example.com"


def _make_dsa_key():
    import base64

    blob = b"\x00" * 128
    return "ssh-dss " + base64.b64encode(blob).decode() + " dsa@example.com"


def test_unrestricted_root_key_is_warning():
    key_line = _make_rsa_key(2048)
    results = checks_access.run_checks(
        root_authorized_keys=key_line,
        users_authorized_keys={},
        sudoers_paths=["/etc/sudoers"],
        group_file_content="docker:x:999:\n",
    )
    acc001 = [r for r in results if r["id"] == "ACC-001"]
    assert len(acc001) >= 1
    # Unrestricted RSA 2048 is a warning
    warnings = [r for r in acc001 if r["status"] == STATUS_WARNING]
    assert len(warnings) >= 1


def test_restricted_forced_command_key_is_info():
    key_line = 'command="/usr/bin/deploy",from="10.0.0.0/8" ' + _make_ed25519_key()
    results = checks_access.run_checks(
        root_authorized_keys=key_line,
        users_authorized_keys={},
        sudoers_paths=["/etc/sudoers"],
        group_file_content="docker:x:999:\n",
    )
    acc001 = [r for r in results if r["id"] == "ACC-001"]
    assert len(acc001) >= 1
    infos = [r for r in acc001 if r["status"] == STATUS_INFO]
    assert len(infos) >= 1


def test_dsa_key_is_warning():
    key_line = _make_dsa_key()
    results = checks_access.run_checks(
        root_authorized_keys=key_line,
        users_authorized_keys={},
        sudoers_paths=["/etc/sudoers"],
        group_file_content="docker:x:999:\n",
    )
    acc001 = [r for r in results if r["id"] == "ACC-001"]
    assert len(acc001) >= 1
    warnings = [r for r in acc001 if r["status"] == STATUS_WARNING]
    assert len(warnings) >= 1


def test_docker_group_members_warning():
    group_content = "docker:x:999:alice,bob\n"
    results = checks_access.run_checks(
        root_authorized_keys="",
        users_authorized_keys={},
        sudoers_paths=["/etc/sudoers"],
        group_file_content=group_content,
    )
    acc003 = [r for r in results if r["id"] == "ACC-003"]
    assert len(acc003) == 1
    assert acc003[0]["status"] == STATUS_WARNING
    assert "alice" in acc003[0]["current_value"]


def test_docker_group_expected_users_info():
    group_content = "docker:x:999:root\n"
    results = checks_access.run_checks(
        root_authorized_keys="",
        users_authorized_keys={},
        sudoers_paths=["/etc/sudoers"],
        group_file_content=group_content,
    )
    acc003 = [r for r in results if r["id"] == "ACC-003"]
    assert len(acc003) == 1
    assert acc003[0]["status"] == STATUS_INFO


def test_permission_error_skipped():
    import builtins

    original_open = builtins.open

    def mock_open(path, *args, **kwargs):
        if path == "/root/.ssh/authorized_keys":
            raise PermissionError("Permission denied")
        return original_open(path, *args, **kwargs)

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(builtins, "open", mock_open)
    results = checks_access.run_checks(
        sudoers_paths=["/etc/sudoers"],
        group_file_content="docker:x:999:\n",
    )
    acc001 = [r for r in results if r["id"] == "ACC-001"]
    assert len(acc001) == 1
    assert acc001[0]["status"] == STATUS_SKIPPED
    assert "Permission denied" in acc001[0]["current_value"]
    monkeypatch.undo()
