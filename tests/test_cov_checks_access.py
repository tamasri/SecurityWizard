"""checks_access: the full run_checks() flow reading files (regression: keys, users and groups were never evaluated)."""

import base64

import pytest

import checks_access
from common import STATUS_CRITICAL, STATUS_INFO, STATUS_PASS, STATUS_SKIPPED, STATUS_WARNING


def _string(data: bytes) -> bytes:
    return len(data).to_bytes(4, "big") + data


def _key(options="", comment="host", rsa_bits=None):
    if rsa_bits:
        modulus = ((1 << (rsa_bits - 1)) | 1).to_bytes((rsa_bits + 7) // 8 + 1, "big")
        blob = _string(b"ssh-rsa") + _string(b"\x01\x00\x01") + _string(modulus)
        key_type = "ssh-rsa"
    else:
        blob = _string(b"ssh-ed25519") + _string(bytes(range(32)))
        key_type = "ssh-ed25519"
    return " ".join(p for p in (options, key_type, base64.b64encode(blob).decode(), comment) if p)


@pytest.fixture
def fs(monkeypatch):
    """A fake file system for checks_access._read_file: path -> content, or an Exception to raise."""
    files = {}

    def read(path):
        if path not in files:
            return "", None
        value = files[path]
        if isinstance(value, Exception):
            return None, str(value)
        return value, None

    monkeypatch.setattr(checks_access, "_read_file", read)
    monkeypatch.setattr(checks_access, "SUDOERS_PATHS", [])
    return files


# ---- file reading ----------------------------------------------------------------------------------------------------


def test_read_file_returns_content_empty_for_missing_and_error_otherwise(tmp_path):
    present = tmp_path / "f"
    present.write_text("hello", encoding="utf-8")
    assert checks_access._read_file(str(present)) == ("hello", None)
    assert checks_access._read_file(str(tmp_path / "missing")) == ("", None)
    content, error = checks_access._read_file(str(tmp_path))  # a directory cannot be read as a file
    assert content is None and error


# ---- ACC-001 through run_checks ----------------------------------------------------------------------------------------


def test_run_checks_reads_root_and_user_keys_from_disk(fs):
    fs["/root/.ssh/authorized_keys"] = _key('command="/usr/bin/rsync --server . /srv",no-pty', "deploy") + "\n"
    fs["/etc/passwd"] = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "alice:x:1000:1000::/home/alice:/bin/bash\n"
        "bob:x:1001:1001::/home/bob/:/bin/bash\n"
        "daemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n"
        "short:line\n"
    )
    fs["/home/alice/.ssh/authorized_keys"] = _key("", "alice laptop") + "\n"
    fs["/home/bob/.ssh/authorized_keys"] = _key("restrict", "bob ci", rsa_bits=2048) + "\n"
    results = [r for r in checks_access.run_checks() if r["id"] == "ACC-001"]
    by_title = {r["title"]: r for r in results}
    assert len(results) == 3
    assert by_title["Root authorized_keys: deploy"]["status"] == STATUS_INFO  # forced-command deploy key
    assert by_title["User alice authorized_keys: alice laptop"]["status"] == STATUS_WARNING  # unrestricted
    assert by_title["User bob authorized_keys: bob ci"]["status"] == STATUS_WARNING  # 2048-bit RSA
    assert "Weak key type or small key size" in by_title["User bob authorized_keys: bob ci"]["risk"]


def test_user_key_variants(fs):
    users = {
        "root": _key(),  # ignored here: root is handled separately
        "dev": "\n".join(
            [
                _key('command="/bin/true"', "forced"),
                _key("restrict", "restricted"),
                _key("", "open"),
                _key("", "small", rsa_bits=1024),
            ]
        ),
    }
    results = checks_access._check_authorized_keys("", users)
    statuses = {r["title"]: r["status"] for r in results}
    assert statuses == {
        "User dev authorized_keys: forced": STATUS_INFO,
        "User dev authorized_keys: restricted": STATUS_INFO,
        "User dev authorized_keys: open": STATUS_WARNING,
        "User dev authorized_keys: small": STATUS_WARNING,
    }


def test_root_key_variants(fs):
    text = "\n".join(
        [_key("restrict", "r"), _key("", "open"), "# comment", "garbage line", _key("", "small", rsa_bits=2048)]
    )
    statuses = [r["status"] for r in checks_access._check_authorized_keys(text, {})]
    assert statuses == [STATUS_INFO, STATUS_WARNING, STATUS_WARNING]


def test_missing_root_key_file_is_not_an_error(fs):
    results = checks_access.run_checks(group_file_content="")
    assert not any(r["status"] == STATUS_SKIPPED and r["id"] == "ACC-001" for r in results)


def test_unreadable_root_key_file_is_reported_as_skipped(fs):
    fs["/root/.ssh/authorized_keys"] = PermissionError("denied")
    results = checks_access.run_checks(group_file_content="")
    skipped = [r for r in results if r["id"] == "ACC-001"]
    assert skipped[0]["status"] == STATUS_SKIPPED and "denied" in skipped[0]["current_value"]


def test_run_checks_uses_the_given_inputs_without_touching_files(fs):
    results = checks_access.run_checks(
        root_authorized_keys=_key("", "given"),
        users_authorized_keys={"eve": _key("", "eve key")},
        sudoers_paths=[],
        group_file_content="",
    )
    assert [r["id"] for r in results if r["id"] == "ACC-001"] == ["ACC-001", "ACC-001"]
    assert any(r["id"] == "ACC-003" for r in results)


# ---- ACC-002 sudoers --------------------------------------------------------------------------------------------------------


def test_sudoers_rules_are_classified_from_real_text(tmp_path):
    sudoers = tmp_path / "sudoers"
    sudoers.write_text(
        "Defaults env_reset\n"
        "root ALL=(ALL:ALL) ALL\n"
        "deploy ALL=(root) NOPASSWD: /usr/local/bin/restart-app\n"
        "ops ALL=(ALL) NOPASSWD: ALL\n",
        encoding="utf-8",
    )
    results = checks_access._check_sudoers([str(sudoers)])
    by_user = {r["details"][0].replace("User: ", ""): r for r in results}
    assert by_user["ops"]["status"] == STATUS_CRITICAL
    assert (
        by_user["deploy"]["status"] == STATUS_INFO
        and "/usr/local/bin/restart-app" in by_user["deploy"]["current_value"]
    )
    assert all(r["id"] == "ACC-002" and r["details"][3].startswith("Line: ") for r in results)


def test_sudoers_parse_failure_is_reported(monkeypatch):
    def boom(paths):
        raise ValueError("cannot parse")

    monkeypatch.setattr(checks_access, "parse_sudoers_paths", boom)
    [result] = checks_access._check_sudoers(["/etc/sudoers"])
    assert result["status"] == STATUS_SKIPPED and "cannot parse" in result["current_value"]


def test_run_checks_includes_sudoers_results(tmp_path, monkeypatch, fs):
    sudoers = tmp_path / "sudoers"
    sudoers.write_text("ops ALL=(ALL) NOPASSWD: ALL\n", encoding="utf-8")
    monkeypatch.setattr(checks_access, "SUDOERS_PATHS", [str(sudoers)])
    results = checks_access.run_checks(root_authorized_keys="", users_authorized_keys={}, group_file_content="")
    assert [r["status"] for r in results if r["id"] == "ACC-002"] == [STATUS_CRITICAL]


# ---- ACC-003 docker group -----------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "group_file, status, member_text",
    [
        ("root:x:0:\ndocker:x:998:\n", STATUS_PASS, "No members"),
        ("docker:x:998:root\n", STATUS_INFO, "root"),
        ("docker:x:998:alice, bob\nusers:x:100:\n", STATUS_WARNING, "alice, bob"),
        ("sudo:x:27:alice\n", STATUS_PASS, "No members"),
        ("docker:x:998\nmalformed\n", STATUS_PASS, "No members"),
    ],
)
def test_docker_group_membership(group_file, status, member_text):
    [result] = checks_access._check_docker_group(group_file)
    assert result["id"] == "ACC-003" and result["status"] == status and result["current_value"] == member_text


def test_docker_group_is_read_from_disk(fs):
    fs["/etc/group"] = "docker:x:998:mallory\n"
    results = checks_access.run_checks(root_authorized_keys="", users_authorized_keys={}, sudoers_paths=[])
    assert [r["status"] for r in results if r["id"] == "ACC-003"] == [STATUS_WARNING]


def test_unreadable_group_file_is_reported(fs):
    fs["/etc/group"] = OSError("no access")
    results = checks_access.run_checks(root_authorized_keys="", users_authorized_keys={}, sudoers_paths=[])
    skipped = [r for r in results if r["id"] == "ACC-003"]
    assert skipped[0]["status"] == STATUS_SKIPPED and "no access" in skipped[0]["current_value"]
