"""checks_ssh: every check, every skip path, and the sshd_config parsing helpers (all inputs mocked)."""

import sys

import pytest

import checks_ssh
from common import STATUS_CRITICAL, STATUS_INFO, STATUS_PASS, STATUS_SKIPPED, STATUS_WARNING, CmdResult

CHECKS = [
    # function, check id, finding name, remediation id
    ("_check_permit_root_login", "SSH-001", "PermitRootLogin", "ssh_permit_root_login"),
    ("_check_password_auth", "SSH-002", "PasswordAuthentication", "ssh_password_auth"),
    ("_check_pubkey_auth", "SSH-003", "PubkeyAuthentication", "ssh_pubkey_auth"),
    ("_check_max_auth_tries", "SSH-004", "MaxAuthTries", "ssh_max_auth_tries"),
    ("_check_empty_passwords", "SSH-005", "PermitEmptyPasswords", "ssh_empty_passwords"),
    ("_check_x11_forwarding", "SSH-006", "X11Forwarding", "ssh_x11_forwarding"),
]

# (function, value) -> expected status
OUTCOMES = [
    ("_check_permit_root_login", "yes", STATUS_CRITICAL),
    ("_check_permit_root_login", "no", STATUS_PASS),
    ("_check_permit_root_login", "prohibit-password", STATUS_PASS),
    ("_check_password_auth", "no", STATUS_PASS),
    ("_check_password_auth", "yes", STATUS_WARNING),
    (
        "_check_password_auth",
        "weird",
        STATUS_PASS,
    ),  # an unknown value is INFO for the port and does not raise the status
    ("_check_pubkey_auth", "yes", STATUS_PASS),
    ("_check_pubkey_auth", "no", STATUS_CRITICAL),
    ("_check_pubkey_auth", "weird", STATUS_PASS),
    ("_check_max_auth_tries", "3", STATUS_PASS),
    ("_check_max_auth_tries", "2", STATUS_PASS),
    ("_check_max_auth_tries", "4", STATUS_WARNING),
    ("_check_max_auth_tries", "5", STATUS_WARNING),
    ("_check_max_auth_tries", "6", STATUS_CRITICAL),
    ("_check_max_auth_tries", "many", STATUS_PASS),
    ("_check_empty_passwords", "no", STATUS_PASS),
    ("_check_empty_passwords", "yes", STATUS_CRITICAL),
    ("_check_empty_passwords", "weird", STATUS_PASS),
    ("_check_x11_forwarding", "no", STATUS_PASS),
    ("_check_x11_forwarding", "yes", STATUS_WARNING),
    ("_check_x11_forwarding", "weird", STATUS_PASS),
]


def _finding_name(function):
    return next(name for fn, _id, name, _rid in CHECKS if fn == function)


@pytest.fixture
def sshd(monkeypatch):
    """A host with sshd installed listening on port 22; tests override the pieces they need."""
    state = {"ports": [22], "values": {}, "skipped": None}
    monkeypatch.setattr(checks_ssh, "_check_sshd_installed", lambda: True)
    monkeypatch.setattr(checks_ssh, "listening_ssh_ports", lambda: list(state["ports"]))

    def evaluate(port=None, **_kwargs):
        if state["skipped"]:
            return {"status": "SKIPPED", "reason": state["skipped"]}
        findings = [{"check": name, "value": value} for name, value in state["values"].get(port, {}).items()]
        return {"status": "OK", "findings": findings}

    monkeypatch.setattr(checks_ssh, "evaluate_ssh_security", evaluate)
    return state


@pytest.mark.parametrize("function, value, expected", OUTCOMES)
def test_status_for_each_value(sshd, function, value, expected):
    sshd["values"] = {22: {_finding_name(function): value}}
    result = getattr(checks_ssh, function)()
    assert result["status"] == expected
    assert result["category"] == "ssh"
    assert "Port 22" in result["current_value"] and value in result["current_value"]


@pytest.mark.parametrize("function, check_id, name, remediation", CHECKS)
def test_result_metadata(sshd, function, check_id, name, remediation):
    sshd["values"] = {22: {name: "no"}}
    result = getattr(checks_ssh, function)()
    assert result["id"] == check_id and result["remediation_id"] == remediation
    assert result["manual_command"] and result["recommended_value"] and result["risk"]


@pytest.mark.parametrize("function, check_id, name, remediation", CHECKS)
def test_skipped_when_sshd_is_not_installed(sshd, monkeypatch, function, check_id, name, remediation):
    monkeypatch.setattr(checks_ssh, "_check_sshd_installed", lambda: False)
    result = getattr(checks_ssh, function)()
    assert result["status"] == STATUS_SKIPPED and result["id"] == check_id
    assert "sshd_config not found" in result["current_value"]


@pytest.mark.parametrize("function, check_id, name, remediation", CHECKS)
def test_skipped_when_no_ssh_port_is_listening(sshd, function, check_id, name, remediation):
    sshd["ports"] = []
    result = getattr(checks_ssh, function)()
    assert result["status"] == STATUS_SKIPPED
    assert "No SSH ports detected" in result["current_value"]


@pytest.mark.parametrize("function, check_id, name, remediation", CHECKS)
def test_skipped_with_the_reason_from_the_evaluation(sshd, function, check_id, name, remediation):
    sshd["skipped"] = "sshd -T failed: permission denied"
    result = getattr(checks_ssh, function)()
    assert result["status"] == STATUS_SKIPPED
    assert "permission denied" in result["current_value"]


@pytest.mark.parametrize("function, check_id, name, remediation", CHECKS)
def test_no_data_is_reported_as_such(sshd, function, check_id, name, remediation):
    sshd["values"] = {22: {}}  # the evaluation returned no finding for this setting
    result = getattr(checks_ssh, function)()
    assert result["current_value"] == "(no data)"
    assert result["status"] == STATUS_PASS


def test_worst_status_wins_across_several_ports(sshd):
    sshd["ports"] = [22, 2222]
    sshd["values"] = {22: {"PermitRootLogin": "no"}, 2222: {"PermitRootLogin": "yes"}}
    result = checks_ssh._check_permit_root_login()
    assert result["status"] == STATUS_CRITICAL
    assert "Port 22" in result["current_value"] and "Port 2222" in result["current_value"]


def test_info_for_an_unrecognised_value_is_listed_in_the_details(sshd):
    sshd["values"] = {22: {"X11Forwarding": "maybe"}}
    result = checks_ssh._check_x11_forwarding()
    assert result["details"] == ["Port 22: X11Forwarding=maybe (%s)" % STATUS_INFO]


def test_run_checks_returns_one_result_per_check(sshd):
    sshd["values"] = {22: {name: "no" for _fn, _id, name, _rid in CHECKS}}
    results = checks_ssh.run_checks()
    assert [r["id"] for r in results] == [cid for _fn, cid, _n, _r in CHECKS]


def test_run_checks_turns_an_unexpected_error_into_a_skipped_result(monkeypatch):
    def boom():
        raise RuntimeError("boom")

    monkeypatch.setattr(checks_ssh, "_check_permit_root_login", boom)
    monkeypatch.setattr(checks_ssh, "_check_sshd_installed", lambda: False)
    results = checks_ssh.run_checks()
    assert results[0]["status"] == STATUS_SKIPPED and "unexpected exception" in results[0]["current_value"]
    assert len(results) == 6


# ---- configuration parsing ------------------------------------------------------------------------------------


@pytest.fixture
def sshd_files(tmp_path, monkeypatch):
    config = tmp_path / "sshd_config"
    dropins = tmp_path / "sshd_config.d"
    dropins.mkdir()
    monkeypatch.setattr(checks_ssh, "SSHD_CONFIG", str(config))
    monkeypatch.setattr(checks_ssh, "SSHD_DROPIN_DIR", str(dropins))
    return config, dropins


def test_parse_returns_nothing_without_a_config_file(sshd_files):
    assert checks_ssh._parse_sshd_config() == {}


def test_parse_first_value_wins_and_ignores_comments(sshd_files):
    config, _ = sshd_files
    config.write_text(
        "# comment\n\nPermitRootLogin no\nPermitRootLogin yes\nLonelyKey\nMaxAuthTries   3  \n", encoding="utf-8"
    )
    assert checks_ssh._parse_sshd_config() == {"permitrootlogin": "no", "maxauthtries": "3"}


@pytest.mark.skipif(sys.platform == "win32", reason="Include handling expects absolute POSIX paths")
def test_parse_follows_absolute_includes(sshd_files, tmp_path):
    config, _ = sshd_files
    included = tmp_path / "extra.conf"
    included.write_text(
        "# c\nX11Forwarding no\nPasswordAuthentication no\nbroken\nPasswordAuthentication yes\n", encoding="utf-8"
    )
    config.write_text(
        "Include %s\nX11Forwarding yes\nRelative Include\nInclude relative/*.conf\n" % included, encoding="utf-8"
    )
    values = checks_ssh._parse_sshd_config()
    assert values["x11forwarding"] == "no"  # the include comes first
    assert values["passwordauthentication"] == "no"


def test_parse_reads_dropin_files_in_order_without_overriding(sshd_files):
    config, dropins = sshd_files
    config.write_text("MaxAuthTries 2\n", encoding="utf-8")
    (dropins / "10-a.conf").write_text("# c\nMaxAuthTries 9\nPermitEmptyPasswords no\nbad\n", encoding="utf-8")
    (dropins / "20-b.conf").write_text("PermitEmptyPasswords yes\nX11Forwarding no\n", encoding="utf-8")
    assert checks_ssh._parse_sshd_config() == {
        "maxauthtries": "2",
        "permitemptypasswords": "no",
        "x11forwarding": "no",
    }


def test_effective_values_use_sshd_t_when_root(monkeypatch):
    monkeypatch.setattr(checks_ssh, "is_root", lambda: True)
    output = "permitrootlogin no\n\nmaxauthtries 4\nport 22\nbadline\n"
    monkeypatch.setattr(checks_ssh, "run_cmd", lambda args: CmdResult(0, output, ""))
    values = checks_ssh._effective_values()
    assert values["permitrootlogin"] == "no" and values["maxauthtries"] == "4"
    assert values["passwordauthentication"] == "yes"  # default kept


def test_effective_values_fall_back_to_the_files_when_sshd_t_fails(monkeypatch, sshd_files):
    config, _ = sshd_files
    config.write_text("PasswordAuthentication no\n", encoding="utf-8")
    monkeypatch.setattr(checks_ssh, "is_root", lambda: True)
    monkeypatch.setattr(checks_ssh, "run_cmd", lambda args: CmdResult(1, "", "no"))
    assert checks_ssh._effective_values()["passwordauthentication"] == "no"


def test_effective_values_without_root_use_files_and_defaults(monkeypatch, sshd_files):
    config, _ = sshd_files
    config.write_text("X11Forwarding no\n", encoding="utf-8")
    monkeypatch.setattr(checks_ssh, "is_root", lambda: False)
    values = checks_ssh._effective_values()
    assert values["x11forwarding"] == "no" and values["permitrootlogin"] == "prohibit-password"


def test_sshd_installed_follows_the_config_file(sshd_files):
    config, _ = sshd_files
    assert checks_ssh._check_sshd_installed() is False
    config.write_text("Port 22\n", encoding="utf-8")
    assert checks_ssh._check_sshd_installed() is True
