"""checks_logs: log inventory, brute-force telemetry, fail2ban/CrowdSec and auditd (all inputs mocked)."""

import pytest

import checks_logs
from common import STATUS_CRITICAL, STATUS_INFO, STATUS_PASS, STATUS_SKIPPED, STATUS_WARNING, CmdResult


def _failed(user, ip, invalid=False):
    prefix = "invalid user " if invalid else ""
    return "Nov 21 10:00:00 host sshd[1]: Failed password for %s%s from %s port 22 ssh2" % (prefix, user, ip)


def _invalid(user, ip):
    return "Nov 21 10:00:00 host sshd[1]: Invalid user %s from %s port 22" % (user, ip)


# ---- log file inventory -----------------------------------------------------------------------------------


def test_log_file_present_is_informational_and_offers_no_chattr_fix(monkeypatch):
    monkeypatch.setattr(checks_logs.os.path, "exists", lambda path: True)
    result = checks_logs._check_log_attr("/var/log/auth.log", "LOG-001", None, "/var/log/auth.log")
    assert result["status"] == STATUS_INFO and result["remediation_id"] is None
    assert "exists" in result["current_value"] and "chattr" not in str(result)


def test_log_file_missing_is_explained(monkeypatch):
    monkeypatch.setattr(checks_logs.os.path, "exists", lambda path: False)
    result = checks_logs._check_log_attr("/var/log/syslog", "LOG-002", None, "/var/log/syslog")
    assert result["status"] == STATUS_INFO and "not found" in result["current_value"]


def test_log_file_check_reports_unexpected_errors_as_skipped(monkeypatch):
    def boom(path):
        raise OSError("disk on fire")

    monkeypatch.setattr(checks_logs.os.path, "exists", boom)
    result = checks_logs._check_log_attr("/var/log/auth.log", "LOG-001", None, "/var/log/auth.log")
    assert result["status"] == STATUS_SKIPPED and "disk on fire" in result["current_value"]


# ---- brute-force telemetry ----------------------------------------------------------------------------------


def _auth_log(monkeypatch, text):
    monkeypatch.setattr(checks_logs, "read_text", lambda path, default="": text)


def test_clean_log_passes(monkeypatch):
    _auth_log(monkeypatch, "Nov 21 sshd[1]: Accepted publickey for root from 10.0.0.1\n")
    result = checks_logs._check_brute_force()
    assert result["status"] == STATUS_PASS and "No recent failed logins" in result["current_value"]
    assert result["details"] == ["No failed logins or invalid users found in the log."]


@pytest.mark.parametrize(
    "failures, expected",
    [(1, STATUS_INFO), (100, STATUS_INFO), (101, STATUS_WARNING), (1000, STATUS_WARNING), (1001, STATUS_CRITICAL)],
)
def test_failure_thresholds(monkeypatch, failures, expected):
    _auth_log(monkeypatch, "\n".join(_failed("root", "203.0.113.9") for _ in range(failures)))
    result = checks_logs._check_brute_force()
    assert result["status"] == expected
    assert "%d failures" % failures in result["current_value"]


def test_top_users_and_ips_are_ranked(monkeypatch):
    lines = [_failed("root", "203.0.113.9")] * 3 + [_failed("admin", "198.51.100.7", invalid=True)] * 2
    lines += [_invalid("oracle", "203.0.113.9")]
    _auth_log(monkeypatch, "\n".join(lines))
    result = checks_logs._check_brute_force()
    details = "\n".join(result["details"])
    assert "6 failures (5 failed passwords, 1 invalid users)" in result["current_value"]
    assert "1. root: 3 attempts" in details and "2. admin: 2 attempts" in details
    assert "1. 203.0.113.9: 4 attempts" in details
    assert "grep -E" in result["command"] and "/var/log/auth.log" in result["command"]


def test_journal_is_used_when_there_is_no_auth_log(monkeypatch):
    _auth_log(monkeypatch, "")
    calls = []

    def run(args, timeout=None):
        calls.append(args)
        return CmdResult(0, _failed("root", "203.0.113.9"), "")

    monkeypatch.setattr(checks_logs, "run_cmd", run)
    result = checks_logs._check_brute_force()
    assert calls[0][0] == "journalctl"
    assert "journalctl -u ssh -u sshd" in result["command"] and result["status"] == STATUS_INFO


@pytest.mark.parametrize("journal", [CmdResult(1, "", "no journal"), CmdResult(0, "   \n", "")])
def test_skipped_when_no_log_source_has_data(monkeypatch, journal):
    _auth_log(monkeypatch, "")
    monkeypatch.setattr(checks_logs, "run_cmd", lambda args, timeout=None: journal)
    result = checks_logs._check_brute_force()
    assert result["status"] == STATUS_SKIPPED and "No auth log data" in result["current_value"]


def test_brute_force_check_reports_unexpected_errors(monkeypatch):
    def boom(path, default=""):
        raise RuntimeError("unreadable")

    monkeypatch.setattr(checks_logs, "read_text", boom)
    result = checks_logs._check_brute_force()
    assert result["status"] == STATUS_SKIPPED and "unreadable" in result["current_value"]


# ---- intrusion prevention and auditd ---------------------------------------------------------------------------


def _services(monkeypatch, active):
    def run(args, timeout=None):
        return CmdResult(0 if args[-1] in active else 3, "active\n" if args[-1] in active else "inactive\n", "")

    monkeypatch.setattr(checks_logs, "run_cmd", run)


@pytest.mark.parametrize(
    "active, expected, text",
    [
        ({"fail2ban", "crowdsec"}, STATUS_PASS, "Both fail2ban and crowdsec"),
        ({"fail2ban"}, STATUS_PASS, "fail2ban is active"),
        ({"crowdsec"}, STATUS_PASS, "crowdsec is active"),
        (set(), STATUS_WARNING, "Neither fail2ban nor crowdsec"),
    ],
)
def test_fail2ban_and_crowdsec(monkeypatch, active, expected, text):
    _services(monkeypatch, active)
    result = checks_logs._check_fail2ban_crowdsec()
    assert result["status"] == expected and text in result["current_value"]


def test_fail2ban_check_reports_unexpected_errors(monkeypatch):
    def boom(args, timeout=None):
        raise RuntimeError("no systemd")

    monkeypatch.setattr(checks_logs, "run_cmd", boom)
    assert checks_logs._check_fail2ban_crowdsec()["status"] == STATUS_SKIPPED


@pytest.mark.parametrize("active, expected", [({"auditd"}, STATUS_PASS), (set(), STATUS_WARNING)])
def test_auditd(monkeypatch, active, expected):
    _services(monkeypatch, active)
    assert checks_logs._check_auditd()["status"] == expected


def test_auditd_check_reports_unexpected_errors(monkeypatch):
    def boom(args, timeout=None):
        raise RuntimeError("no systemd")

    monkeypatch.setattr(checks_logs, "run_cmd", boom)
    assert checks_logs._check_auditd()["status"] == STATUS_SKIPPED


def test_run_checks_returns_the_five_log_checks(monkeypatch):
    monkeypatch.setattr(checks_logs.os.path, "exists", lambda path: True)
    _auth_log(monkeypatch, "")
    monkeypatch.setattr(checks_logs, "run_cmd", lambda args, timeout=None: CmdResult(1, "", ""))
    ids = [c["id"] for c in checks_logs.run_checks()]
    assert ids == ["LOG-001", "LOG-002", "LOG-003", "LOG-004", "LOG-005"]
