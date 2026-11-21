"""checks_misc: world-writable paths, systemd sandboxing, TLS expiry and failed-login telemetry (all mocked)."""

import socket
import ssl
import sys
from types import SimpleNamespace

import pytest

import checks_misc
from common import STATUS_CRITICAL, STATUS_INFO, STATUS_PASS, STATUS_SKIPPED, STATUS_WARNING, CmdResult

# ---- find world-writable ------------------------------------------------------------------------------------------


def test_world_writable_find_arguments_are_a_safe_argument_list(monkeypatch):
    seen = {}

    def run(args, timeout=None):
        seen["args"], seen["timeout"] = list(args), timeout
        return CmdResult(0, "/tmp/a\n\n/var/b\n", "")

    monkeypatch.setattr(checks_misc, "run_cmd", run)
    assert checks_misc._find_world_writable(timeout=9.0) == ["/tmp/a", "/var/b"]
    args = seen["args"]
    assert args[:3] == ["/usr/bin/find", "/", "-xdev"] and seen["timeout"] == 9.0
    for pruned in ("/proc", "/sys", "/var/lib/docker"):
        assert pruned in args
    assert args[-1] == "-print" and "-perm" in args and "-1000" in args


def test_world_writable_find_failures_return_none(monkeypatch):
    monkeypatch.setattr(checks_misc, "run_cmd", lambda args, timeout=None: CmdResult(124, "", "", timed_out=True))
    assert checks_misc._find_world_writable() is None
    monkeypatch.setattr(checks_misc, "run_cmd", lambda args, timeout=None: CmdResult(1, "", "denied"))
    assert checks_misc._find_world_writable() is None


def test_check_world_writable_outcomes(monkeypatch):
    monkeypatch.setattr(checks_misc, "_find_world_writable", lambda timeout=15.0: None)
    assert checks_misc.check_world_writable()["status"] == STATUS_SKIPPED
    monkeypatch.setattr(checks_misc, "_find_world_writable", lambda timeout=15.0: [])
    assert checks_misc.check_world_writable()["status"] == STATUS_PASS
    paths = ["/data/p%d" % i for i in range(25)]
    monkeypatch.setattr(checks_misc, "_find_world_writable", lambda timeout=15.0: paths)
    result = checks_misc.check_world_writable()
    assert (
        result["status"] != STATUS_PASS and "... and 5 more" in result["details"][-1] and len(result["details"]) == 21
    )


# ---- systemd units ---------------------------------------------------------------------------------------------------


def test_unit_listing_skips_symlinks_and_other_files(tmp_path):
    (tmp_path / "a.service").write_text("[Service]\n", encoding="utf-8")
    (tmp_path / "b.timer").write_text("x", encoding="utf-8")
    if sys.platform != "win32":
        (tmp_path / "vendor.service").symlink_to(tmp_path / "a.service")
    units = checks_misc._parse_systemd_units(str(tmp_path))
    assert [u.split("/")[-1].split("\\")[-1] for u in units] == ["a.service"]


def test_unit_listing_survives_os_errors(monkeypatch):
    def boom(pattern):
        raise OSError("denied")

    monkeypatch.setattr(checks_misc.glob, "glob", boom)
    assert checks_misc._parse_systemd_units("/etc/systemd/system") == []


def test_unit_sandboxing_directives_are_detected(tmp_path):
    unit = tmp_path / "app.service"
    unit.write_text(
        "[Service]\nNoNewPrivileges=yes\n  PrivateTmp=true\nProtectSystem\n# ProtectHome=yes\n", encoding="utf-8"
    )
    found = checks_misc._read_unit_sandboxing(str(unit))
    assert found["NoNewPrivileges"] and found["PrivateTmp"] and found["ProtectSystem"]
    assert not found["ProtectHome"] and not found["ProtectKernelModules"]
    assert not any(checks_misc._read_unit_sandboxing(str(tmp_path / "missing.service")).values())


def test_systemd_check_outcomes(monkeypatch):
    monkeypatch.setattr(checks_misc.os.path, "isdir", lambda path: False)
    assert checks_misc.check_systemd_sandboxing()[0]["status"] == STATUS_SKIPPED
    monkeypatch.setattr(checks_misc.os.path, "isdir", lambda path: True)
    monkeypatch.setattr(checks_misc, "_parse_systemd_units", lambda unit_dir: [])
    assert checks_misc.check_systemd_sandboxing()[0]["status"] == STATUS_SKIPPED
    units = {"/e/full.service": [], "/e/few.service": ["ProtectHome", "PrivateTmp"], "/e/many.service": ["A", "B", "C"]}
    monkeypatch.setattr(checks_misc, "_parse_systemd_units", lambda unit_dir: list(units))

    def read(path):
        names = (
            "NoNewPrivileges",
            "ProtectSystem",
            "PrivateTmp",
            "ProtectHome",
            "ProtectKernelTunables",
            "ProtectKernelModules",
        )
        missing = units[path]
        if path.endswith("many.service"):
            missing = ["NoNewPrivileges", "ProtectSystem", "PrivateTmp"]
        return {name: name not in missing for name in names}

    monkeypatch.setattr(checks_misc, "_read_unit_sandboxing", read)
    statuses = {c["title"]: c["status"] for c in checks_misc.check_systemd_sandboxing()}
    assert statuses == {
        "Unit full.service sandboxing": STATUS_PASS,
        "Unit few.service sandboxing": STATUS_INFO,
        "Unit many.service sandboxing": STATUS_WARNING,
    }


# ---- TLS expiry --------------------------------------------------------------------------------------------------------


def test_tls_ports_come_from_ss(monkeypatch):
    output = "LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*\nLISTEN 0 4096 [::]:443 [::]:*\nLISTEN 0 128 127.0.0.1:8443 0.0.0.0:*\nshort\nLISTEN 0 1 nocolon x\nLISTEN 0 1 host:abc x\n"
    monkeypatch.setattr(checks_misc, "run_cmd", lambda args, timeout=None: CmdResult(0, output, ""))
    assert checks_misc._get_tls_ports() == [443, 8443]
    monkeypatch.setattr(checks_misc, "run_cmd", lambda args, timeout=None: CmdResult(1, "", "no ss"))
    assert checks_misc._get_tls_ports() == []


def test_tls_expiry_uses_the_injected_handshake():
    assert checks_misc._check_tls_expiry(443, handshake_fn=lambda port: {"port": port, "days_to_expiry": 5.0}) == {
        "port": 443,
        "days_to_expiry": 5.0,
    }


class FakeSocket:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeTlsSocket(FakeSocket):
    def __init__(self, cert):
        self.cert = cert

    def getpeercert(self):
        return self.cert


def _tls(monkeypatch, cert=None, connect_error=None, wrap_error=None):
    def connect(address, timeout=None):
        if connect_error:
            raise connect_error
        return FakeSocket()

    class Context:
        def wrap_socket(self, sock, server_hostname=None):
            if wrap_error:
                raise wrap_error
            return FakeTlsSocket(cert)

    monkeypatch.setattr(checks_misc.socket, "create_connection", connect)
    monkeypatch.setattr(checks_misc.ssl, "create_default_context", lambda: Context())


def test_real_handshake_path_parses_the_expiry_date(monkeypatch):
    _tls(monkeypatch, cert={"notAfter": "Jan  1 00:00:00 2099 GMT"})
    info = checks_misc._check_tls_expiry(443)
    assert info["port"] == 443 and info["days_to_expiry"] > 365 and info["expires_at"].startswith("2099-01-01")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"cert": {}},
        {"connect_error": ConnectionRefusedError("closed")},
        {"cert": None, "wrap_error": socket.timeout("slow")},
        {"cert": None, "wrap_error": ssl.SSLCertVerificationError("self signed")},
    ],
    ids=["no-cert", "refused", "timeout", "untrusted"],
)
def test_handshake_failures_return_none(monkeypatch, kwargs):
    _tls(monkeypatch, **kwargs)
    assert checks_misc._check_tls_expiry(443) is None


@pytest.mark.parametrize(
    "days, status",
    [(-2.0, STATUS_CRITICAL), (1.5, STATUS_CRITICAL), (10.0, STATUS_WARNING), (14.0, STATUS_PASS), (90.0, STATUS_PASS)],
)
def test_tls_expiry_thresholds(monkeypatch, days, status):
    monkeypatch.setattr(checks_misc, "_get_tls_ports", lambda: [443])
    [result] = checks_misc.check_tls_expiry(
        handshake_fn=lambda port: {"port": port, "days_to_expiry": days, "expires_at": "2099-01-01T00:00:00+00:00"}
    )
    assert result["status"] == status and "443" in result["current_value"]


def test_tls_check_without_ports_or_certificates(monkeypatch):
    monkeypatch.setattr(checks_misc, "_get_tls_ports", lambda: [])
    assert checks_misc.check_tls_expiry()[0]["status"] == STATUS_SKIPPED
    monkeypatch.setattr(checks_misc, "_get_tls_ports", lambda: [443, 8443])
    results = checks_misc.check_tls_expiry(
        handshake_fn=lambda port: (
            None if port == 443 else {"port": port, "days_to_expiry": 60.0, "expires_at": "2099-01-01T00:00:00+00:00"}
        )
    )
    assert [r["status"] for r in results] == [STATUS_SKIPPED, STATUS_PASS]


# ---- failed logins -------------------------------------------------------------------------------------------------------


def test_failed_logins_are_counted_per_source_ip(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(
        "Failed password for root from 203.0.113.9 port 22 ssh2\n"
        "Failed password for invalid user admin from 203.0.113.9 port 22 ssh2\n"
        "Failed password for bob from 198.51.100.7 port 22 ssh2\n"
        "Accepted publickey for bob from 198.51.100.7\n",
        encoding="utf-8",
    )
    assert checks_misc._parse_failed_logins(str(log)) == {"203.0.113.9": 2, "198.51.100.7": 1}
    assert checks_misc._parse_failed_logins(str(tmp_path / "missing.log")) == {}


def _logins(monkeypatch, counts, fail2ban=False, crowdsec=False):
    monkeypatch.setattr(checks_misc, "_parse_failed_logins", lambda: counts)
    monkeypatch.setattr(
        checks_misc, "detect_environment", lambda: SimpleNamespace(fail2ban=fail2ban, crowdsec=crowdsec)
    )


@pytest.mark.parametrize(
    "counts, fail2ban, crowdsec, status",
    [
        ({"203.0.113.9": 100}, False, False, STATUS_PASS),
        ({"203.0.113.9": 101}, False, False, STATUS_WARNING),
        ({"203.0.113.9": 101}, True, False, STATUS_INFO),
        ({"203.0.113.9": 500}, False, True, STATUS_INFO),
    ],
)
def test_failed_login_thresholds(monkeypatch, counts, fail2ban, crowdsec, status):
    _logins(monkeypatch, counts, fail2ban, crowdsec)
    result = checks_misc.check_failed_logins()
    assert result["status"] == status and "203.0.113.9" in result["current_value"]


def test_failed_logins_top_ips_are_ranked(monkeypatch):
    _logins(monkeypatch, {"10.0.0.%d" % i: i for i in range(1, 15)})
    details = checks_misc.check_failed_logins()["details"]
    assert len(details) == 10 and details[0] == "10.0.0.14: 14 failures"


@pytest.mark.parametrize("fail2ban, note", [(False, "failures may be blocked"), (True, "failures may be blocked")])
def test_no_failed_login_entries_is_skipped_with_a_reason(monkeypatch, fail2ban, note):
    _logins(monkeypatch, {}, fail2ban=fail2ban)
    result = checks_misc.check_failed_logins()
    assert result["status"] == STATUS_SKIPPED and "No failed login entries" in result["current_value"]
    assert (note in result["current_value"]) is fail2ban


# ---- run_checks --------------------------------------------------------------------------------------------------------------


def test_run_checks_collects_all_four_checks(monkeypatch):
    monkeypatch.setattr(checks_misc, "check_world_writable", lambda: {"id": "MSC-001"})
    monkeypatch.setattr(checks_misc, "check_systemd_sandboxing", lambda: [{"id": "MSC-002"}])
    monkeypatch.setattr(checks_misc, "check_tls_expiry", lambda: [{"id": "MSC-003"}])
    monkeypatch.setattr(checks_misc, "check_failed_logins", lambda: {"id": "MSC-004"})
    assert [r["id"] for r in checks_misc.run_checks()] == ["MSC-001", "MSC-002", "MSC-003", "MSC-004"]
