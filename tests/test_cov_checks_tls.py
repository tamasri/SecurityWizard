"""checks_tls: certificate validity, weak protocol detection and cipher strength (every TLS handshake mocked)."""

import socket
import ssl
from datetime import datetime, timedelta, timezone

import pytest

import checks_tls
from common import STATUS_CRITICAL, STATUS_PASS, STATUS_SKIPPED, STATUS_WARNING
from config import reset_config


@pytest.fixture(autouse=True)
def clean_config():
    reset_config()
    yield
    reset_config()


def _allow(tmp_path, monkeypatch, *hosts):
    entries = ", ".join(f'{{host = "{h}", reason = "test"}}' for h in hosts)
    path = tmp_path / "securitywizard.toml"
    path.write_text(f"[pentest]\ntargets = [{entries}]\n", encoding="utf-8")
    monkeypatch.setenv("SECURITYWIZARD_CONFIG", str(path))


def _not_after(days_from_now: float) -> str:
    when = datetime.now(timezone.utc) + timedelta(days=days_from_now)
    return when.strftime("%b %d %H:%M:%S %Y") + " GMT"


# ---- configured_domains ---------------------------------------------------------------------------------------


def test_configured_domains_empty_without_config():
    assert checks_tls.configured_domains() == []


def test_configured_domains_sorted_and_deduplicated(tmp_path, monkeypatch):
    _allow(tmp_path, monkeypatch, "b.example.com", "a.example.com")
    assert checks_tls.configured_domains() == ["a.example.com", "b.example.com"]


# ---- TLS-001: certificate ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "days, expected",
    [
        (-1, STATUS_CRITICAL),
        (5, STATUS_CRITICAL),
        (13.9, STATUS_CRITICAL),
        (20, STATUS_WARNING),
        (29.9, STATUS_WARNING),
        (60, STATUS_PASS),
    ],
)
def test_certificate_expiry_thresholds(days, expected):
    def connect(host, port, ctx, timeout):
        return {"notAfter": _not_after(days)}, ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256), "TLSv1.3"

    result = checks_tls.check_certificate("example.com", 443, "HTTPS", connect=connect)
    assert result["id"] == "TLS-001" and result["status"] == expected
    assert "example.com:443" in result["title"]


def test_certificate_chain_validation_failure_is_critical():
    def connect(host, port, ctx, timeout):
        raise ssl.SSLCertVerificationError("certificate verify failed: self-signed certificate")

    result = checks_tls.check_certificate("example.com", 443, "HTTPS", connect=connect)
    assert result["status"] == STATUS_CRITICAL and "self-signed" in result["current_value"]


@pytest.mark.parametrize("exc", [OSError("connection refused"), socket.timeout("timed out")])
def test_certificate_connection_failure_is_skipped(exc):
    def connect(host, port, ctx, timeout):
        raise exc

    result = checks_tls.check_certificate("example.com", 993, "IMAPS", connect=connect)
    assert result["status"] == STATUS_SKIPPED


def test_certificate_missing_details_is_a_warning():
    def connect(host, port, ctx, timeout):
        return {}, ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256), "TLSv1.3"

    result = checks_tls.check_certificate("example.com", 443, "HTTPS", connect=connect)
    assert result["status"] == STATUS_WARNING and "no certificate" in result["current_value"].lower()


# ---- TLS-002: weak protocol versions ------------------------------------------------------------------------------


class _PermissiveContext:
    """A fake ssl.SSLContext whose minimum/maximum_version assignment always succeeds, so whether a weak
    version is "offered" or "refused" depends entirely on the injected connect() function."""

    def __init__(self, *_args, **_kwargs):
        self.check_hostname = None
        self.verify_mode = None
        self.minimum_version = None
        self.maximum_version = None


class _AllVersionsUnsupportedContext:
    """Every minimum_version assignment raises, simulating an OpenSSL build that cannot attempt any weak version."""

    def __init__(self, *_args, **_kwargs):
        self.check_hostname = None
        self.verify_mode = None

    def __setattr__(self, name, value):
        if name == "minimum_version":
            raise ValueError("protocol version not supported by this build")
        object.__setattr__(self, name, value)


class _OnlyTLSv11UnsupportedContext:
    """TLSv1.1 cannot even be attempted; TLSv1 can."""

    def __init__(self, *_args, **_kwargs):
        self.check_hostname = None
        self.verify_mode = None

    def __setattr__(self, name, value):
        if name == "minimum_version" and value == ssl.TLSVersion.TLSv1_1:
            raise ValueError("TLSv1.1 not supported by this build")
        object.__setattr__(self, name, value)


def test_weak_protocols_refused_passes(monkeypatch):
    monkeypatch.setattr(checks_tls.ssl, "SSLContext", _PermissiveContext)

    def connect(host, port, ctx, timeout):
        raise ssl.SSLError("protocol version")

    result = checks_tls.check_weak_protocols("example.com", 443, "HTTPS", connect=connect)
    assert result["id"] == "TLS-002" and result["status"] == STATUS_PASS
    assert "Refused: TLSv1, TLSv1.1" in result["current_value"]


def test_weak_protocol_still_accepted_is_critical(monkeypatch):
    monkeypatch.setattr(checks_tls.ssl, "SSLContext", _PermissiveContext)

    def connect(host, port, ctx, timeout):
        return None, None, "TLSv1"

    result = checks_tls.check_weak_protocols("example.com", 443, "HTTPS", connect=connect)
    assert result["status"] == STATUS_CRITICAL and "Still accepts: TLSv1" in result["current_value"]


def test_weak_protocols_entirely_inconclusive_is_skipped(monkeypatch):
    monkeypatch.setattr(checks_tls.ssl, "SSLContext", _AllVersionsUnsupportedContext)
    result = checks_tls.check_weak_protocols("example.com", 443, "HTTPS", connect=lambda *a: (None, None, "x"))
    assert result["status"] == STATUS_SKIPPED and "cannot even attempt" in result["current_value"]


def test_weak_protocols_partially_inconclusive_still_reports(monkeypatch):
    monkeypatch.setattr(checks_tls.ssl, "SSLContext", _OnlyTLSv11UnsupportedContext)

    def connect(host, port, ctx, timeout):
        raise ssl.SSLError("protocol version")

    result = checks_tls.check_weak_protocols("example.com", 443, "HTTPS", connect=connect)
    assert result["status"] == STATUS_PASS
    assert "Refused: TLSv1" in result["current_value"] and "could not test: TLSv1.1" in result["current_value"]


def test_probe_weak_version_direct(monkeypatch):
    monkeypatch.setattr(checks_tls.ssl, "SSLContext", _PermissiveContext)
    assert checks_tls.probe_weak_version("h", 443, "TLSv1", connect=lambda *a: (None, None, "TLSv1")) is True
    assert (
        checks_tls.probe_weak_version("h", 443, "TLSv1", connect=lambda *a: (_ for _ in ()).throw(OSError())) is False
    )
    monkeypatch.setattr(checks_tls.ssl, "SSLContext", _AllVersionsUnsupportedContext)
    assert checks_tls.probe_weak_version("h", 443, "TLSv1") is None


# ---- TLS-003: cipher strength ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cipher_name, expected",
    [
        ("TLS_AES_256_GCM_SHA384", STATUS_PASS),
        ("ECDHE-RSA-RC4-SHA", STATUS_CRITICAL),
        ("EXP-DES-CBC-SHA", STATUS_CRITICAL),
    ],
)
def test_cipher_strength(cipher_name, expected):
    def connect(host, port, ctx, timeout):
        return {"notAfter": _not_after(90)}, (cipher_name, "TLSv1.2", 256), "TLSv1.2"

    result = checks_tls.check_cipher("example.com", 443, "HTTPS", connect=connect)
    assert result["id"] == "TLS-003" and result["status"] == expected and cipher_name in result["current_value"]


def test_cipher_connection_failure_is_skipped():
    def connect(host, port, ctx, timeout):
        raise OSError("refused")

    assert checks_tls.check_cipher("example.com", 443, "HTTPS", connect=connect)["status"] == STATUS_SKIPPED


def test_cipher_missing_is_skipped():
    def connect(host, port, ctx, timeout):
        return {}, None, "TLSv1.3"

    assert checks_tls.check_cipher("example.com", 443, "HTTPS", connect=connect)["status"] == STATUS_SKIPPED


# ---- run_checks orchestration and the allowlist -----------------------------------------------------------------------


def test_run_checks_without_any_domain_configured():
    [result] = checks_tls.run_checks()
    assert result["status"] == STATUS_SKIPPED and result["id"] == "TLS-001"


def test_run_checks_refuses_a_domain_outside_the_allowlist(tmp_path, monkeypatch):
    _allow(tmp_path, monkeypatch, "allowed.example.com")
    monkeypatch.setattr(checks_tls, "configured_domains", lambda: ["not-allowed.example.com"])
    results = checks_tls.run_checks()
    assert len(results) == 1 and results[0]["status"] == STATUS_SKIPPED
    assert "not in the [pentest] target allowlist" in results[0]["current_value"]


def test_run_checks_covers_every_port_and_check_for_an_allowed_domain(tmp_path, monkeypatch):
    _allow(tmp_path, monkeypatch, "example.com")

    def connect(host, port, ctx, timeout):
        return {"notAfter": _not_after(90)}, ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256), "TLSv1.3"

    monkeypatch.setattr(checks_tls, "_connect", connect)
    results = checks_tls.run_checks()
    assert len(results) == len(checks_tls.DEFAULT_PORTS) * 3
    assert {r["id"] for r in results} == {"TLS-001", "TLS-002", "TLS-003"}
    assert all(r["status"] == STATUS_PASS for r in results)


def test_run_checks_turns_an_unexpected_error_into_a_skipped_result(tmp_path, monkeypatch):
    _allow(tmp_path, monkeypatch, "example.com")

    def boom(*args, **kwargs):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(checks_tls, "check_certificate", boom)
    monkeypatch.setattr(checks_tls, "check_weak_protocols", lambda *a, **k: {"id": "TLS-002", "status": STATUS_PASS})
    monkeypatch.setattr(checks_tls, "check_cipher", lambda *a, **k: {"id": "TLS-003", "status": STATUS_PASS})
    results = checks_tls.run_checks()
    broken = [r for r in results if r["status"] == STATUS_SKIPPED and "kaboom" in r["current_value"]]
    assert len(broken) == len(checks_tls.DEFAULT_PORTS)
