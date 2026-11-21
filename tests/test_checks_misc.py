import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from checks_misc import (
    check_failed_logins,
    check_systemd_sandboxing,
    check_tls_expiry,
    check_world_writable,
)
from common import STATUS_CRITICAL, STATUS_INFO, STATUS_PASS, STATUS_SKIPPED, STATUS_WARNING

# ---------------------------------------------------------------------------
# MSC-001: World-writable files
# ---------------------------------------------------------------------------


class TestWorldWritable:
    def test_no_world_writable(self, monkeypatch):
        """No world-writable files -> PASS."""
        monkeypatch.setattr(
            "checks_misc.run_cmd",
            lambda args, timeout=15.0: MagicMock(returncode=0, stdout="", stderr="", timed_out=False, not_found=False),
        )
        result = check_world_writable()
        assert result["status"] == STATUS_PASS
        assert result["id"] == "MSC-001"

    def test_world_writable_found(self, monkeypatch):
        """World-writable files found -> WARNING with details."""
        monkeypatch.setattr(
            "checks_misc.run_cmd",
            lambda args, timeout=15.0: MagicMock(
                returncode=0, stdout="/tmp/file1\n/var/tmp/file2\n", stderr="", timed_out=False, not_found=False
            ),
        )
        result = check_world_writable()
        assert result["status"] == STATUS_WARNING
        assert result["current_value"] == "2 world-writable paths without sticky bit"
        assert "/tmp/file1" in result["details"]

    def test_find_timeout(self, monkeypatch):
        """find times out -> SKIPPED with reason."""
        monkeypatch.setattr(
            "checks_misc.run_cmd",
            lambda args, timeout=15.0: MagicMock(
                returncode=124, stdout="", stderr="timeout", timed_out=True, not_found=False
            ),
        )
        result = check_world_writable()
        assert result["status"] == STATUS_SKIPPED
        assert "timed out" in result["current_value"]

    def test_find_not_found(self, monkeypatch):
        """find not found -> SKIPPED with reason."""
        monkeypatch.setattr(
            "checks_misc.run_cmd",
            lambda args, timeout=15.0: MagicMock(
                returncode=127, stdout="", stderr="command not found", timed_out=False, not_found=True
            ),
        )
        result = check_world_writable()
        assert result["status"] == STATUS_SKIPPED


# ---------------------------------------------------------------------------
# MSC-002: Systemd sandboxing
# ---------------------------------------------------------------------------


class TestSystemdSandboxing:
    def test_no_unit_dir(self, monkeypatch):
        """/etc/systemd/system missing -> SKIPPED."""
        monkeypatch.setattr(os.path, "isdir", lambda p: False)
        results = check_systemd_sandboxing()
        assert len(results) == 1
        assert results[0]["status"] == STATUS_SKIPPED
        assert "does not exist" in results[0]["current_value"]

    def test_no_units(self, monkeypatch):
        """No .service files -> SKIPPED."""
        monkeypatch.setattr(os.path, "isdir", lambda p: True)
        monkeypatch.setattr("checks_misc.glob.glob", lambda pattern: [])
        results = check_systemd_sandboxing()
        assert len(results) == 1
        assert results[0]["status"] == STATUS_SKIPPED
        assert "No local .service unit files" in results[0]["current_value"]

    def test_unit_all_directives(self, monkeypatch, tmp_path):
        """Unit with all directives -> PASS."""
        unit_file = tmp_path / "myservice.service"
        unit_file.write_text(
            "[Service]\n"
            "NoNewPrivileges=true\n"
            "ProtectSystem=strict\n"
            "PrivateTmp=true\n"
            "ProtectHome=true\n"
            "ProtectKernelTunables=true\n"
            "ProtectKernelModules=true\n"
        )
        monkeypatch.setattr(os.path, "isdir", lambda p: True)
        monkeypatch.setattr("checks_misc.glob.glob", lambda pattern: [str(unit_file)])
        monkeypatch.setattr(os.path, "islink", lambda p: False)
        results = check_systemd_sandboxing()
        assert len(results) == 1
        assert results[0]["status"] == STATUS_PASS
        assert "myservice.service" in results[0]["title"]

    def test_unit_missing_directives(self, monkeypatch, tmp_path):
        """Unit missing some directives -> INFO or WARNING."""
        unit_file = tmp_path / "myservice.service"
        unit_file.write_text("[Service]\nNoNewPrivileges=true\n")
        monkeypatch.setattr(os.path, "isdir", lambda p: True)
        monkeypatch.setattr("checks_misc.glob.glob", lambda pattern: [str(unit_file)])
        monkeypatch.setattr(os.path, "islink", lambda p: False)
        results = check_systemd_sandboxing()
        assert len(results) == 1
        # 5 missing directives -> WARNING
        assert results[0]["status"] == STATUS_WARNING
        assert "ProtectSystem" in results[0]["current_value"]

    def test_symlink_skipped(self, monkeypatch, tmp_path):
        """Symlink units are skipped (vendor units)."""
        unit_file = tmp_path / "vendor.service"
        unit_file.write_text("[Service]\n")
        monkeypatch.setattr(os.path, "isdir", lambda p: True)
        monkeypatch.setattr("checks_misc.glob.glob", lambda pattern: [str(unit_file)])
        monkeypatch.setattr(os.path, "islink", lambda p: True)
        results = check_systemd_sandboxing()
        assert len(results) == 1
        assert results[0]["status"] == STATUS_SKIPPED


# ---------------------------------------------------------------------------
# MSC-003: TLS expiry
# ---------------------------------------------------------------------------


class TestTLSExpiry:
    def test_no_ports(self, monkeypatch):
        """No listening ports -> SKIPPED."""
        monkeypatch.setattr(
            "checks_misc.run_cmd",
            lambda args, timeout=5.0: MagicMock(returncode=0, stdout="", stderr="", timed_out=False, not_found=False),
        )
        results = check_tls_expiry()
        assert len(results) == 1
        assert results[0]["status"] == STATUS_SKIPPED
        assert "No local listening TCP ports" in results[0]["current_value"]

    def test_cert_expired(self, monkeypatch):
        """Expired cert -> CRITICAL."""
        monkeypatch.setattr(
            "checks_misc.run_cmd",
            lambda args, timeout=5.0: MagicMock(
                returncode=0, stdout="LISTEN 0 128 0.0.0.0:443 0.0.0.0:*", stderr="", timed_out=False, not_found=False
            ),
        )

        def fake_handshake(port):
            return {"port": port, "days_to_expiry": -5.0, "expires_at": "2024-01-01T00:00:00+00:00"}

        results = check_tls_expiry(handshake_fn=fake_handshake)
        assert len(results) == 1
        assert results[0]["status"] == STATUS_CRITICAL
        assert "expired" in results[0]["current_value"]

    def test_cert_expiring_soon(self, monkeypatch):
        """Cert expires in 2 days -> CRITICAL."""
        monkeypatch.setattr(
            "checks_misc.run_cmd",
            lambda args, timeout=5.0: MagicMock(
                returncode=0, stdout="LISTEN 0 128 0.0.0.0:443 0.0.0.0:*", stderr="", timed_out=False, not_found=False
            ),
        )

        def fake_handshake(port):
            return {"port": port, "days_to_expiry": 2.0, "expires_at": "2024-06-15T00:00:00+00:00"}

        results = check_tls_expiry(handshake_fn=fake_handshake)
        assert len(results) == 1
        assert results[0]["status"] == STATUS_CRITICAL
        assert "expires in 2.0 days" in results[0]["current_value"]

    def test_cert_expiring_14_days(self, monkeypatch):
        """Cert expires in 10 days -> WARNING."""
        monkeypatch.setattr(
            "checks_misc.run_cmd",
            lambda args, timeout=5.0: MagicMock(
                returncode=0, stdout="LISTEN 0 128 0.0.0.0:443 0.0.0.0:*", stderr="", timed_out=False, not_found=False
            ),
        )

        def fake_handshake(port):
            return {"port": port, "days_to_expiry": 10.0, "expires_at": "2024-06-25T00:00:00+00:00"}

        results = check_tls_expiry(handshake_fn=fake_handshake)
        assert len(results) == 1
        assert results[0]["status"] == STATUS_WARNING

    def test_cert_valid(self, monkeypatch):
        """Cert valid for 30 days -> PASS."""
        monkeypatch.setattr(
            "checks_misc.run_cmd",
            lambda args, timeout=5.0: MagicMock(
                returncode=0, stdout="LISTEN 0 128 0.0.0.0:443 0.0.0.0:*", stderr="", timed_out=False, not_found=False
            ),
        )

        def fake_handshake(port):
            return {"port": port, "days_to_expiry": 30.0, "expires_at": "2024-07-15T00:00:00+00:00"}

        results = check_tls_expiry(handshake_fn=fake_handshake)
        assert len(results) == 1
        assert results[0]["status"] == STATUS_PASS

    def test_handshake_failure(self, monkeypatch):
        """Handshake fails -> SKIPPED."""
        monkeypatch.setattr(
            "checks_misc.run_cmd",
            lambda args, timeout=5.0: MagicMock(
                returncode=0, stdout="LISTEN 0 128 0.0.0.0:443 0.0.0.0:*", stderr="", timed_out=False, not_found=False
            ),
        )

        def fake_handshake(port):
            return None

        results = check_tls_expiry(handshake_fn=fake_handshake)
        assert len(results) == 1
        assert results[0]["status"] == STATUS_SKIPPED


# ---------------------------------------------------------------------------
# MSC-004: Failed logins
# ---------------------------------------------------------------------------


class TestFailedLogins:
    def test_no_failures(self, monkeypatch):
        """No failed logins -> SKIPPED."""
        monkeypatch.setattr("checks_misc.detect_environment", lambda: MagicMock(fail2ban=False, crowdsec=False))
        monkeypatch.setattr("checks_misc.open", lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError), raising=False)
        # Simulate no entries
        monkeypatch.setattr("checks_misc._parse_failed_logins", lambda log_path="/var/log/auth.log": {})
        result = check_failed_logins()
        assert result["status"] == STATUS_SKIPPED
        assert "No failed login entries" in result["current_value"]

    def test_high_failures_no_f2b(self, monkeypatch):
        """High failures, no fail2ban -> WARNING."""
        monkeypatch.setattr("checks_misc.detect_environment", lambda: MagicMock(fail2ban=False, crowdsec=False))
        monkeypatch.setattr(
            "checks_misc._parse_failed_logins",
            lambda log_path="/var/log/auth.log": {"192.168.1.100": 150, "10.0.0.5": 20},
        )
        result = check_failed_logins()
        assert result["status"] == STATUS_WARNING
        assert "150 failures" in result["current_value"]

    def test_high_failures_with_f2b(self, monkeypatch):
        """High failures, fail2ban active -> INFO."""
        monkeypatch.setattr("checks_misc.detect_environment", lambda: MagicMock(fail2ban=True, crowdsec=False))
        monkeypatch.setattr(
            "checks_misc._parse_failed_logins",
            lambda log_path="/var/log/auth.log": {"192.168.1.100": 150, "10.0.0.5": 20},
        )
        result = check_failed_logins()
        assert result["status"] == STATUS_INFO
        assert "fail2ban/crowdsec active" in result["current_value"]

    def test_low_failures(self, monkeypatch):
        """Low failures -> PASS."""
        monkeypatch.setattr("checks_misc.detect_environment", lambda: MagicMock(fail2ban=False, crowdsec=False))
        monkeypatch.setattr(
            "checks_misc._parse_failed_logins", lambda log_path="/var/log/auth.log": {"192.168.1.100": 5, "10.0.0.5": 2}
        )
        result = check_failed_logins()
        assert result["status"] == STATUS_PASS
        assert "5 failures" in result["current_value"]
