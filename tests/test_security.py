import json

import pytest

import security


@pytest.fixture(autouse=True)
def setup_security(monkeypatch, tmp_path):
    """Set up security module for tests."""
    # Set environment variables
    monkeypatch.setenv("SECURITYWIZARD_ALLOWED_HOSTS", "localhost,127.0.0.1")
    monkeypatch.setenv("SECURITYWIZARD_BACKUP_DIR", str(tmp_path))
    monkeypatch.setenv("SECURITYWIZARD_AUDIT_LOG", str(tmp_path / "audit.log"))
    monkeypatch.setenv("SECURITYWIZARD_READONLY", "0")

    # Initialize security
    security.init()

    # Reset rate limits
    security._rate_limits = {
        "login": {},
        "apply": {},
        "rollback": {},
    }

    yield


def test_validate_remediation_id():
    """Test remediation ID validation."""
    assert security.validate_remediation_id("NET-001") is True
    assert security.validate_remediation_id("SSH-042") is True
    assert security.validate_remediation_id("net-001") is False
    assert security.validate_remediation_id("NET-1") is False
    assert security.validate_remediation_id("NET-0001") is False
    assert security.validate_remediation_id("NET001") is False
    assert security.validate_remediation_id("") is False


def test_validate_snapshot_id():
    """Test snapshot ID validation."""
    assert security.validate_snapshot_id("SNAP-abc12345") is True
    assert security.validate_snapshot_id("SNAP-ABC12345") is True
    assert security.validate_snapshot_id("SNAP-abc12345678901234567890123456789") is True
    assert security.validate_snapshot_id("SNAP-abc") is False
    assert security.validate_snapshot_id("SNAP-abc123456789012345678901234567890") is False
    assert security.validate_snapshot_id("snap-abc12345") is False
    assert security.validate_snapshot_id("SNAP_abc12345") is False
    assert security.validate_snapshot_id("") is False


def test_check_origin_allowed_no_origin():
    """Test origin check with no Origin/Referer header."""

    class MockRequest:
        headers = {}

    assert security.check_origin_allowed(MockRequest()) is True


def test_check_origin_allowed_matching_origin():
    """Test origin check with matching Origin header."""

    class MockRequest:
        headers = {"origin": "http://localhost"}

    assert security.check_origin_allowed(MockRequest()) is True


def test_check_origin_allowed_mismatching_origin():
    """Test origin check with mismatching Origin header."""

    class MockRequest:
        headers = {"origin": "http://evil.com"}

    assert security.check_origin_allowed(MockRequest()) is False


def test_check_origin_allowed_matching_referer():
    """Test origin check with matching Referer header."""

    class MockRequest:
        headers = {"referer": "http://127.0.0.1/page"}

    assert security.check_origin_allowed(MockRequest()) is True


def test_check_rate_limit_allows_first_request():
    """Test rate limit allows first request."""
    assert security.check_rate_limit("login", "127.0.0.1") is True


def test_check_rate_limit_blocks_excessive_requests():
    """Test rate limit blocks excessive requests."""
    # Make 5 requests (limit is 5)
    for i in range(5):
        assert security.check_rate_limit("login", "127.0.0.1") is True

    # 6th request should be blocked
    assert security.check_rate_limit("login", "127.0.0.1") is False


def test_check_rate_limit_different_ips():
    """Test rate limit works independently per IP."""
    # Use up limit for first IP
    for i in range(5):
        security.check_rate_limit("login", "127.0.0.1")

    # Different IP should still be allowed
    assert security.check_rate_limit("login", "192.168.1.1") is True


def test_audit_log_writes_entry(tmp_path):
    """Test audit log writes JSON lines."""
    security.audit_log("login", "127.0.0.1", result="success")

    with open(tmp_path / "audit.log", "r") as f:
        line = f.readline().strip()

    entry = json.loads(line)
    assert entry["action"] == "login"
    assert entry["client"] == "127.0.0.1"
    assert entry["result"] == "success"
    assert "timestamp" in entry


def test_audit_log_filters_secrets(tmp_path):
    """Test audit log filters out secrets."""
    security.audit_log("login", "127.0.0.1", password="secret123", result="success")

    with open(tmp_path / "audit.log", "r") as f:
        line = f.readline().strip()

    entry = json.loads(line)
    assert "password" not in entry
    assert entry["result"] == "success"


def test_is_readoff_mode(monkeypatch):
    """Test read-only mode detection."""
    monkeypatch.setenv("SECURITYWIZARD_READONLY", "1")
    assert security.is_readonly() is True

    monkeypatch.setenv("SECURITYWIZARD_READONLY", "0")
    assert security.is_readonly() is False


def test_get_security_headers():
    """Test security headers are returned."""
    headers = security.get_security_headers()
    assert headers["Content-Security-Policy"] == "default-src 'self'"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Referrer-Policy"] == "no-referrer"


def test_get_cache_headers():
    """Test cache headers are returned."""
    headers = security.get_cache_headers()
    assert headers["Cache-Control"] == "no-store"
