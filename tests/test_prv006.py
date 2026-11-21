"""Tests for PRV-006: sshd_config permission evaluation."""

from unittest.mock import MagicMock, patch

from checks_privilege import _check_sshd_config, _evaluate_sshd_config_permissions
from common import STATUS_CRITICAL, STATUS_INFO, STATUS_PASS


def test_sshd_config_0644_root_not_critical():
    """sshd_config with mode 0644 owned by root should not be critical."""
    status = _evaluate_sshd_config_permissions(0o644, 0)
    assert status != STATUS_CRITICAL


def test_sshd_config_0644_root_is_info():
    """sshd_config with mode 0644 owned by root should be INFO (distro default)."""
    status = _evaluate_sshd_config_permissions(0o644, 0)
    assert status == STATUS_INFO


def test_sshd_config_0640_root_is_pass():
    """sshd_config with mode 0640 owned by root should be PASS."""
    status = _evaluate_sshd_config_permissions(0o640, 0)
    assert status == STATUS_PASS


def test_sshd_config_0600_root_is_pass():
    """sshd_config with mode 0600 owned by root should be PASS."""
    status = _evaluate_sshd_config_permissions(0o600, 0)
    assert status == STATUS_PASS


def test_sshd_config_0666_is_critical():
    """sshd_config with mode 0666 (world-writable) should be critical."""
    status = _evaluate_sshd_config_permissions(0o666, 0)
    assert status == STATUS_CRITICAL


def test_sshd_config_0664_is_critical():
    """sshd_config with mode 0664 (group-writable) should be critical."""
    status = _evaluate_sshd_config_permissions(0o664, 0)
    assert status == STATUS_CRITICAL


def test_sshd_config_non_root_owner_is_critical():
    """sshd_config not owned by root should be critical."""
    status = _evaluate_sshd_config_permissions(0o644, 1000)
    assert status == STATUS_CRITICAL


def test_sshd_config_with_private_key_is_critical():
    """sshd_config containing a private key block should be critical."""
    with patch("checks_privilege.os.path.isfile", return_value=True):
        with patch("checks_privilege.read_text", return_value="RSA PRIVATE KEY-----\nabc\ndef\n"):
            status = _evaluate_sshd_config_permissions(0o644, 0)
            assert status == STATUS_CRITICAL


def test_sshd_config_with_password_auth_is_critical():
    """sshd_config with PasswordAuthentication yes should be critical."""
    with patch("checks_privilege.os.path.isfile", return_value=True):
        with patch("checks_privilege.read_text", return_value="PasswordAuthentication yes\n"):
            status = _evaluate_sshd_config_permissions(0o644, 0)
            assert status == STATUS_CRITICAL


def test_check_sshd_config_0644_root():
    """Full check: sshd_config 0644 root should not be critical."""
    mock_stat = MagicMock()
    mock_stat.st_mode = 0o100644
    mock_stat.st_uid = 0
    mock_stat.st_gid = 0

    with patch("checks_privilege.os.path.isfile", return_value=True):
        with patch("checks_privilege.os.stat", return_value=mock_stat):
            with patch("checks_privilege.read_text", return_value=""):
                result = _check_sshd_config()
                assert result["status"] != STATUS_CRITICAL
                assert result["status"] == STATUS_INFO


def test_check_sshd_config_0666():
    """Full check: sshd_config 0666 should be critical."""
    mock_stat = MagicMock()
    mock_stat.st_mode = 0o100666
    mock_stat.st_uid = 0
    mock_stat.st_gid = 0

    with patch("checks_privilege.os.path.isfile", return_value=True):
        with patch("checks_privilege.os.stat", return_value=mock_stat):
            with patch("checks_privilege.read_text", return_value=""):
                result = _check_sshd_config()
                assert result["status"] == STATUS_CRITICAL


def test_check_sshd_config_non_root_owner():
    """Full check: sshd_config owned by non-root should be critical."""
    mock_stat = MagicMock()
    mock_stat.st_mode = 0o100644
    mock_stat.st_uid = 1000
    mock_stat.st_gid = 0

    with patch("checks_privilege.os.path.isfile", return_value=True):
        with patch("checks_privilege.os.stat", return_value=mock_stat):
            with patch("checks_privilege.read_text", return_value=""):
                result = _check_sshd_config()
                assert result["status"] == STATUS_CRITICAL


def test_shadow_0644_is_critical():
    """PRV-003: shadow with mode 0644 should be critical."""
    from checks_privilege import _check_shadow

    mock_stat = MagicMock()
    mock_stat.st_mode = 0o100644
    mock_stat.st_uid = 0
    mock_stat.st_gid = 42

    with patch("checks_privilege.os.path.isfile", return_value=True):
        with patch("checks_privilege.os.stat", return_value=mock_stat):
            result = _check_shadow()
            assert result["status"] == STATUS_CRITICAL
