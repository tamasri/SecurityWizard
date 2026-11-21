import pytest
from unittest.mock import patch
from checks_kernel import (
    _check_bpf_jit_harden,
    _check_tcp_rfc1337,
    _check_secure_redirects,
    _check_ptrace_scope,
    _check_protected_hardlinks,
    _check_protected_symlinks,
    _check_unprivileged_bpf,
    _check_aslr,
)
from common import STATUS_PASS, STATUS_WARNING, STATUS_CRITICAL, STATUS_SKIPPED


@pytest.mark.parametrize("value,expected_status", [
    ("2", STATUS_PASS),
    ("1", STATUS_WARNING),
    ("0", STATUS_CRITICAL),
])
def test_bpf_jit_harden_pass_and_fail(value, expected_status):
    with patch("checks_kernel._read_sysctl") as mock_read:
        mock_read.return_value = (True, value)
        result = _check_bpf_jit_harden()
        assert result["status"] == expected_status
        assert result["id"] == "KRN-008"


def test_bpf_jit_harden_missing():
    with patch("checks_kernel._read_sysctl") as mock_read:
        mock_read.return_value = (False, "")
        result = _check_bpf_jit_harden()
        assert result["status"] == STATUS_SKIPPED
        assert "not found" in result["current_value"]


@pytest.mark.parametrize("value,expected_status", [
    ("1", STATUS_PASS),
    ("0", STATUS_WARNING),
])
def test_tcp_rfc1337_pass_and_fail(value, expected_status):
    with patch("checks_kernel._read_sysctl") as mock_read:
        mock_read.return_value = (True, value)
        result = _check_tcp_rfc1337()
        assert result["status"] == expected_status
        assert result["id"] == "KRN-009"


def test_tcp_rfc1337_missing():
    with patch("checks_kernel._read_sysctl") as mock_read:
        mock_read.return_value = (False, "")
        result = _check_tcp_rfc1337()
        assert result["status"] == STATUS_SKIPPED
        assert "not found" in result["current_value"]


@pytest.mark.parametrize("all_val,def_val,expected_status", [
    ("0", "0", STATUS_PASS),
    ("1", "0", STATUS_WARNING),
    ("0", "1", STATUS_WARNING),
    ("1", "1", STATUS_WARNING),
])
def test_secure_redirects_pass_and_fail(all_val, def_val, expected_status):
    with patch("checks_kernel._read_sysctl") as mock_read:
        mock_read.side_effect = [(True, all_val), (True, def_val)]
        result = _check_secure_redirects()
        assert result["status"] == expected_status
        assert result["id"] == "KRN-010"


def test_secure_redirects_missing():
    with patch("checks_kernel._read_sysctl") as mock_read:
        mock_read.side_effect = [(False, ""), (True, "0")]
        result = _check_secure_redirects()
        assert result["status"] == STATUS_SKIPPED
        assert "not found" in result["current_value"]


@pytest.mark.parametrize("value,expected_status", [
    ("1", STATUS_PASS),
    ("2", STATUS_PASS),
    ("0", STATUS_WARNING),
])
def test_ptrace_scope_pass_and_fail(value, expected_status):
    with patch("checks_kernel._read_sysctl") as mock_read:
        mock_read.return_value = (True, value)
        result = _check_ptrace_scope()
        assert result["status"] == expected_status
        assert result["id"] == "KRN-011"


def test_ptrace_scope_missing():
    with patch("checks_kernel._read_sysctl") as mock_read:
        mock_read.return_value = (False, "")
        result = _check_ptrace_scope()
        assert result["status"] == STATUS_SKIPPED
        assert "not found" in result["current_value"]


@pytest.mark.parametrize("value,expected_status", [
    ("1", STATUS_PASS),
    ("0", STATUS_WARNING),
])
def test_protected_hardlinks_pass_and_fail(value, expected_status):
    with patch("checks_kernel._read_sysctl") as mock_read:
        mock_read.return_value = (True, value)
        result = _check_protected_hardlinks()
        assert result["status"] == expected_status
        assert result["id"] == "KRN-012"


def test_protected_hardlinks_missing():
    with patch("checks_kernel._read_sysctl") as mock_read:
        mock_read.return_value = (False, "")
        result = _check_protected_hardlinks()
        assert result["status"] == STATUS_SKIPPED
        assert "not found" in result["current_value"]


@pytest.mark.parametrize("value,expected_status", [
    ("1", STATUS_PASS),
    ("0", STATUS_WARNING),
])
def test_protected_symlinks_pass_and_fail(value, expected_status):
    with patch("checks_kernel._read_sysctl") as mock_read:
        mock_read.return_value = (True, value)
        result = _check_protected_symlinks()
        assert result["status"] == expected_status
        assert result["id"] == "KRN-013"


def test_protected_symlinks_missing():
    with patch("checks_kernel._read_sysctl") as mock_read:
        mock_read.return_value = (False, "")
        result = _check_protected_symlinks()
        assert result["status"] == STATUS_SKIPPED
        assert "not found" in result["current_value"]


@pytest.mark.parametrize("value,expected_status", [
    ("1", STATUS_PASS),
    ("2", STATUS_PASS),
    ("0", STATUS_WARNING),
])
def test_unprivileged_bpf_pass_and_fail(value, expected_status):
    with patch("checks_kernel._read_sysctl") as mock_read:
        mock_read.return_value = (True, value)
        result = _check_unprivileged_bpf()
        assert result["status"] == expected_status
        assert result["id"] == "KRN-014"


def test_unprivileged_bpf_missing():
    with patch("checks_kernel._read_sysctl") as mock_read:
        mock_read.return_value = (False, "")
        result = _check_unprivileged_bpf()
        assert result["status"] == STATUS_SKIPPED
        assert "not found" in result["current_value"]


@pytest.mark.parametrize("value,expected_status", [
    ("2", STATUS_PASS),
    ("1", STATUS_WARNING),
    ("0", STATUS_CRITICAL),
])
def test_aslr_pass_and_fail(value, expected_status):
    with patch("checks_kernel._read_sysctl") as mock_read:
        mock_read.return_value = (True, value)
        result = _check_aslr()
        assert result["status"] == expected_status
        assert result["id"] == "KRN-015"


def test_aslr_missing():
    with patch("checks_kernel._read_sysctl") as mock_read:
        mock_read.return_value = (False, "")
        result = _check_aslr()
        assert result["status"] == STATUS_SKIPPED
        assert "not found" in result["current_value"]
