"""Tests for sshd_effective module."""

from unittest.mock import patch

from common import CmdResult
from sshd_effective import effective_config, evaluate_ssh_security, listening_ssh_ports


def test_listening_ssh_ports_from_ss():
    """Test port detection from ss output."""
    mock_ss = CmdResult(
        returncode=0,
        stdout='tcp LISTEN 0 128 0.0.0.0:22 users:(("sshd",pid=123,fd=3))\ntcp LISTEN 0 128 0.0.0.0:2222 users:(("sshd",pid=124,fd=3))',
        stderr="",
    )
    mock_sshd = CmdResult(returncode=0, stdout="port 22\nport 2222\n", stderr="")

    with patch("sshd_effective.run_cmd") as mock_run:
        mock_run.side_effect = [mock_ss, mock_sshd]
        ports = listening_ssh_ports()
        assert ports == [22, 2222]


def test_effective_config_hardened_server():
    """Test effective config for hardened key-only two-port server."""
    mock_sshd = CmdResult(
        returncode=0,
        stdout="""port 22
permitrootlogin no
passwordauthentication no
pubkeyauthentication yes
permitemptypasswords no
x11forwarding no
maxauthtries 3
ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com
macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
kexalgorithms curve25519-sha256,diffie-hellman-group16-sha512
""",
        stderr="",
    )

    with patch("sshd_effective.run_cmd") as mock_run:
        mock_run.return_value = mock_sshd
        result = effective_config(port=22)
        assert result["error"] is None
        assert result["config"]["permitrootlogin"] == "no"
        assert result["config"]["passwordauthentication"] == "no"
        assert result["config"]["pubkeyauthentication"] == "yes"
        assert result["config"]["ciphers"] == ["aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"]


def test_effective_config_weak_legacy_server():
    """Test effective config for weak legacy server."""
    mock_sshd = CmdResult(
        returncode=0,
        stdout="""port 22
permitrootlogin yes
passwordauthentication yes
pubkeyauthentication yes
permitemptypasswords yes
x11forwarding yes
maxauthtries 10
ciphers aes128-cbc,3des-cbc,arcfour
macs hmac-md5,hmac-sha1
kexalgorithms diffie-hellman-group1-sha1,diffie-hellman-group14-sha1
""",
        stderr="",
    )

    with patch("sshd_effective.run_cmd") as mock_run:
        mock_run.return_value = mock_sshd
        result = effective_config(port=22)
        assert result["error"] is None
        assert result["config"]["permitrootlogin"] == "yes"
        assert result["config"]["passwordauthentication"] == "yes"
        assert result["config"]["ciphers"] == ["aes128-cbc", "3des-cbc", "arcfour"]


def test_evaluate_ssh_security_hardened():
    """Test security evaluation for hardened server."""
    mock_sshd = CmdResult(
        returncode=0,
        stdout="""port 22
permitrootlogin no
passwordauthentication no
pubkeyauthentication yes
permitemptypasswords no
x11forwarding no
maxauthtries 3
ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com
macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
kexalgorithms curve25519-sha256,diffie-hellman-group16-sha512
""",
        stderr="",
    )

    with patch("sshd_effective.run_cmd") as mock_run:
        mock_run.return_value = mock_sshd
        result = evaluate_ssh_security(port=22)
        assert result["status"] == "OK"
        # Check that weak algorithms are not flagged
        weak_checks = [f for f in result["findings"] if f["check"].startswith("Weak")]
        assert len(weak_checks) == 0


def test_evaluate_ssh_security_weak():
    """Test security evaluation for weak server."""
    mock_sshd = CmdResult(
        returncode=0,
        stdout="""port 22
permitrootlogin yes
passwordauthentication yes
pubkeyauthentication yes
permitemptypasswords yes
x11forwarding yes
maxauthtries 10
ciphers aes128-cbc,3des-cbc,arcfour
macs hmac-md5,hmac-sha1
kexalgorithms diffie-hellman-group1-sha1,diffie-hellman-group14-sha1
""",
        stderr="",
    )

    with patch("sshd_effective.run_cmd") as mock_run:
        mock_run.return_value = mock_sshd
        result = evaluate_ssh_security(port=22)
        assert result["status"] == "OK"
        # Check that weak algorithms are flagged
        weak_ciphers = [f for f in result["findings"] if f["check"] == "WeakCiphers"]
        assert len(weak_ciphers) == 1
        assert "aes128-cbc" in weak_ciphers[0]["value"]
        assert "3des-cbc" in weak_ciphers[0]["value"]
        assert "arcfour" in weak_ciphers[0]["value"]


def test_sshd_t_failure():
    """Test handling of sshd -T failure."""
    mock_sshd = CmdResult(returncode=1, stdout="", stderr="sshd: error reading config")

    with patch("sshd_effective.run_cmd") as mock_run:
        mock_run.return_value = mock_sshd
        result = effective_config(port=22)
        assert result["error"] == "sshd: error reading config"
        assert result["config"] == {}
