"""Tests for KRN-001 rp_filter check with Docker/multi-homed detection."""

from unittest.mock import patch

import checks_kernel
from common import STATUS_CRITICAL, STATUS_PASS, STATUS_WARNING


def _mock_run_cmd(rc, out="", err=""):
    """Create a mock run_cmd that returns fixed values."""

    def _run_cmd(args, timeout=20):
        return rc, out, err

    return _run_cmd


def _mock_sysctl_value(key, value):
    """Create a mock run_cmd that returns a specific sysctl value."""

    def _run_cmd(args, timeout=20):
        if args == ["sysctl", "-n", key]:
            return 0, value, ""
        return 1, "", "not found"

    return _run_cmd


class TestKRN001DockerHost:
    """Test KRN-001 on a Docker host (loose mode accepted)."""

    @patch("checks_kernel.run_cmd")
    @patch("checks_kernel.os.path.isdir")
    def test_rpf_loose_pass_on_docker(self, mock_isdir, mock_run_cmd):
        """rp_filter=2 should be PASS on a Docker host."""
        mock_isdir.side_effect = lambda path: path == "/var/lib/docker"
        mock_run_cmd.side_effect = lambda args, timeout=20: (
            (0, "2", "")
            if args == ["sysctl", "-n", "net.ipv4.conf.all.rp_filter"]
            else (0, "2", "")
            if args == ["sysctl", "-n", "net.ipv4.conf.default.rp_filter"]
            else (1, "", "not found")
        )
        result = checks_kernel._check_rpf()
        assert result["status"] == STATUS_PASS
        assert "2 (loose)" in result["recommended_value"]
        assert any("Docker" in d or "containerized" in d.lower() for d in result["details"])

    @patch("checks_kernel.run_cmd")
    @patch("checks_kernel.os.path.isdir")
    def test_rpf_strict_pass_on_docker(self, mock_isdir, mock_run_cmd):
        """rp_filter=1 should also be PASS on a Docker host (acceptable)."""
        mock_isdir.side_effect = lambda path: path == "/var/lib/docker"
        mock_run_cmd.side_effect = lambda args, timeout=20: (
            (0, "1", "")
            if args == ["sysctl", "-n", "net.ipv4.conf.all.rp_filter"]
            else (0, "1", "")
            if args == ["sysctl", "-n", "net.ipv4.conf.default.rp_filter"]
            else (1, "", "not found")
        )
        result = checks_kernel._check_rpf()
        assert result["status"] == STATUS_PASS
        assert "strict" in result["recommended_value"].lower() or "loose" in result["recommended_value"].lower()

    @patch("checks_kernel.run_cmd")
    @patch("checks_kernel.os.path.isdir")
    def test_rpf_zero_warning_on_docker(self, mock_isdir, mock_run_cmd):
        """rp_filter=0 should be WARNING on a Docker host."""
        mock_isdir.side_effect = lambda path: path == "/var/lib/docker"
        mock_run_cmd.side_effect = lambda args, timeout=20: (
            (0, "0", "")
            if args == ["sysctl", "-n", "net.ipv4.conf.all.rp_filter"]
            else (0, "0", "")
            if args == ["sysctl", "-n", "net.ipv4.conf.default.rp_filter"]
            else (1, "", "not found")
        )
        result = checks_kernel._check_rpf()
        assert result["status"] == STATUS_WARNING
        assert "2 (loose)" in result["recommended_value"]


class TestKRN001PlainHost:
    """Test KRN-001 on a plain single-homed host."""

    @patch("checks_kernel.run_cmd")
    @patch("checks_kernel.os.path.isdir")
    def test_rpf_strict_pass_on_plain(self, mock_isdir, mock_run_cmd):
        """rp_filter=1 should be PASS on a plain host."""
        mock_isdir.return_value = False
        mock_run_cmd.side_effect = lambda args, timeout=20: (
            (0, "1", "")
            if args == ["sysctl", "-n", "net.ipv4.conf.all.rp_filter"]
            else (0, "1", "")
            if args == ["sysctl", "-n", "net.ipv4.conf.default.rp_filter"]
            else (1, "", "not found")
        )
        result = checks_kernel._check_rpf()
        assert result["status"] == STATUS_PASS
        assert "1 (strict)" in result["recommended_value"]

    @patch("checks_kernel.run_cmd")
    @patch("checks_kernel.os.path.isdir")
    def test_rpf_loose_warning_on_plain(self, mock_isdir, mock_run_cmd):
        """rp_filter=2 should be WARNING on a plain host."""
        mock_isdir.return_value = False
        mock_run_cmd.side_effect = lambda args, timeout=20: (
            (0, "2", "")
            if args == ["sysctl", "-n", "net.ipv4.conf.all.rp_filter"]
            else (0, "2", "")
            if args == ["sysctl", "-n", "net.ipv4.conf.default.rp_filter"]
            else (1, "", "not found")
        )
        result = checks_kernel._check_rpf()
        assert result["status"] == STATUS_WARNING
        assert "1 (strict)" in result["recommended_value"]

    @patch("checks_kernel.run_cmd")
    @patch("checks_kernel.os.path.isdir")
    def test_rpf_zero_critical_on_plain(self, mock_isdir, mock_run_cmd):
        """rp_filter=0 should be CRITICAL on a plain host."""
        mock_isdir.return_value = False
        mock_run_cmd.side_effect = lambda args, timeout=20: (
            (0, "0", "")
            if args == ["sysctl", "-n", "net.ipv4.conf.all.rp_filter"]
            else (0, "0", "")
            if args == ["sysctl", "-n", "net.ipv4.conf.default.rp_filter"]
            else (1, "", "not found")
        )
        result = checks_kernel._check_rpf()
        assert result["status"] == STATUS_CRITICAL
        assert "1 (strict)" in result["recommended_value"]


class TestRemediationPlanDocker:
    """Test that the remediation plan for a Docker host contains rp_filter=2."""

    @patch("actions_system.run_cmd")
    @patch("actions_system.os.path.isdir")
    def test_sysctl_baseline_docker_contains_rp_filter_2(self, mock_isdir, mock_run_cmd):
        """The sysctl_baseline plan on a Docker host must set rp_filter=2."""
        import actions_system

        mock_isdir.side_effect = lambda path: path == "/var/lib/docker"
        mock_run_cmd.side_effect = lambda args, timeout=20: (
            (1, "", "not found")
            if args == ["which", "docker"]
            else (1, "", "not found")
            if args == ["which", "kubelet"]
            else (1, "", "not found")
            if args == ["which", "wg"]
            else (0, "default via 10.0.0.1 dev eth0\n", "")
            if args == ["ip", "route", "show", "default"]
            else (0, "default via 10.0.0.1 dev eth0\n10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5\n", "")
            if args == ["ip", "-o", "-4", "route", "show"]
            else (1, "", "not found")
        )
        plan = actions_system._build_sysctl_baseline()
        assert "blockers" not in plan or not plan["blockers"]
        file_change = plan["file_changes"][0]
        content = file_change["new_content"]
        assert "net.ipv4.conf.all.rp_filter=2" in content
        assert "net.ipv4.conf.default.rp_filter=2" in content
        assert any("loose" in w.lower() or "containerized" in w.lower() for w in plan["warnings"])


class TestRemediationPlanPlain:
    """Test that the remediation plan for a plain host contains rp_filter=1."""

    @patch("actions_system.run_cmd")
    @patch("actions_system.os.path.isdir")
    def test_sysctl_baseline_plain_contains_rp_filter_1(self, mock_isdir, mock_run_cmd):
        """The sysctl_baseline plan on a plain host must set rp_filter=1."""
        import actions_system

        mock_isdir.return_value = False
        mock_run_cmd.side_effect = lambda args, timeout=20: (
            (1, "", "not found")
            if args == ["which", "docker"]
            else (1, "", "not found")
            if args == ["which", "kubelet"]
            else (1, "", "not found")
            if args == ["which", "wg"]
            else (0, "default via 10.0.0.1 dev eth0\n", "")
            if args == ["ip", "route", "show", "default"]
            else (0, "default via 10.0.0.1 dev eth0\n10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5\n", "")
            if args == ["ip", "-o", "-4", "route", "show"]
            else (1, "", "not found")
        )
        plan = actions_system._build_sysctl_baseline()
        assert "blockers" not in plan or not plan["blockers"]
        file_change = plan["file_changes"][0]
        content = file_change["new_content"]
        assert "net.ipv4.conf.all.rp_filter=1" in content
        assert "net.ipv4.conf.default.rp_filter=1" in content
        assert not plan["warnings"] or not any("loose" in w.lower() for w in plan["warnings"])
