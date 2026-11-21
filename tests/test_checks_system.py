"""Tests for checks_system.py."""
import pytest
from unittest.mock import MagicMock, patch
from common import (
    STATUS_PASS, STATUS_WARNING, STATUS_CRITICAL, STATUS_INFO, STATUS_SKIPPED,
    make_check, skipped_check, run_cmd, read_text,
)
from envdetect import Environment
from checks_system import (
    _check_auditd,
    _check_unattended_upgrades,
    _check_reboot_required,
    _check_noexec_tmp,
    _check_core_dumps,
    _check_time_sync,
    _check_apparmor_selinux,
    run_checks,
)

def _make_env(is_docker=False):
    """Create an Environment object with the specified docker flag."""
    env = Environment()
    env.is_docker = is_docker
    return env


def _make_cmd_result(returncode=0, stdout="", stderr="", timed_out=False, not_found=False):
    from common import CmdResult
    return CmdResult(
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        not_found=not_found,
    )


class TestCheckAuditd:
    def test_auditd_not_installed(self):
        runner = MagicMock()
        runner.return_value = _make_cmd_result(returncode=127, not_found=True)
        result = _check_auditd(runner=runner)
        assert result["id"] == "SYS-001"
        assert result["status"] == STATUS_SKIPPED
        assert "auditctl command not found" in result["current_value"]

    def test_auditd_not_running(self):
        runner = MagicMock()
        runner.return_value = _make_cmd_result(returncode=1, stderr="auditd is not running")
        result = _check_auditd(runner=runner)
        assert result["id"] == "SYS-001"
        assert result["status"] == STATUS_SKIPPED
        assert "auditd is not running" in result["current_value"]

    def test_auditd_running_no_rules(self):
        runner = MagicMock()
        runner.side_effect = [
            _make_cmd_result(returncode=0, stdout="enabled 1\n"),
            _make_cmd_result(returncode=0, stdout=""),
        ]
        result = _check_auditd(runner=runner)
        assert result["id"] == "SYS-001"
        assert result["status"] == STATUS_INFO
        assert "No rules configured" in result["current_value"]

    def test_auditd_running_with_rules(self):
        runner = MagicMock()
        runner.side_effect = [
            _make_cmd_result(returncode=0, stdout="enabled 1\n"),
            _make_cmd_result(returncode=0, stdout="-w /etc/passwd -p wa -k identity\n-w /etc/shadow -p wa -k identity\n"),
        ]
        result = _check_auditd(runner=runner)
        assert result["id"] == "SYS-001"
        assert result["status"] == STATUS_PASS
        assert "2 rule(s) configured" in result["current_value"]


class TestCheckUnattendedUpgrades:
    def test_not_installed(self):
        runner = MagicMock()
        runner.return_value = _make_cmd_result(returncode=0, stdout="un  unattended-upgrades 1.2.3  <none>\n")
        result = _check_unattended_upgrades(runner=runner)
        assert result["id"] == "SYS-002"
        assert result["status"] == STATUS_SKIPPED
        assert "not found" in result["current_value"]

    def test_installed_but_timer_not_enabled(self):
        runner = MagicMock()
        runner.side_effect = [
            _make_cmd_result(returncode=0, stdout="ii  unattended-upgrades 1.2.3  amd64  automatic installation of security upgrades\n"),
            _make_cmd_result(returncode=1, stderr="disabled"),
        ]
        result = _check_unattended_upgrades(runner=runner)
        assert result["id"] == "SYS-002"
        assert result["status"] == STATUS_WARNING
        assert "timer not enabled" in result["title"]

    def test_installed_and_enabled(self):
        runner = MagicMock()
        runner.side_effect = [
            _make_cmd_result(returncode=0, stdout="ii  unattended-upgrades 1.2.3  amd64  automatic installation of security upgrades\n"),
            _make_cmd_result(returncode=0, stdout="enabled\n"),
        ]
        result = _check_unattended_upgrades(runner=runner)
        assert result["id"] == "SYS-002"
        assert result["status"] == STATUS_PASS
        assert "enabled" in result["current_value"]


class TestCheckRebootRequired:
    def test_reboot_required(self, tmp_path):
        reboot_file = tmp_path / "reboot-required"
        reboot_file.write_text("Reboot required\n")
        
        runner = MagicMock()
        runner.side_effect = [
            _make_cmd_result(returncode=0, stdout="6.8.0-40-generic\n"),
            _make_cmd_result(returncode=0, stdout="ii  linux-image-6.8.0-40-generic  6.8.0-40.40  amd64\n"),
        ]
        
        with patch("checks_system.open", create=True) as mock_open:
            mock_open.return_value.__enter__.return_value.read.return_value = "Reboot required\n"
            result = _check_reboot_required(runner=runner)
        
        assert result["id"] == "SYS-003"
        assert result["status"] == STATUS_WARNING
        assert "Reboot required" in result["title"]

    def test_no_reboot_required(self):
        runner = MagicMock()
        runner.side_effect = [
            _make_cmd_result(returncode=0, stdout="6.8.0-40-generic\n"),
            _make_cmd_result(returncode=0, stdout="ii  linux-image-6.8.0-40-generic  6.8.0-40.40  amd64\n"),
        ]
        
        with patch("checks_system.open", create=True) as mock_open:
            mock_open.side_effect = FileNotFoundError()
            result = _check_reboot_required(runner=runner)
        
        assert result["id"] == "SYS-003"
        assert result["status"] == STATUS_PASS
        assert "No reboot required" in result["title"]

    def test_running_kernel_not_installed(self):
        runner = MagicMock()
        runner.side_effect = [
            _make_cmd_result(returncode=0, stdout="6.8.0-39-generic\n"),
            _make_cmd_result(returncode=0, stdout="ii  linux-image-6.8.0-40-generic  6.8.0-40.40  amd64\n"),
        ]
        
        with patch("checks_system.open", create=True) as mock_open:
            mock_open.side_effect = FileNotFoundError()
            result = _check_reboot_required(runner=runner)
        
        assert result["id"] == "SYS-003"
        assert result["status"] == STATUS_WARNING
        assert "not in installed list" in result["title"]


class TestCheckNoexecTmp:
    def test_all_options_present(self):
        runner = MagicMock()
        runner.return_value = _make_cmd_result(
            returncode=0,
            stdout="/dev/sda1 on / type ext4 (rw,noatime)\ntmpfs on /tmp type tmpfs (rw,nosuid,nodev,noexec,size=100000k)\ntmpfs on /var/tmp type tmpfs (rw,nosuid,nodev,noexec,size=100000k)\ntmpfs on /dev/shm type tmpfs (rw,nosuid,nodev,noexec,size=100000k)\n"
        )
        env = _make_env(is_docker=False)
        result = _check_noexec_tmp(runner=runner, env=env)
        assert result["id"] == "SYS-004"
        assert result["status"] == STATUS_PASS
        assert "noexec,nosuid,nodev" in result["current_value"]

    def test_missing_noexec(self):
        runner = MagicMock()
        runner.return_value = _make_cmd_result(
            returncode=0,
            stdout="/dev/sda1 on / type ext4 (rw,noatime)\ntmpfs on /tmp type tmpfs (rw,nosuid,nodev,size=100000k)\ntmpfs on /var/tmp type tmpfs (rw,nosuid,nodev,noexec,size=100000k)\ntmpfs on /dev/shm type tmpfs (rw,nosuid,nodev,noexec,size=100000k)\n"
        )
        env = _make_env(is_docker=False)
        result = _check_noexec_tmp(runner=runner, env=env)
        assert result["id"] == "SYS-004"
        assert result["status"] == STATUS_WARNING
        assert "/tmp missing noexec" in result["current_value"]

    def test_missing_noexec_on_docker_host(self):
        runner = MagicMock()
        runner.return_value = _make_cmd_result(
            returncode=0,
            stdout="/dev/sda1 on / type ext4 (rw,noatime)\ntmpfs on /tmp type tmpfs (rw,nosuid,nodev,size=100000k)\ntmpfs on /var/tmp type tmpfs (rw,nosuid,nodev,noexec,size=100000k)\ntmpfs on /dev/shm type tmpfs (rw,nosuid,nodev,noexec,size=100000k)\n"
        )
        env = _make_env(is_docker=True)
        result = _check_noexec_tmp(runner=runner, env=env)
        assert result["id"] == "SYS-004"
        assert result["status"] == STATUS_INFO
        assert "/tmp missing noexec" in result["current_value"]


class TestCheckCoreDumps:
    def test_optimal_settings(self):
        runner = MagicMock()
        runner.side_effect = [
            _make_cmd_result(returncode=0, stdout="fs.suid_dumpable = 0\n"),
            _make_cmd_result(returncode=0, stdout="kernel.core_pattern = |/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h\n"),
            _make_cmd_result(returncode=0, stdout="MemoryMax=infinity\nTasksMax=infinity\n"),
        ]
        result = _check_core_dumps(runner=runner)
        assert result["id"] == "SYS-005"
        assert result["status"] == STATUS_PASS
        assert "optimal" in result["title"]

    def test_suid_dumpable_not_zero(self):
        runner = MagicMock()
        runner.side_effect = [
            _make_cmd_result(returncode=0, stdout="fs.suid_dumpable = 2\n"),
            _make_cmd_result(returncode=0, stdout="kernel.core_pattern = |/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h\n"),
            _make_cmd_result(returncode=0, stdout="MemoryMax=infinity\nTasksMax=infinity\n"),
        ]
        result = _check_core_dumps(runner=runner)
        assert result["id"] == "SYS-005"
        assert result["status"] == STATUS_WARNING
        assert "fs.suid_dumpable=2" in result["current_value"]


class TestCheckTimeSync:
    def test_ntp_synchronized(self):
        runner = MagicMock()
        runner.return_value = _make_cmd_result(returncode=0, stdout="NTPSynchronized=yes\nTimezone=UTC\n")
        result = _check_time_sync(runner=runner)
        assert result["id"] == "SYS-006"
        assert result["status"] == STATUS_PASS
        assert "NTPSynchronized=yes" in result["current_value"]

    def test_ntp_not_synchronized(self):
        runner = MagicMock()
        runner.return_value = _make_cmd_result(returncode=0, stdout="NTPSynchronized=no\nTimezone=UTC\n")
        result = _check_time_sync(runner=runner)
        assert result["id"] == "SYS-006"
        assert result["status"] == STATUS_WARNING
        assert "NTPSynchronized=no" in result["current_value"]

    def test_chrony_active(self):
        runner = MagicMock()
        runner.side_effect = [
            _make_cmd_result(returncode=1, stderr="Failed to parse timedatectl output"),
            _make_cmd_result(returncode=0, stdout="Reference ID    : 0x12345678\nStratum         : 2\n"),
        ]
        result = _check_time_sync(runner=runner)
        assert result["id"] == "SYS-006"
        assert result["status"] == STATUS_PASS
        assert "chrony" in result["title"]


class TestCheckAppArmorSelinux:
    def test_apparmor_enforcing(self):
        runner = MagicMock()
        runner.return_value = _make_cmd_result(returncode=0, stdout="apparmor is enabled\n")
        result = _check_apparmor_selinux(runner=runner)
        assert result["id"] == "SYS-007"
        assert result["status"] == STATUS_PASS
        assert "AppArmor" in result["title"]

    def test_selinux_enforcing(self):
        runner = MagicMock()
        runner.side_effect = [
            _make_cmd_result(returncode=1, stderr="aa-status: command not found"),
            _make_cmd_result(returncode=0, stdout="Enforcing\n"),
        ]
        result = _check_apparmor_selinux(runner=runner)
        assert result["id"] == "SYS-007"
        assert result["status"] == STATUS_PASS
        assert "SELinux" in result["title"]

    def test_no_mac_system(self):
        runner = MagicMock()
        runner.side_effect = [
            _make_cmd_result(returncode=1, stderr="aa-status: command not found"),
            _make_cmd_result(returncode=1, stderr="getenforce: command not found"),
        ]
        result = _check_apparmor_selinux(runner=runner)
        assert result["id"] == "SYS-007"
        assert result["status"] == STATUS_WARNING
        assert "No MAC system" in result["title"]


class TestRunChecks:
    def test_run_checks_returns_all_checks(self):
        with patch("checks_system._check_auditd") as mock_auditd, \
             patch("checks_system._check_unattended_upgrades") as mock_updates, \
             patch("checks_system._check_reboot_required") as mock_reboot, \
             patch("checks_system._check_noexec_tmp") as mock_noexec, \
             patch("checks_system._check_core_dumps") as mock_core, \
             patch("checks_system._check_time_sync") as mock_time, \
             patch("checks_system._check_apparmor_selinux") as mock_mac:
            
            mock_auditd.return_value = {"id": "SYS-001", "status": STATUS_PASS}
            mock_updates.return_value = {"id": "SYS-002", "status": STATUS_PASS}
            mock_reboot.return_value = {"id": "SYS-003", "status": STATUS_PASS}
            mock_noexec.return_value = {"id": "SYS-004", "status": STATUS_PASS}
            mock_core.return_value = {"id": "SYS-005", "status": STATUS_PASS}
            mock_time.return_value = {"id": "SYS-006", "status": STATUS_PASS}
            mock_mac.return_value = {"id": "SYS-007", "status": STATUS_PASS}
            
            checks = run_checks()
            assert len(checks) == 7
            assert checks[0]["id"] == "SYS-001"
            assert checks[6]["id"] == "SYS-007"
