"""System checks: auditd, updates, reboot, noexec /tmp, core dumps, time sync, AppArmor/SELinux."""

import logging
from typing import List

from common import (
    STATUS_INFO,
    STATUS_PASS,
    STATUS_WARNING,
    make_check,
    run_cmd,
    skipped_check,
)
from envdetect import detect_environment

logger = logging.getLogger(__name__)


def _check_auditd(runner=None) -> dict:
    """Check that auditd is active and has rules."""
    if runner is None:
        runner = run_cmd

    # Check if auditd is running
    result = runner(["auditctl", "-s"], timeout=10.0)
    if result.not_found:
        return skipped_check(
            id="SYS-001",
            category="system",
            title="auditd not installed",
            what_it_checks="Whether auditd is installed and running.",
            risk="No system auditing is active.",
            command="auditctl -s",
            reason="auditctl command not found",
        )
    if result.returncode != 0:
        return skipped_check(
            id="SYS-001",
            category="system",
            title="auditd not running",
            what_it_checks="Whether auditd is installed and running.",
            risk="No system auditing is active.",
            command="auditctl -s",
            reason="auditd is not running: " + result.stderr.strip(),
        )

    # Check if there are rules
    rules_result = runner(["auditctl", "-l"], timeout=10.0)
    if rules_result.returncode != 0:
        return skipped_check(
            id="SYS-001",
            category="system",
            title="auditd rule check failed",
            what_it_checks="Whether auditd has active rules.",
            risk="Audit rules may not be configured.",
            command="auditctl -l",
            reason="Failed to list audit rules: " + rules_result.stderr.strip(),
        )

    rules = [line for line in rules_result.stdout.strip().splitlines() if line.strip()]
    if not rules:
        return make_check(
            id="SYS-001",
            category="system",
            title="auditd running but no rules",
            status=STATUS_INFO,
            what_it_checks="Whether auditd is installed and running.",
            risk="Auditd is running but no rules are configured, so nothing is being audited.",
            command="auditctl -l",
            current_value="No rules configured",
            recommended_value="Add audit rules for critical files and system calls",
            details=["auditd is running but has no active rules"],
        )

    return make_check(
        id="SYS-001",
        category="system",
        title="auditd active with rules",
        status=STATUS_PASS,
        what_it_checks="Whether auditd is installed and running.",
        risk="System auditing is active and rules are configured.",
        command="auditctl -l",
        current_value="{} rule(s) configured".format(len(rules)),
        recommended_value="Keep auditd running with appropriate rules",
        details=["auditd is running with {} active rule(s)".format(len(rules))],
    )


def _check_unattended_upgrades(runner=None, fs=None) -> dict:
    """Check if unattended-upgrades is installed and enabled."""
    if runner is None:
        runner = run_cmd
    if fs is None:
        from envdetect import _default_fs

        fs = _default_fs()

    # Check if unattended-upgrades package is installed
    result = runner(["dpkg", "-l", "unattended-upgrades"], timeout=10.0)
    if result.not_found or result.returncode != 0:
        return skipped_check(
            id="SYS-002",
            category="system",
            title="unattended-upgrades not installed",
            what_it_checks="Whether unattended-upgrades is installed and enabled.",
            risk="Security updates are not applied automatically.",
            command="dpkg -l unattended-upgrades",
            reason="unattended-upgrades package not found",
        )

    # Check if the package is installed (ii status)
    if "ii" not in result.stdout:
        return skipped_check(
            id="SYS-002",
            category="system",
            title="unattended-upgrades not installed",
            what_it_checks="Whether unattended-upgrades is installed and enabled.",
            risk="Security updates are not applied automatically.",
            command="dpkg -l unattended-upgrades",
            reason="unattended-upgrades package not found",
        )

    # Check if systemd timer is enabled
    timer_result = runner(["systemctl", "is-enabled", "unattended-upgrades.timer"], timeout=10.0)
    if timer_result.returncode != 0:
        return make_check(
            id="SYS-002",
            category="system",
            title="unattended-upgrades timer not enabled",
            status=STATUS_WARNING,
            what_it_checks="Whether unattended-upgrades is installed and enabled.",
            risk="Unattended upgrades may not run automatically.",
            command="systemctl is-enabled unattended-upgrades.timer",
            current_value=timer_result.stdout.strip() or timer_result.stderr.strip(),
            recommended_value="Enable timer: systemctl enable --now unattended-upgrades.timer",
            details=["unattended-upgrades.timer is not enabled"],
        )

    return make_check(
        id="SYS-002",
        category="system",
        title="unattended-upgrades enabled",
        status=STATUS_PASS,
        what_it_checks="Whether unattended-upgrades is installed and enabled.",
        risk="Security updates are applied automatically.",
        command="systemctl is-enabled unattended-upgrades.timer",
        current_value="enabled",
        recommended_value="Keep unattended-upgrades enabled",
        details=["unattended-upgrades is installed and timer is enabled"],
    )


def _check_reboot_required(runner=None) -> dict:
    """Check if a reboot is required and if running kernel matches installed kernel."""
    if runner is None:
        runner = run_cmd

    # Check /var/run/reboot-required
    reboot_file = "/var/run/reboot-required"
    try:
        with open(reboot_file, "r", encoding="utf-8") as f:
            reboot_content = f.read().strip()
        reboot_required = True
    except FileNotFoundError:
        reboot_required = False
        reboot_content = ""
    except Exception as exc:
        logger.warning("Failed to read reboot-required file: %s", exc)
        return skipped_check(
            id="SYS-003",
            category="system",
            title="Reboot check failed",
            what_it_checks="Whether a reboot is required.",
            risk="System may be running outdated kernel or libraries.",
            command="cat /var/run/reboot-required",
            reason="Failed to read reboot-required file: " + str(exc),
        )

    # Get running kernel
    uname_result = runner(["uname", "-r"], timeout=10.0)
    if uname_result.returncode != 0:
        return skipped_check(
            id="SYS-003",
            category="system",
            title="uname failed",
            what_it_checks="Whether a reboot is required.",
            risk="Cannot determine running kernel version.",
            command="uname -r",
            reason="uname command failed: " + uname_result.stderr.strip(),
        )
    running_kernel = uname_result.stdout.strip()

    # Get installed kernels via dpkg
    dpkg_result = runner(["dpkg", "-l", "linux-image-*"], timeout=10.0)
    if dpkg_result.returncode != 0:
        return skipped_check(
            id="SYS-003",
            category="system",
            title="dpkg query failed",
            what_it_checks="Whether a reboot is required.",
            risk="Cannot determine installed kernel versions.",
            command="dpkg -l linux-image-*",
            reason="dpkg query failed: " + dpkg_result.stderr.strip(),
        )

    # Parse installed kernels
    installed_kernels = []
    for line in dpkg_result.stdout.strip().splitlines():
        if line.startswith("ii"):
            parts = line.split()
            if len(parts) >= 2:
                pkg_name = parts[1]
                if pkg_name.startswith("linux-image-"):
                    kernel_ver = pkg_name[len("linux-image-") :]
                    installed_kernels.append(kernel_ver)

    if not installed_kernels:
        return skipped_check(
            id="SYS-003",
            category="system",
            title="No installed kernels found",
            what_it_checks="Whether a reboot is required.",
            risk="Cannot compare running kernel with installed kernels.",
            command="dpkg -l linux-image-*",
            reason="No linux-image packages found",
        )

    # Check if running kernel is the newest installed
    if running_kernel not in installed_kernels:
        return make_check(
            id="SYS-003",
            category="system",
            title="Running kernel not in installed list",
            status=STATUS_WARNING,
            what_it_checks="Whether a reboot is required.",
            risk="Running kernel may be outdated.",
            command="uname -r",
            current_value="Running: {}, Installed: {}".format(running_kernel, ", ".join(sorted(installed_kernels))),
            recommended_value="Reboot to load the installed kernel",
            details=["Running kernel {} is not among installed kernels".format(running_kernel)],
        )

    if reboot_required:
        return make_check(
            id="SYS-003",
            category="system",
            title="Reboot required",
            status=STATUS_WARNING,
            what_it_checks="Whether a reboot is required.",
            risk="System has pending updates that require a reboot.",
            command="cat /var/run/reboot-required",
            current_value="Reboot required: " + reboot_content,
            recommended_value="Reboot the system to apply pending updates",
            details=["/var/run/reboot-required exists"],
        )

    return make_check(
        id="SYS-003",
        category="system",
        title="No reboot required",
        status=STATUS_PASS,
        what_it_checks="Whether a reboot is required.",
        risk="System is up to date.",
        command="cat /var/run/reboot-required",
        current_value="Running kernel: {}".format(running_kernel),
        recommended_value="No action needed",
        details=["No reboot required, running kernel matches installed kernel"],
    )


def _check_noexec_tmp(runner=None, env=None) -> dict:
    """Check /tmp, /var/tmp, /dev/shm mount options for noexec, nosuid, nodev."""
    if runner is None:
        runner = run_cmd

    if env is None:
        env = detect_environment()
    # is_container_host checks if the *system itself* is running inside a container.
    # We need to know if the host *runs* Docker (i.e. has Docker installed and running).
    # The Environment object has an 'is_docker' attribute which indicates if Docker is detected on the host.
    # However, looking at envdetect.py signatures, `is_container_host` returns a bool.
    # The test `_make_env` sets `env.is_docker = is_docker`.
    # The `Environment` class likely has an `is_docker` attribute.
    # Let's check how `is_container_host` works vs `env.is_docker`.
    # In the test, `env.is_docker` is set.
    # The implementation uses `is_container_host(env)`.
    # If `is_container_host` checks if we are *inside* a container, it might return False for a Docker host.
    # The requirement says: "INFO on Docker hosts where noexec may break things".
    # A "Docker host" is a machine running Docker, not necessarily inside a container.
    # The `Environment` object has an `is_docker` attribute (from `_probe_docker`).
    # `is_container_host` likely checks if the current process is in a container.
    # So we should use `env.is_docker` instead of `is_container_host(env)`.
    is_docker = getattr(env, "is_docker", False)

    mount_result = runner(["mount"], timeout=10.0)
    if mount_result.returncode != 0:
        return skipped_check(
            id="SYS-004",
            category="system",
            title="mount command failed",
            what_it_checks="Mount options for /tmp, /var/tmp, /dev/shm.",
            risk="Cannot verify noexec/nosuid/nodev options.",
            command="mount",
            reason="mount command failed: " + mount_result.stderr.strip(),
        )

    mounts = {}
    for line in mount_result.stdout.strip().splitlines():
        parts = line.split()
        if len(parts) >= 4:
            mount_point = parts[2]
            # Find the part that starts with '(' - that's the options
            options = ""
            for i, part in enumerate(parts):
                if part.startswith("("):
                    options = part.strip("()")
                    break
            if not options and len(parts) > 4:
                options = parts[4].strip("()")
            mounts[mount_point] = options

    issues = []
    for mp in ["/tmp", "/var/tmp", "/dev/shm"]:  # nosec B108  # NOSONAR - names the mount points to inspect
        opts = mounts.get(mp, "")
        if "noexec" not in opts:
            issues.append("{} missing noexec".format(mp))
        if "nosuid" not in opts:
            issues.append("{} missing nosuid".format(mp))
        if "nodev" not in opts:
            issues.append("{} missing nodev".format(mp))

    if issues:
        status = STATUS_INFO if is_docker else STATUS_WARNING
        return make_check(
            id="SYS-004",
            category="system",
            title="Missing mount options",
            status=status,
            what_it_checks="Mount options for /tmp, /var/tmp, /dev/shm.",
            risk="Executables can run from temporary directories."
            if not is_docker
            else "On Docker hosts, noexec may break some container operations.",
            command="mount",
            current_value="; ".join(issues),
            recommended_value="Add noexec,nosuid,nodev to mount options",
            details=issues,
        )

    return make_check(
        id="SYS-004",
        category="system",
        title="Temporary mounts hardened",
        status=STATUS_PASS,
        what_it_checks="Mount options for /tmp, /var/tmp, /dev/shm.",
        risk="Temporary directories are properly restricted.",
        command="mount",
        current_value="/tmp, /var/tmp, /dev/shm have noexec,nosuid,nodev",  # nosec B108
        recommended_value="Keep these mount options",
        details=["All temporary mounts have noexec,nosuid,nodev"],
    )


def _check_core_dumps(runner=None) -> dict:
    """Check core dump settings: fs.suid_dumpable, kernel.core_pattern, systemd coredump limits."""
    if runner is None:
        runner = run_cmd

    issues = []

    # Check fs.suid_dumpable
    suid_result = runner(["sysctl", "fs.suid_dumpable"], timeout=10.0)
    if suid_result.returncode != 0:
        issues.append("fs.suid_dumpable check failed: " + suid_result.stderr.strip())
    else:
        value = suid_result.stdout.strip().split("=")[-1].strip()
        if value != "0":
            issues.append("fs.suid_dumpable={}".format(value))

    # Check kernel.core_pattern
    core_pattern_result = runner(["sysctl", "kernel.core_pattern"], timeout=10.0)
    if core_pattern_result.returncode != 0:
        issues.append("kernel.core_pattern check failed: " + core_pattern_result.stderr.strip())
    else:
        pattern = core_pattern_result.stdout.strip().split("=")[-1].strip()
        # Check if it's a pipe to systemd-coredump or similar
        if pattern and not pattern.startswith("|") and pattern != "core":
            issues.append("kernel.core_pattern={}".format(pattern))

    # Check systemd coredump limits
    coredump_result = runner(
        ["systemctl", "show", "systemd-coredump", "--property=MemoryMax", "--property=TasksMax"], timeout=10.0
    )
    if coredump_result.returncode == 0:
        mem_max = ""
        tasks_max = ""
        for line in coredump_result.stdout.strip().splitlines():
            if line.startswith("MemoryMax="):
                mem_max = line.split("=", 1)[1]
            elif line.startswith("TasksMax="):
                tasks_max = line.split("=", 1)[1]
        if mem_max and mem_max != "infinity" and mem_max != "0":
            issues.append("systemd-coredump MemoryMax={}".format(mem_max))
        if tasks_max and tasks_max != "infinity" and tasks_max != "0":
            issues.append("systemd-coredump TasksMax={}".format(tasks_max))

    if issues:
        return make_check(
            id="SYS-005",
            category="system",
            title="Core dump settings not optimal",
            status=STATUS_WARNING,
            what_it_checks="Core dump settings: fs.suid_dumpable, kernel.core_pattern, systemd coredump limits.",
            risk="Core dumps may leak sensitive data or consume excessive resources.",
            command="sysctl fs.suid_dumpable kernel.core_pattern",
            current_value="; ".join(issues),
            recommended_value="Set fs.suid_dumpable=0, configure kernel.core_pattern to pipe to systemd-coredump",
            details=issues,
        )

    return make_check(
        id="SYS-005",
        category="system",
        title="Core dump settings optimal",
        status=STATUS_PASS,
        what_it_checks="Core dump settings: fs.suid_dumpable, kernel.core_pattern, systemd coredump limits.",
        risk="Core dumps are properly configured.",
        command="sysctl fs.suid_dumpable kernel.core_pattern",
        current_value="fs.suid_dumpable=0, core_pattern configured",
        recommended_value="Keep current settings",
        details=["Core dump settings are optimal"],
    )


def _check_time_sync(runner=None) -> dict:
    """Check time synchronization via timedatectl, chrony, or systemd-timesyncd."""
    if runner is None:
        runner = run_cmd

    # Try timedatectl first
    timedate_result = runner(["timedatectl", "show", "--property=NTPSynchronized", "--property=Timezone"], timeout=10.0)
    if timedate_result.returncode == 0:
        ntp_synced = ""
        for line in timedate_result.stdout.strip().splitlines():
            if line.startswith("NTPSynchronized="):
                ntp_synced = line.split("=", 1)[1]

        if ntp_synced == "yes":
            return make_check(
                id="SYS-006",
                category="system",
                title="Time synchronized via NTP",
                status=STATUS_PASS,
                what_it_checks="Time synchronization status.",
                risk="System clock is synchronized.",
                command="timedatectl show",
                current_value="NTPSynchronized=yes",
                recommended_value="Keep NTP synchronization active",
                details=["Time is synchronized via NTP"],
            )
        else:
            return make_check(
                id="SYS-006",
                category="system",
                title="Time not synchronized",
                status=STATUS_WARNING,
                what_it_checks="Time synchronization status.",
                risk="System clock may drift, affecting logs and security certificates.",
                command="timedatectl show",
                current_value="NTPSynchronized={}".format(ntp_synced),
                recommended_value="Enable NTP: timedatectl set-ntp true",
                details=["NTP is not synchronized"],
            )

    # Try chrony
    chrony_result = runner(["chronyc", "tracking"], timeout=10.0)
    if chrony_result.returncode == 0:
        return make_check(
            id="SYS-006",
            category="system",
            title="Time synchronized via chrony",
            status=STATUS_PASS,
            what_it_checks="Time synchronization status.",
            risk="System clock is synchronized via chrony.",
            command="chronyc tracking",
            current_value="chrony is active",
            recommended_value="Keep chrony running",
            details=["Time is synchronized via chrony"],
        )

    # Try systemd-timesyncd
    timesyncd_result = runner(["systemctl", "is-active", "systemd-timesyncd"], timeout=10.0)
    if timesyncd_result.returncode == 0 and timesyncd_result.stdout.strip() == "active":
        return make_check(
            id="SYS-006",
            category="system",
            title="Time synchronized via systemd-timesyncd",
            status=STATUS_PASS,
            what_it_checks="Time synchronization status.",
            risk="System clock is synchronized via systemd-timesyncd.",
            command="systemctl is-active systemd-timesyncd",
            current_value="systemd-timesyncd is active",
            recommended_value="Keep systemd-timesyncd running",
            details=["Time is synchronized via systemd-timesyncd"],
        )

    return make_check(
        id="SYS-006",
        category="system",
        title="No time synchronization found",
        status=STATUS_WARNING,
        what_it_checks="Time synchronization status.",
        risk="System clock may drift, affecting logs and security certificates.",
        command="timedatectl show",
        current_value="No NTP service found",
        recommended_value="Install and enable an NTP client",
        details=["No time synchronization service detected"],
    )


def _check_apparmor_selinux(runner=None) -> dict:
    """Check AppArmor or SELinux enforcing state."""
    if runner is None:
        runner = run_cmd

    detect_environment()

    # Check AppArmor
    apparmor_result = runner(["aa-status"], timeout=10.0)
    if apparmor_result.returncode == 0:
        if "enabled" in apparmor_result.stdout:
            return make_check(
                id="SYS-007",
                category="system",
                title="AppArmor enforcing",
                status=STATUS_PASS,
                what_it_checks="AppArmor or SELinux enforcing state.",
                risk="AppArmor is enforcing, providing mandatory access control.",
                command="aa-status",
                current_value="AppArmor is enforcing",
                recommended_value="Keep AppArmor enforcing",
                details=["AppArmor is active and enforcing"],
            )
        else:
            return make_check(
                id="SYS-007",
                category="system",
                title="AppArmor not enforcing",
                status=STATUS_WARNING,
                what_it_checks="AppArmor or SELinux enforcing state.",
                risk="AppArmor is not enforcing, reducing access control.",
                command="aa-status",
                current_value=apparmor_result.stdout.strip(),
                recommended_value="Enable AppArmor enforcing mode",
                details=["AppArmor is not enforcing"],
            )

    # Check SELinux
    selinux_result = runner(["getenforce"], timeout=10.0)
    if selinux_result.returncode == 0:
        mode = selinux_result.stdout.strip()
        if mode == "Enforcing":
            return make_check(
                id="SYS-007",
                category="system",
                title="SELinux enforcing",
                status=STATUS_PASS,
                what_it_checks="AppArmor or SELinux enforcing state.",
                risk="SELinux is enforcing, providing mandatory access control.",
                command="getenforce",
                current_value="SELinux is Enforcing",
                recommended_value="Keep SELinux enforcing",
                details=["SELinux is active and enforcing"],
            )
        elif mode == "Permissive":
            return make_check(
                id="SYS-007",
                category="system",
                title="SELinux permissive",
                status=STATUS_WARNING,
                what_it_checks="AppArmor or SELinux enforcing state.",
                risk="SELinux is permissive, not enforcing access control.",
                command="getenforce",
                current_value="SELinux is Permissive",
                recommended_value="Switch SELinux to enforcing mode",
                details=["SELinux is in permissive mode"],
            )
        else:
            return make_check(
                id="SYS-007",
                category="system",
                title="SELinux disabled",
                status=STATUS_WARNING,
                what_it_checks="AppArmor or SELinux enforcing state.",
                risk="SELinux is disabled, reducing access control.",
                command="getenforce",
                current_value="SELinux is {}".format(mode),
                recommended_value="Enable SELinux",
                details=["SELinux is disabled"],
            )

    return make_check(
        id="SYS-007",
        category="system",
        title="No MAC system found",
        status=STATUS_WARNING,
        what_it_checks="AppArmor or SELinux enforcing state.",
        risk="No mandatory access control system is active.",
        command="aa-status",
        current_value="Neither AppArmor nor SELinux is active",
        recommended_value="Install and enable AppArmor or SELinux",
        details=["No MAC system detected"],
    )


def run_checks() -> List[dict]:
    """Run all system checks."""
    env = detect_environment()
    checks = [
        _check_auditd(),
        _check_unattended_upgrades(),
        _check_reboot_required(),
        _check_noexec_tmp(env=env),
        _check_core_dumps(),
        _check_time_sync(),
        _check_apparmor_selinux(),
    ]
    return checks
