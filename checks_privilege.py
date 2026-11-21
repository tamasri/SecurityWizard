"""SecurityWizard – Module 4: Privilege Escalation & Filesystem Integrity Scanner."""

import os
import stat
import glob
import logging
import traceback

from common import (
    run_cmd,
    read_text,
    is_root,
    make_check,
    skipped_check,
    STATUS_PASS,
    STATUS_WARNING,
    STATUS_CRITICAL,
    STATUS_INFO,
    STATUS_SKIPPED,
)
from config import get_config

CATEGORY = "privilege"
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PRV-001  SUID/SGID binary hunter vs known-safe baseline
# ---------------------------------------------------------------------------
def build_find_cmd(paths):
    """Build the correct `find` argv for SUID/SGID hunting.

    All paths come first, then -xdev, then prune exclusions, then the
    -perm /6000 -type f expression.  This avoids the classic
    "paths must precede expression" error.
    """
    cmd = ["find"]
    cmd.extend(paths)
    cmd.append("-xdev")
    exclusions = [
        "/proc", "/sys",
        "/var/lib/docker", "/var/lib/containerd",
        "/snap", "/var/snap", "/var/lib/snapd",
    ]
    for ex in exclusions:
        cmd.extend(["-path", ex, "-prune", "-o"])
    cmd.append("-perm")
    cmd.append("/6000")
    cmd.append("-type")
    cmd.append("f")
    return cmd


def _check_suid_sgid():
    """Scan critical paths for SUID/SGID binaries and compare against a whitelist."""
    safe_baseline = {
        "passwd", "sudo", "su", "mount", "umount", "ping", "ping6", "chsh",
        "chfn", "gpasswd", "newgrp", "fusermount", "fusermount3", "pkexec",
        "ssh-agent", "unix_chkpwd", "crontab", "expiry", "chage", "wall",
        "write", "dotlockfile", "mount.nfs", "Xorg.wrap",
        "mail", "mailx", "mailq", "mailstats",
    }
    risky_gtfo = {
        "vim", "vi", "find", "bash", "sh", "dash", "python", "python2",
        "python3", "perl", "ruby", "nmap", "docker", "awk", "gawk", "env",
        "less", "more", "nano", "cp", "tar", "zip", "php", "node", "nodejs",
        "python3.10", "python3.11", "python3.9", "python3.8", "python3.7",
        "python3.6", "python3.5", "python3.4", "python3.3", "python3.2",
        "python3.1", "python3.0", "python2.7", "python2.6", "python2.5",
    }
    scan_paths = [
        "/usr/bin", "/usr/sbin", "/bin", "/sbin",
        "/usr/local/bin", "/usr/local/sbin",
        "/usr/lib", "/usr/libexec", "/opt",
    ]
    existing = [p for p in scan_paths if os.path.isdir(p)]
    if not existing:
        return make_check(
            "PRV-001", CATEGORY,
            "SUID/SGID binary hunter vs known-safe baseline",
            STATUS_SKIPPED,
            "Scans critical paths for binaries with SUID/SGID bits and compares them against a known-safe baseline whitelist.",
            "An attacker who can write to or replace a SUID/SGID binary can escalate to root.",
            "find <paths> -xdev -perm /6000 -type f",
            "No scan paths found",
            "Only known-safe SUID/SGID binaries present",
        )

    cmd_args = build_find_cmd(existing)
    rc, out, err = run_cmd(cmd_args, timeout=120)
    if rc != 0:
        reason = ("find failed: " + err.strip()) if err.strip() else "find failed (rc=%d)" % rc
        logger.warning("PRV-001: %s", reason)
        return make_check(
            "PRV-001", CATEGORY,
            "SUID/SGID binary hunter vs known-safe baseline",
            STATUS_SKIPPED,
            "Scans critical paths for binaries with SUID/SGID bits and compares them against a known-safe baseline whitelist.",
            "An attacker who can write to or replace a SUID/SGID binary can escalate to root.",
            " ".join(cmd_args),
            reason,
            "Only known-safe SUID/SGID binaries present",
        )

    binaries = [line.strip() for line in out.splitlines() if line.strip()]

    # Build the set of dpkg-owned files from /var/lib/dpkg/info/*.list
    dpkg_owned = set()
    for list_file in glob.glob("/var/lib/dpkg/info/*.list"):
        for line in read_text(list_file).splitlines():
            line = line.strip()
            if line:
                dpkg_owned.add(line)

    details = []
    risky_found = []
    unknown_found = []
    for binary in binaries:
        name = os.path.basename(binary)
        if get_config().allowed_suid(binary):
            details.append("ALLOWED: " + binary)
            continue
        if name in risky_gtfo:
            details.append("RISKY: " + binary)
            risky_found.append(binary)
        elif binary in dpkg_owned:
            details.append("SAFE (dpkg): " + binary)
        elif name in safe_baseline:
            details.append("SAFE: " + binary)
        else:
            details.append("UNKNOWN: " + binary)
            unknown_found.append(binary)

    if risky_found:
        status = STATUS_CRITICAL
        current_value = "Found " + str(len(risky_found)) + " risky SUID/SGID binaries: " + ", ".join(risky_found)
    elif unknown_found:
        status = STATUS_WARNING
        current_value = "Found " + str(len(unknown_found)) + " unknown SUID/SGID binaries: " + ", ".join(unknown_found)
    else:
        status = STATUS_PASS
        current_value = "All " + str(len(binaries)) + " SUID/SGID binaries are in the safe baseline or dpkg-owned"

    return make_check(
        "PRV-001", CATEGORY,
        "SUID/SGID binary hunter vs known-safe baseline",
        status,
        "Scans critical paths for binaries with SUID/SGID bits and compares them against a known-safe baseline whitelist.",
        "An attacker who can write to or replace a SUID/SGID binary can escalate to root.",
        " ".join(cmd_args),
        current_value,
        "Only known-safe SUID/SGID binaries present",
        details,
        remediation_id=None,
        manual_command="find /usr/bin /usr/sbin /bin /sbin /usr/local/bin /usr/local/sbin /usr/lib /usr/libexec /opt -xdev -perm /6000 -type f 2>/dev/null",
    )


# ---------------------------------------------------------------------------
# PRV-002  /etc/passwd ownership and permissions
# ---------------------------------------------------------------------------
def _check_passwd():
    """Verify /etc/passwd is 0644 root:root."""
    path = "/etc/passwd"
    if not os.path.isfile(path):
        return make_check(
            "PRV-002", CATEGORY,
            "/etc/passwd ownership and permissions (0644 root:root)",
            STATUS_SKIPPED,
            "Checks that /etc/passwd is owned by root:root and has permissions 0644.",
            "If /etc/passwd is world-writable, an attacker can add a new user with UID 0 and gain root access.",
            "stat -c '%a %U:%G' /etc/passwd",
            "File not found",
            "0644 root:root",
        )
    st = os.stat(path)
    mode = stat.S_IMODE(st.st_mode)
    mode_oct = oct(mode)[2:].zfill(3)
    uid = st.st_uid
    gid = st.st_gid
    owner = "root" if uid == 0 else str(uid)
    group = "root" if gid == 0 else str(gid)
    current_value = "0" + mode_oct + " " + owner + ":" + group
    if mode == 0o644 and uid == 0 and gid == 0:
        status = STATUS_PASS
    else:
        status = STATUS_CRITICAL
    return make_check(
        "PRV-002", CATEGORY,
        "/etc/passwd ownership and permissions (0644 root:root)",
        status,
        "Checks that /etc/passwd is owned by root:root and has permissions 0644.",
        "If /etc/passwd is world-writable, an attacker can add a new user with UID 0 and gain root access.",
        "stat -c '%a %U:%G' /etc/passwd",
        current_value,
        "0644 root:root",
        remediation_id="fix_perm_passwd",
        manual_command="chown root:root /etc/passwd && chmod 0644 /etc/passwd",
    )


# ---------------------------------------------------------------------------
# PRV-003  /etc/shadow permissions
# ---------------------------------------------------------------------------
def _check_shadow():
    """Verify /etc/shadow is 0640 or 0000, owned by root:shadow or root:root."""
    path = "/etc/shadow"
    if not os.path.isfile(path):
        return make_check(
            "PRV-003", CATEGORY,
            "/etc/shadow permissions (0640 or 0000)",
            STATUS_SKIPPED,
            "Checks that /etc/shadow has permissions 0640 or 0000 and is owned by root:shadow or root:root.",
            "If /etc/shadow is readable by non-root users, an attacker can read password hashes and crack them offline.",
            "stat -c '%a %U:%G' /etc/shadow",
            "File not found",
            "0640 root:shadow or 0000 root:root",
        )
    st = os.stat(path)
    mode = stat.S_IMODE(st.st_mode)
    mode_oct = oct(mode)[2:].zfill(3)
    uid = st.st_uid
    gid = st.st_gid
    owner = "root" if uid == 0 else str(uid)
    group = "shadow" if gid == 42 else ("root" if gid == 0 else str(gid))
    current_value = "0" + mode_oct + " " + owner + ":" + group
    if mode in (0o640, 0o000) and uid == 0 and gid in (0, 42):
        status = STATUS_PASS
    else:
        status = STATUS_CRITICAL
    return make_check(
        "PRV-003", CATEGORY,
        "/etc/shadow permissions (0640 or 0000)",
        status,
        "Checks that /etc/shadow has permissions 0640 or 0000 and is owned by root:shadow or root:root.",
        "If /etc/shadow is readable by non-root users, an attacker can read password hashes and crack them offline.",
        "stat -c '%a %U:%G' /etc/shadow",
        current_value,
        "0640 root:shadow or 0000 root:root",
        remediation_id="fix_perm_shadow",
        manual_command="chown root:shadow /etc/shadow && chmod 0640 /etc/shadow",
    )


# ---------------------------------------------------------------------------
# PRV-004  /etc/group permissions
# ---------------------------------------------------------------------------
def _check_group():
    """Verify /etc/group is 0644 root:root."""
    path = "/etc/group"
    if not os.path.isfile(path):
        return make_check(
            "PRV-004", CATEGORY,
            "/etc/group permissions (0644)",
            STATUS_SKIPPED,
            "Checks that /etc/group is owned by root:root and has permissions 0644.",
            "If /etc/group is world-writable, an attacker can add themselves to privileged groups like sudo or docker.",
            "stat -c '%a %U:%G' /etc/group",
            "File not found",
            "0644 root:root",
        )
    st = os.stat(path)
    mode = stat.S_IMODE(st.st_mode)
    mode_oct = oct(mode)[2:].zfill(3)
    uid = st.st_uid
    gid = st.st_gid
    owner = "root" if uid == 0 else str(uid)
    group = "root" if gid == 0 else str(gid)
    current_value = "0" + mode_oct + " " + owner + ":" + group
    if mode == 0o644 and uid == 0 and gid == 0:
        status = STATUS_PASS
    else:
        status = STATUS_CRITICAL
    return make_check(
        "PRV-004", CATEGORY,
        "/etc/group permissions (0644)",
        status,
        "Checks that /etc/group is owned by root:root and has permissions 0644.",
        "If /etc/group is world-writable, an attacker can add themselves to privileged groups like sudo or docker.",
        "stat -c '%a %U:%G' /etc/group",
        current_value,
        "0644 root:root",
        remediation_id="fix_perm_group",
        manual_command="chown root:root /etc/group && chmod 0644 /etc/group",
    )


# ---------------------------------------------------------------------------
# PRV-005  /etc/sudoers permissions
# ---------------------------------------------------------------------------
def _check_sudoers():
    """Verify /etc/sudoers is 0440 root:root."""
    path = "/etc/sudoers"
    if not os.path.isfile(path):
        return make_check(
            "PRV-005", CATEGORY,
            "/etc/sudoers permissions (0440)",
            STATUS_SKIPPED,
            "Checks that /etc/sudoers is owned by root:root and has permissions 0440.",
            "If /etc/sudoers is world-writable, an attacker can grant themselves full sudo access without a password.",
            "stat -c '%a %U:%G' /etc/sudoers",
            "File not found",
            "0440 root:root",
        )
    st = os.stat(path)
    mode = stat.S_IMODE(st.st_mode)
    mode_oct = oct(mode)[2:].zfill(3)
    uid = st.st_uid
    gid = st.st_gid
    owner = "root" if uid == 0 else str(uid)
    group = "root" if gid == 0 else str(gid)
    current_value = "0" + mode_oct + " " + owner + ":" + group
    if mode == 0o440 and uid == 0 and gid == 0:
        status = STATUS_PASS
    else:
        status = STATUS_CRITICAL
    return make_check(
        "PRV-005", CATEGORY,
        "/etc/sudoers permissions (0440)",
        status,
        "Checks that /etc/sudoers is owned by root:root and has permissions 0440.",
        "If /etc/sudoers is world-writable, an attacker can grant themselves full sudo access without a password.",
        "stat -c '%a %U:%G' /etc/sudoers",
        current_value,
        "0440 root:root",
        remediation_id="fix_perm_sudoers",
        manual_command="chown root:root /etc/sudoers && chmod 0440 /etc/sudoers",
    )


# ---------------------------------------------------------------------------
# PRV-006  /etc/ssh/sshd_config permissions
# ---------------------------------------------------------------------------
def _evaluate_sshd_config_permissions(mode: int, uid: int) -> str:
    """Evaluate sshd_config permissions and return a status string.

    sshd_config is the distro default at 0644 and is not secret.
    Returns STATUS_PASS for 0640/0600, STATUS_INFO for 0644, and
    STATUS_CRITICAL when group/world writable, not owned by root,
    or when the file contains secrets (private key blocks or
    password-like values).
    """
    # Critical: group or world writable
    if mode & 0o020:
        return STATUS_CRITICAL
    # Critical: not owned by root
    if uid != 0:
        return STATUS_CRITICAL
    # Check for secrets in the file
    path = "/etc/ssh/sshd_config"
    if os.path.isfile(path):
        content = read_text(path)
        if "PRIVATE KEY" in content or "RSA PRIVATE KEY" in content or "OPENSSH PRIVATE KEY" in content:
            return STATUS_CRITICAL
        if "PasswordAuthentication" in content and "yes" in content.split("PasswordAuthentication")[-1].split("\n")[0].lower():
            return STATUS_CRITICAL
    # 0644 is the distro default: INFO
    if mode == 0o644:
        return STATUS_INFO
    # 0640 or 0600 owned by root: PASS
    if mode in (0o640, 0o600):
        return STATUS_PASS
    # Other modes owned by root and not group/world writable: PASS
    return STATUS_PASS


def _check_sshd_config():
    """Verify /etc/ssh/sshd_config permissions and ownership."""
    path = "/etc/ssh/sshd_config"
    if not os.path.isfile(path):
        return make_check(
            "PRV-006", CATEGORY,
            "/etc/ssh/sshd_config permissions",
            STATUS_SKIPPED,
            "Checks that /etc/ssh/sshd_config is owned by root and has safe permissions.",
            "If sshd_config is world-writable, an attacker can change SSH settings to allow password login or open a backdoor.",
            "stat -c '%a %U:%G' /etc/ssh/sshd_config",
            "File not found",
            "0644 root:root (distro default)",
        )
    st = os.stat(path)
    mode = stat.S_IMODE(st.st_mode)
    mode_oct = oct(mode)[2:].zfill(3)
    uid = st.st_uid
    gid = st.st_gid
    owner = "root" if uid == 0 else str(uid)
    group = "root" if gid == 0 else str(gid)
    current_value = "0" + mode_oct + " " + owner + ":" + group
    status = _evaluate_sshd_config_permissions(mode, uid)
    return make_check(
        "PRV-006", CATEGORY,
        "/etc/ssh/sshd_config permissions",
        status,
        "Checks that /etc/ssh/sshd_config is owned by root and has safe permissions. 0644 is the distro default and is not secret.",
        "If sshd_config is world-writable, an attacker can change SSH settings to allow password login or open a backdoor.",
        "stat -c '%a %U:%G' /etc/ssh/sshd_config",
        current_value,
        "0644 root:root (distro default)",
        remediation_id="fix_perm_sshd_config",
        manual_command="chown root:root /etc/ssh/sshd_config && chmod 0644 /etc/ssh/sshd_config",
    )


# ---------------------------------------------------------------------------
# PRV-007  Cron jobs inventory
# ---------------------------------------------------------------------------
def _check_cron():
    """List system and user cron jobs, flag world-writable cron files."""
    details = []
    world_writable = []
    # /etc/crontab
    etc_crontab = "/etc/crontab"
    if os.path.isfile(etc_crontab):
        st = os.stat(etc_crontab)
        mode = stat.S_IMODE(st.st_mode)
        details.append("/etc/crontab (0" + oct(mode)[2:].zfill(3) + ")")
        if mode & 0o002:
            world_writable.append(etc_crontab)
    # /etc/cron.d/*
    for f in sorted(glob.glob("/etc/cron.d/*")):
        if os.path.isfile(f):
            st = os.stat(f)
            mode = stat.S_IMODE(st.st_mode)
            details.append(f + " (0" + oct(mode)[2:].zfill(3) + ")")
            if mode & 0o002:
                world_writable.append(f)
    # /var/spool/cron/crontabs/*
    for f in sorted(glob.glob("/var/spool/cron/crontabs/*")):
        if os.path.isfile(f):
            st = os.stat(f)
            mode = stat.S_IMODE(st.st_mode)
            details.append(f + " (0" + oct(mode)[2:].zfill(3) + ")")
            if mode & 0o002:
                world_writable.append(f)
    if world_writable:
        status = STATUS_WARNING
        current_value = "World-writable cron files: " + ", ".join(world_writable)
    elif details:
        status = STATUS_INFO
        current_value = str(len(details)) + " cron entries found"
    else:
        status = STATUS_INFO
        current_value = "No cron jobs found"
    return make_check(
        "PRV-007", CATEGORY,
        "Cron jobs inventory (system and user crontabs)",
        status,
        "Lists all system and user cron jobs and flags any cron files that are world-writable.",
        "A world-writable cron file allows any user to add a malicious cron job that runs as root.",
        "ls -l /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/*",
        current_value,
        "No world-writable cron files",
        details,
        remediation_id=None,
        manual_command="find /etc/crontab /etc/cron.d /var/spool/cron/crontabs -type f -perm -o+w -ls 2>/dev/null",
    )


# ---------------------------------------------------------------------------
# PRV-008  Dangerous NOPASSWD: ALL entries in sudoers
# ---------------------------------------------------------------------------
def _check_nopasswd():
    """Grep /etc/sudoers and /etc/sudoers.d/* for NOPASSWD: ALL."""
    details = []
    dangerous = []
    sudoers_path = "/etc/sudoers"
    if os.path.isfile(sudoers_path):
        content = read_text(sudoers_path)
        for line in content.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "NOPASSWD" in stripped and "ALL" in stripped:
                details.append(sudoers_path + ": " + stripped)
                dangerous.append(sudoers_path)
    for f in sorted(glob.glob("/etc/sudoers.d/*")):
        if os.path.isfile(f):
            content = read_text(f)
            for line in content.splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("#") and "NOPASSWD" in stripped and "ALL" in stripped:
                    details.append(f + ": " + stripped)
                    dangerous.append(f)
    if dangerous:
        status = STATUS_CRITICAL
        current_value = "NOPASSWD: ALL found in: " + ", ".join(sorted(set(dangerous)))
    else:
        status = STATUS_PASS
        current_value = "No NOPASSWD: ALL entries found"
    return make_check(
        "PRV-008", CATEGORY,
        "Dangerous NOPASSWD: ALL entries in sudoers",
        status,
        "Greps /etc/sudoers and /etc/sudoers.d/* for entries that allow any user to run any command as root without a password.",
        "A NOPASSWD: ALL entry lets any user run any command as root without entering a password, giving full root access.",
        "grep -r 'NOPASSWD.*ALL' /etc/sudoers /etc/sudoers.d/",
        current_value,
        "No NOPASSWD: ALL entries",
        details,
        remediation_id=None,
        manual_command="grep -r 'NOPASSWD.*ALL' /etc/sudoers /etc/sudoers.d/ 2>/dev/null",
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def run_checks():
    """Run all privilege-escalation checks and return a list of check dicts."""
    checks = []
    check_funcs = [
        _check_suid_sgid,
        _check_passwd,
        _check_shadow,
        _check_group,
        _check_sudoers,
        _check_sshd_config,
        _check_cron,
        _check_nopasswd,
    ]
    for func in check_funcs:
        try:
            checks.append(func())
        except Exception:
            checks.append(skipped_check(
                func.__name__.replace("_check_", "").upper(),
                CATEGORY,
                func.__doc__.strip() if func.__doc__ else func.__name__,
                "Unexpected error while running this check.",
                "The check itself failed, so the state of this setting is unknown.",
                func.__name__,
                "Exception: " + traceback.format_exc().strip(),
            ))
    return checks
