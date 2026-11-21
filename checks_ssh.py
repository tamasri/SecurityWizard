"""SSH daemon security & access hardening checks."""

import glob
import os

from common import (
    STATUS_CRITICAL,
    STATUS_INFO,
    STATUS_PASS,
    STATUS_WARNING,
    is_root,
    make_check,
    read_text,
    run_cmd,
    skipped_check,
)
from sshd_effective import evaluate_ssh_security, listening_ssh_ports

SUPPORTED = ["network", "ssh", "kernel", "privilege", "docker", "logs"]
CATEGORY = "ssh"

SSHD_CONFIG = "/etc/ssh/sshd_config"
SSHD_DROPIN_DIR = "/etc/ssh/sshd_config.d"


def _parse_sshd_config():
    """Parse sshd_config and drop-ins. Returns dict of first-seen values (lowercase keys)."""
    values = {}
    config_path = SSHD_CONFIG
    if not os.path.exists(config_path):
        return values
    lines = read_text(config_path).splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        key = parts[0].lower()
        if key == "include":
            pattern = parts[1]
            if pattern.startswith("/"):
                for f in glob.glob(pattern):
                    if os.path.isfile(f):
                        for dl in read_text(f).splitlines():
                            dl = dl.strip()
                            if not dl or dl.startswith("#"):
                                continue
                            dp = dl.split(None, 1)
                            if len(dp) < 2:
                                continue
                            dk = dp[0].lower()
                            if dk not in values:
                                values[dk] = dp[1].strip()
            continue
        if key not in values:
            values[key] = parts[1].strip()
    # Drop-in .conf files (first value wins, but Include already handled above if present)
    for f in sorted(glob.glob(os.path.join(SSHD_DROPIN_DIR, "*.conf"))):
        for dl in read_text(f).splitlines():
            dl = dl.strip()
            if not dl or dl.startswith("#"):
                continue
            dp = dl.split(None, 1)
            if len(dp) < 2:
                continue
            dk = dp[0].lower()
            if dk not in values:
                values[dk] = dp[1].strip()
    return values


def _effective_values():
    """Return effective sshd values. Uses sshd -T if root and available, else parsed config + defaults."""
    defaults = {
        "permitrootlogin": "prohibit-password",
        "passwordauthentication": "yes",
        "pubkeyauthentication": "yes",
        "maxauthtries": "6",
        "permitemptypasswords": "no",
        "x11forwarding": "yes",
    }
    if is_root():
        rc, out, _err = run_cmd(["sshd", "-T"])
        if rc == 0 and out.strip():
            eff = {}
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    eff[parts[0].lower()] = parts[1].strip()
            for k in defaults:
                if k in eff:
                    defaults[k] = eff[k]
            return defaults
    parsed = _parse_sshd_config()
    for k in defaults:
        if k in parsed:
            defaults[k] = parsed[k]
    return defaults


def _check_sshd_installed():
    if not os.path.exists(SSHD_CONFIG):
        return False
    return True


def _check_permit_root_login():
    if not _check_sshd_installed():
        return skipped_check(
            "SSH-001",
            CATEGORY,
            "PermitRootLogin (target: no or prohibit-password)",
            "Whether the sshd daemon allows direct root login via SSH.",
            "An attacker who guesses the root password gains immediate full control of the server.",
            "sshd -T | grep permitrootlogin",
            "sshd_config not found - sshd may not be installed",
            remediation_id="ssh_permit_root_login",
        )
    ports = listening_ssh_ports()
    if not ports:
        return skipped_check(
            "SSH-001",
            CATEGORY,
            "PermitRootLogin (target: no or prohibit-password)",
            "Whether the sshd daemon allows direct root login via SSH.",
            "An attacker who guesses the root password gains immediate full control of the server.",
            "sshd -T | grep permitrootlogin",
            "No SSH ports detected",
            remediation_id="ssh_permit_root_login",
        )
    details = []
    worst_status = STATUS_PASS
    for port in ports:
        result = evaluate_ssh_security(port=port)
        if result["status"] == "SKIPPED":
            return skipped_check(
                "SSH-001",
                CATEGORY,
                "PermitRootLogin (target: no or prohibit-password)",
                "Whether the sshd daemon allows direct root login via SSH.",
                "An attacker who guesses the root password gains immediate full control of the server.",
                "sshd -T | grep permitrootlogin",
                result["reason"],
                remediation_id="ssh_permit_root_login",
            )
        for finding in result["findings"]:
            if finding["check"] == "PermitRootLogin":
                val = finding["value"]
                if val == "yes":
                    status = STATUS_CRITICAL
                    worst_status = STATUS_CRITICAL
                elif val == "no":
                    status = STATUS_PASS
                else:
                    status = STATUS_PASS
                details.append(f"Port {port}: PermitRootLogin={val} ({status})")
    return make_check(
        "SSH-001",
        CATEGORY,
        "PermitRootLogin (target: no or prohibit-password)",
        worst_status,
        "Checks whether the SSH daemon permits direct login as the root user. "
        "The recommended setting is 'no' or 'prohibit-password' so that root can only log in with a key.",
        "If root login is allowed with a password, an attacker who brute-forces the root password "
        "immediately owns the entire server with no escalation step needed.",
        "sshd -T | grep permitrootlogin",
        current_value="; ".join(details) if details else "(no data)",
        recommended_value="no or prohibit-password",
        details=details,
        remediation_id="ssh_permit_root_login",
        manual_command="sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl reload sshd",
    )


def _check_password_auth():
    if not _check_sshd_installed():
        return skipped_check(
            "SSH-002",
            CATEGORY,
            "PasswordAuthentication (target: no)",
            "Whether SSH password authentication is enabled.",
            "With password auth on, attackers can brute-force passwords; keys are much harder to crack.",
            "sshd -T | grep passwordauthentication",
            "sshd_config not found - sshd may not be installed",
            remediation_id="ssh_password_auth",
        )
    ports = listening_ssh_ports()
    if not ports:
        return skipped_check(
            "SSH-002",
            CATEGORY,
            "PasswordAuthentication (target: no)",
            "Whether SSH password authentication is enabled.",
            "With password auth on, attackers can brute-force passwords; keys are much harder to crack.",
            "sshd -T | grep passwordauthentication",
            "No SSH ports detected",
            remediation_id="ssh_password_auth",
        )
    details = []
    worst_status = STATUS_PASS
    for port in ports:
        result = evaluate_ssh_security(port=port)
        if result["status"] == "SKIPPED":
            return skipped_check(
                "SSH-002",
                CATEGORY,
                "PasswordAuthentication (target: no)",
                "Whether SSH password authentication is enabled.",
                "With password auth on, attackers can brute-force passwords; keys are much harder to crack.",
                "sshd -T | grep passwordauthentication",
                result["reason"],
                remediation_id="ssh_password_auth",
            )
        for finding in result["findings"]:
            if finding["check"] == "PasswordAuthentication":
                val = finding["value"]
                if val == "no":
                    status = STATUS_PASS
                elif val == "yes":
                    status = STATUS_WARNING
                    worst_status = STATUS_WARNING
                else:
                    status = STATUS_INFO
                details.append(f"Port {port}: PasswordAuthentication={val} ({status})")
    return make_check(
        "SSH-002",
        CATEGORY,
        "PasswordAuthentication (target: no)",
        worst_status,
        "Checks whether SSH accepts password-based logins. Disabling it forces users to use public-key authentication.",
        "Password authentication exposes the server to brute-force and credential-stuffing attacks, "
        "and leaked passwords can be replayed on other systems.",
        "sshd -T | grep passwordauthentication",
        current_value="; ".join(details) if details else "(no data)",
        recommended_value="no",
        details=details,
        remediation_id="ssh_password_auth",
        manual_command="sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && systemctl reload sshd",
    )


def _check_pubkey_auth():
    if not _check_sshd_installed():
        return skipped_check(
            "SSH-003",
            CATEGORY,
            "PubkeyAuthentication (target: yes)",
            "Whether SSH public-key authentication is enabled.",
            "Without key auth, users must rely on passwords, which are easier to steal or guess.",
            "sshd -T | grep pubkeyauthentication",
            "sshd_config not found - sshd may not be installed",
            remediation_id="ssh_pubkey_auth",
        )
    ports = listening_ssh_ports()
    if not ports:
        return skipped_check(
            "SSH-003",
            CATEGORY,
            "PubkeyAuthentication (target: yes)",
            "Whether SSH public-key authentication is enabled.",
            "Without key auth, users must rely on passwords, which are easier to steal or guess.",
            "sshd -T | grep pubkeyauthentication",
            "No SSH ports detected",
            remediation_id="ssh_pubkey_auth",
        )
    details = []
    worst_status = STATUS_PASS
    for port in ports:
        result = evaluate_ssh_security(port=port)
        if result["status"] == "SKIPPED":
            return skipped_check(
                "SSH-003",
                CATEGORY,
                "PubkeyAuthentication (target: yes)",
                "Whether SSH public-key authentication is enabled.",
                "Without key auth, users must rely on passwords, which are easier to steal or guess.",
                "sshd -T | grep pubkeyauthentication",
                result["reason"],
                remediation_id="ssh_pubkey_auth",
            )
        for finding in result["findings"]:
            if finding["check"] == "PubkeyAuthentication":
                val = finding["value"]
                if val == "yes":
                    status = STATUS_PASS
                elif val == "no":
                    status = STATUS_CRITICAL
                    worst_status = STATUS_CRITICAL
                else:
                    status = STATUS_INFO
                details.append(f"Port {port}: PubkeyAuthentication={val} ({status})")
    return make_check(
        "SSH-003",
        CATEGORY,
        "PubkeyAuthentication (target: yes)",
        worst_status,
        "Checks whether SSH accepts public-key logins. This is the preferred authentication method for servers.",
        "If key authentication is disabled, every login depends on a password, making the server "
        "vulnerable to credential attacks and removing the strongest SSH protection.",
        "sshd -T | grep pubkeyauthentication",
        current_value="; ".join(details) if details else "(no data)",
        recommended_value="yes",
        details=details,
        remediation_id="ssh_pubkey_auth",
        manual_command="sed -i 's/^#\\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config && systemctl reload sshd",
    )


def _check_max_auth_tries():
    if not _check_sshd_installed():
        return skipped_check(
            "SSH-004",
            CATEGORY,
            "MaxAuthTries (target: <= 3)",
            "The maximum number of authentication attempts per SSH connection.",
            "A high limit lets attackers try many passwords or keys before being cut off, increasing brute-force success.",
            "sshd -T | grep maxauthtries",
            "sshd_config not found - sshd may not be installed",
            remediation_id="ssh_max_auth_tries",
        )
    ports = listening_ssh_ports()
    if not ports:
        return skipped_check(
            "SSH-004",
            CATEGORY,
            "MaxAuthTries (target: <= 3)",
            "The maximum number of authentication attempts per SSH connection.",
            "A high limit lets attackers try many passwords or keys before being cut off, increasing brute-force success.",
            "sshd -T | grep maxauthtries",
            "No SSH ports detected",
            remediation_id="ssh_max_auth_tries",
        )
    details = []
    worst_status = STATUS_PASS
    for port in ports:
        result = evaluate_ssh_security(port=port)
        if result["status"] == "SKIPPED":
            return skipped_check(
                "SSH-004",
                CATEGORY,
                "MaxAuthTries (target: <= 3)",
                "The maximum number of authentication attempts per SSH connection.",
                "A high limit lets attackers try many passwords or keys before being cut off, increasing brute-force success.",
                "sshd -T | grep maxauthtries",
                result["reason"],
                remediation_id="ssh_max_auth_tries",
            )
        for finding in result["findings"]:
            if finding["check"] == "MaxAuthTries":
                val = finding["value"]
                try:
                    val_int = int(val)
                    if val_int <= 3:
                        status = STATUS_PASS
                    elif val_int <= 5:
                        status = STATUS_WARNING
                        worst_status = STATUS_WARNING
                    else:
                        status = STATUS_CRITICAL
                        worst_status = STATUS_CRITICAL
                except ValueError:
                    status = STATUS_INFO
                details.append(f"Port {port}: MaxAuthTries={val} ({status})")
    return make_check(
        "SSH-004",
        CATEGORY,
        "MaxAuthTries (target: <= 3)",
        worst_status,
        "Checks the maximum number of authentication attempts allowed on a single SSH connection. "
        "Lowering this reduces the window for brute-force attacks.",
        "With a high MaxAuthTries, an attacker can try many passwords or keys on one connection, "
        "making brute-force attacks much faster and more likely to succeed.",
        "sshd -T | grep maxauthtries",
        current_value="; ".join(details) if details else "(no data)",
        recommended_value="3",
        details=details,
        remediation_id="ssh_max_auth_tries",
        manual_command="sed -i 's/^#\\?MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config && systemctl reload sshd",
    )


def _check_empty_passwords():
    if not _check_sshd_installed():
        return skipped_check(
            "SSH-005",
            CATEGORY,
            "PermitEmptyPasswords (target: no)",
            "Whether SSH allows login with an empty (blank) password.",
            "If empty passwords are permitted, any account with no password set can be accessed by anyone over SSH.",
            "sshd -T | grep permitemptypasswords",
            "sshd_config not found - sshd may not be installed",
            remediation_id="ssh_empty_passwords",
        )
    ports = listening_ssh_ports()
    if not ports:
        return skipped_check(
            "SSH-005",
            CATEGORY,
            "PermitEmptyPasswords (target: no)",
            "Whether SSH allows login with an empty (blank) password.",
            "If empty passwords are permitted, any account with no password set can be accessed by anyone over SSH.",
            "sshd -T | grep permitemptypasswords",
            "No SSH ports detected",
            remediation_id="ssh_empty_passwords",
        )
    details = []
    worst_status = STATUS_PASS
    for port in ports:
        result = evaluate_ssh_security(port=port)
        if result["status"] == "SKIPPED":
            return skipped_check(
                "SSH-005",
                CATEGORY,
                "PermitEmptyPasswords (target: no)",
                "Whether SSH allows login with an empty (blank) password.",
                "If empty passwords are permitted, any account with no password set can be accessed by anyone over SSH.",
                "sshd -T | grep permitemptypasswords",
                result["reason"],
                remediation_id="ssh_empty_passwords",
            )
        for finding in result["findings"]:
            if finding["check"] == "PermitEmptyPasswords":
                val = finding["value"]
                if val == "no":
                    status = STATUS_PASS
                elif val == "yes":
                    status = STATUS_CRITICAL
                    worst_status = STATUS_CRITICAL
                else:
                    status = STATUS_INFO
                details.append(f"Port {port}: PermitEmptyPasswords={val} ({status})")
    return make_check(
        "SSH-005",
        CATEGORY,
        "PermitEmptyPasswords (target: no)",
        worst_status,
        "Checks whether SSH permits logins with an empty password. This should always be disabled.",
        "If empty passwords are allowed, any user account without a password (e.g., a newly created service account) "
        "can be logged into without any credential, giving an attacker a free entry point.",
        "sshd -T | grep permitemptypasswords",
        current_value="; ".join(details) if details else "(no data)",
        recommended_value="no",
        details=details,
        remediation_id="ssh_empty_passwords",
        manual_command="sed -i 's/^#\\?PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config && systemctl reload sshd",
    )


def _check_x11_forwarding():
    if not _check_sshd_installed():
        return skipped_check(
            "SSH-006",
            CATEGORY,
            "X11Forwarding (target: no)",
            "Whether SSH X11 forwarding is enabled.",
            "X11 forwarding opens a channel for graphical apps; if left on, a compromised X server can leak input or screen data.",
            "sshd -T | grep x11forwarding",
            "sshd_config not found - sshd may not be installed",
            remediation_id="ssh_x11_forwarding",
        )
    ports = listening_ssh_ports()
    if not ports:
        return skipped_check(
            "SSH-006",
            CATEGORY,
            "X11Forwarding (target: no)",
            "Whether SSH X11 forwarding is enabled.",
            "X11 forwarding opens a channel for graphical apps; if left on, a compromised X server can leak input or screen data.",
            "sshd -T | grep x11forwarding",
            "No SSH ports detected",
            remediation_id="ssh_x11_forwarding",
        )
    details = []
    worst_status = STATUS_PASS
    for port in ports:
        result = evaluate_ssh_security(port=port)
        if result["status"] == "SKIPPED":
            return skipped_check(
                "SSH-006",
                CATEGORY,
                "X11Forwarding (target: no)",
                "Whether SSH X11 forwarding is enabled.",
                "X11 forwarding opens a channel for graphical apps; if left on, a compromised X server can leak input or screen data.",
                "sshd -T | grep x11forwarding",
                result["reason"],
                remediation_id="ssh_x11_forwarding",
            )
        for finding in result["findings"]:
            if finding["check"] == "X11Forwarding":
                val = finding["value"]
                if val == "no":
                    status = STATUS_PASS
                elif val == "yes":
                    status = STATUS_WARNING
                    worst_status = STATUS_WARNING
                else:
                    status = STATUS_INFO
                details.append(f"Port {port}: X11Forwarding={val} ({status})")
    return make_check(
        "SSH-006",
        CATEGORY,
        "X11Forwarding (target: no)",
        worst_status,
        "Checks whether SSH X11 forwarding is enabled. It is rarely needed on headless servers and expands the attack surface.",
        "With X11 forwarding on, a malicious or compromised X application on the client can interact with the server's X server, "
        "potentially capturing keystrokes or screen contents and gaining a foothold on the remote system.",
        "sshd -T | grep x11forwarding",
        current_value="; ".join(details) if details else "(no data)",
        recommended_value="no",
        details=details,
        remediation_id="ssh_x11_forwarding",
        manual_command="sed -i 's/^#\\?X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config && systemctl reload sshd",
    )


def run_checks():
    results = []
    for fn in (
        _check_permit_root_login,
        _check_password_auth,
        _check_pubkey_auth,
        _check_max_auth_tries,
        _check_empty_passwords,
        _check_x11_forwarding,
    ):
        try:
            results.append(fn())
        except Exception:
            results.append(
                skipped_check(
                    fn.__name__.replace("_check_", "").upper(),
                    CATEGORY,
                    fn.__doc__ or fn.__name__,
                    "An internal error occurred while evaluating this SSH check.",
                    "The check could not be completed due to an unexpected error.",
                    "internal",
                    "unexpected exception",
                )
            )
    return results
