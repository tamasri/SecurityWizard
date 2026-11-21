"""Module 6: Log Tampering Protection & Intrusion Monitor."""

import os
import re
from collections import Counter

from common import (
    STATUS_CRITICAL,
    STATUS_INFO,
    STATUS_PASS,
    STATUS_WARNING,
    make_check,
    read_text,
    run_cmd,
    skipped_check,
)

CATEGORY = "logs"

AUTH_LOG = "/var/log/auth.log"
SYSLOG = "/var/log/syslog"


def _check_log_attr(log_path, check_id, remediation_id, log_name):
    """Check log file existence and recommend remote shipping."""
    try:
        if not os.path.exists(log_path):
            return make_check(
                check_id,
                CATEGORY,
                f"{log_name} protection",
                STATUS_INFO,
                "Checks whether the log file exists and recommends remote log shipping.",
                "Without remote log shipping, a compromised root user can delete or truncate local logs, destroying forensic evidence.",
                f"test -f {log_path}",
                current_value=f"{log_name} not found (journald-only or rotated away)",
                recommended_value="Consider remote log shipping (rsyslog/journald forwarding) or auditd for tamper-proof logging.",
                details=[
                    f"{log_name} does not exist. Consider forwarding logs to a remote server for tamper-proof storage."
                ],
                remediation_id=None,
                manual_command="",
            )

        return make_check(
            check_id,
            CATEGORY,
            f"{log_name} protection",
            STATUS_INFO,
            "Checks whether the log file exists and recommends remote log shipping.",
            "Without remote log shipping, a compromised root user can delete or truncate local logs, destroying forensic evidence.",
            f"test -f {log_path}",
            current_value=f"{log_name} exists",
            recommended_value="Consider remote log shipping (rsyslog/journald forwarding) or auditd for tamper-proof logging.",
            details=[f"{log_name} exists. Consider forwarding logs to a remote server for tamper-proof storage."],
            remediation_id=None,
            manual_command="",
        )
    except Exception as e:
        import logging

        logging.getLogger("securitywizard").exception("Error checking %s", log_path)
        return skipped_check(
            check_id,
            CATEGORY,
            f"{log_name} protection",
            "Checks whether the log file exists and recommends remote log shipping.",
            "Without remote log shipping, a compromised root user can delete or truncate local logs, destroying forensic evidence.",
            f"test -f {log_path}",
            f"Unexpected error: {e}",
            remediation_id=None,
        )


def _check_brute_force():
    """Parse auth log for brute-force patterns."""
    try:
        log_content = read_text(AUTH_LOG, "")
        source = AUTH_LOG

        if not log_content:
            # Fallback to journalctl
            rc, out, err = run_cmd(
                ["journalctl", "-u", "ssh", "-u", "sshd", "--no-pager", "-n", "5000", "--output=cat"],
                timeout=30,
            )
            if rc != 0 or not out.strip():
                return skipped_check(
                    "LOG-003",
                    CATEGORY,
                    "Brute-force telemetry: failed SSH logins, invalid users, top attacker IPs",
                    "Parses recent authentication logs for failed SSH logins, invalid users, and top attacking IPs.",
                    "Brute-force attacks can exhaust accounts or guess passwords. Without telemetry, an admin may not notice an ongoing attack in time.",
                    "journalctl -u ssh -u sshd --no-pager -n 5000 --output=cat",
                    "No auth log data available (auth.log missing and journalctl returned no data).",
                    remediation_id=None,
                )
            log_content = out
            source = "journalctl -u ssh -u sshd"

        failed_passwords = 0
        invalid_users = 0
        user_counter = Counter()
        ip_counter = Counter()

        # Pattern for failed password: "Failed password for (invalid user )?USER from IP"
        failed_pattern = re.compile(r"Failed password for (invalid user )?(\S+) from (\S+)")
        # Pattern for invalid user: "Invalid user USER from IP"
        invalid_pattern = re.compile(r"Invalid user (\S+) from (\S+)")

        for line in log_content.splitlines():
            m = failed_pattern.search(line)
            if m:
                failed_passwords += 1
                user = m.group(2)
                ip = m.group(3)
                user_counter[user] += 1
                ip_counter[ip] += 1
                continue

            m = invalid_pattern.search(line)
            if m:
                invalid_users += 1
                user = m.group(1)
                ip = m.group(2)
                user_counter[user] += 1
                ip_counter[ip] += 1

        total_failures = failed_passwords + invalid_users

        if total_failures > 1000:
            status = STATUS_CRITICAL
            current_value = (
                f"{total_failures} failures ({failed_passwords} failed passwords, {invalid_users} invalid users)"
            )
            recommended_value = "Investigate and block top attacker IPs; consider fail2ban or crowdsec."
        elif total_failures > 100:
            status = STATUS_WARNING
            current_value = (
                f"{total_failures} failures ({failed_passwords} failed passwords, {invalid_users} invalid users)"
            )
            recommended_value = "Investigate and block top attacker IPs; consider fail2ban or crowdsec."
        elif total_failures > 0:
            status = STATUS_INFO
            current_value = (
                f"{total_failures} failures ({failed_passwords} failed passwords, {invalid_users} invalid users)"
            )
            recommended_value = "Monitor for increasing failure counts; consider fail2ban."
        else:
            status = STATUS_PASS
            current_value = "No recent failed logins detected"
            recommended_value = "No action needed; keep monitoring."

        details = []
        if total_failures > 0:
            details.append(
                f"Total failures: {total_failures} ({failed_passwords} failed passwords, {invalid_users} invalid users)"
            )
            details.append("")
            details.append("Top 5 usernames:")
            for rank, (user, count) in enumerate(user_counter.most_common(5), 1):
                details.append(f"  {rank}. {user}: {count} attempts")
            details.append("")
            details.append("Top 10 attacking IPs:")
            for rank, (ip, count) in enumerate(ip_counter.most_common(10), 1):
                details.append(f"  {rank}. {ip}: {count} attempts")
        else:
            details.append("No failed logins or invalid users found in the log.")

        return make_check(
            "LOG-003",
            CATEGORY,
            "Brute-force telemetry: failed SSH logins, invalid users, top attacker IPs",
            status,
            "Parses the authentication log for failed SSH password attempts and invalid user logins. "
            "It counts total failures, identifies the most targeted usernames, and ranks the top attacking IP addresses.",
            "Brute-force attacks can exhaust accounts or guess weak passwords. Without telemetry, an admin may not notice an ongoing attack in time. "
            "High failure counts indicate an active brute-force attempt that should be investigated and blocked.",
            f"grep -E 'Failed password|Invalid user' {source}",
            current_value=current_value,
            recommended_value=recommended_value,
            details=details,
            remediation_id=None,
            manual_command="",
        )
    except Exception as e:
        return skipped_check(
            "LOG-003",
            CATEGORY,
            "Brute-force telemetry: failed SSH logins, invalid users, top attacker IPs",
            "Parses recent authentication logs for failed SSH logins, invalid users, and top attacking IPs.",
            "Brute-force attacks can exhaust accounts or guess passwords. Without telemetry, an admin may not notice an ongoing attack in time.",
            f"grep -E 'Failed password|Invalid user' {AUTH_LOG}",
            f"Unexpected error: {e}",
            remediation_id=None,
        )


def _check_fail2ban_crowdsec():
    """Check status of fail2ban and crowdsec."""
    try:
        fail2ban_active = False
        crowdsec_active = False

        rc1, out1, err1 = run_cmd(["systemctl", "is-active", "fail2ban"])
        fail2ban_active = out1.strip() == "active"

        rc2, out2, err2 = run_cmd(["systemctl", "is-active", "crowdsec"])
        crowdsec_active = out2.strip() == "active"

        if fail2ban_active and crowdsec_active:
            status = STATUS_PASS
            current_value = "Both fail2ban and crowdsec are active"
            recommended_value = "Both fail2ban and crowdsec running."
            details = ["fail2ban: active", "crowdsec: active"]
        elif fail2ban_active:
            status = STATUS_PASS
            current_value = "fail2ban is active (crowdsec not installed)"
            recommended_value = "fail2ban running; crowdsec optional."
            details = ["fail2ban: active", "crowdsec: not active (may not be installed)"]
        elif crowdsec_active:
            status = STATUS_PASS
            current_value = "crowdsec is active (fail2ban not installed)"
            recommended_value = "crowdsec running; fail2ban optional."
            details = ["fail2ban: not active (may not be installed)", "crowdsec: active"]
        else:
            status = STATUS_WARNING
            current_value = "Neither fail2ban nor crowdsec is active"
            recommended_value = "Install and enable fail2ban or crowdsec to automatically block brute-force attackers."
            details = [
                "fail2ban: not active (may not be installed)",
                "crowdsec: not active (may not be installed)",
                "Without an intrusion prevention tool, brute-force attacks must be handled manually.",
            ]

        return make_check(
            "LOG-004",
            CATEGORY,
            "fail2ban / crowdsec status",
            status,
            "Checks whether fail2ban or crowdsec is running. These tools automatically ban IP addresses "
            "that exceed a threshold of failed login attempts, providing real-time brute-force protection.",
            "Without fail2ban or crowdsec, brute-force attacks must be detected and blocked manually. "
            "An attacker can keep guessing passwords indefinitely, increasing the chance of a successful login.",
            "systemctl is-active fail2ban; systemctl is-active crowdsec",
            current_value=current_value,
            recommended_value=recommended_value,
            details=details,
            remediation_id=None,
            manual_command="",
        )
    except Exception as e:
        return skipped_check(
            "LOG-004",
            CATEGORY,
            "fail2ban / crowdsec status",
            "Checks whether fail2ban or crowdsec is running for automatic brute-force protection.",
            "Without fail2ban or crowdsec, brute-force attacks must be detected and blocked manually.",
            "systemctl is-active fail2ban; systemctl is-active crowdsec",
            f"Unexpected error: {e}",
            remediation_id=None,
        )


def _check_auditd():
    """Check auditd status."""
    try:
        rc, out, err = run_cmd(["systemctl", "is-active", "auditd"])
        auditd_active = out.strip() == "active"

        if auditd_active:
            status = STATUS_PASS
            current_value = "auditd is active"
            recommended_value = "auditd running."
            details = ["auditd service is active and recording system calls."]
        else:
            status = STATUS_WARNING
            current_value = "auditd is not active"
            recommended_value = "Install and enable auditd for system call auditing."
            details = [
                "auditd service is not active (may not be installed).",
                "Without auditd, system-level events like file access, privilege escalation, and network connections are not logged.",
            ]

        return make_check(
            "LOG-005",
            CATEGORY,
            "auditd status",
            status,
            "Checks whether the audit daemon (auditd) is running. auditd records system calls and security-relevant events, "
            "providing a detailed audit trail for forensic analysis and compliance.",
            "Without auditd, an attacker's actions at the system call level are not captured. "
            "This makes it harder to detect privilege escalation, unauthorized file access, or configuration changes.",
            "systemctl is-active auditd",
            current_value=current_value,
            recommended_value=recommended_value,
            details=details,
            remediation_id=None,
            manual_command="",
        )
    except Exception as e:
        return skipped_check(
            "LOG-005",
            CATEGORY,
            "auditd status",
            "Checks whether the audit daemon (auditd) is running for system call auditing.",
            "Without auditd, system-level events like file access and privilege escalation are not logged.",
            "systemctl is-active auditd",
            f"Unexpected error: {e}",
            remediation_id=None,
        )


def run_checks() -> list:
    """Run all log checks and return a list of check result dicts."""
    checks = []

    # LOG-001: auth.log protection
    checks.append(_check_log_attr(AUTH_LOG, "LOG-001", None, "/var/log/auth.log"))

    # LOG-002: syslog protection
    checks.append(_check_log_attr(SYSLOG, "LOG-002", None, "/var/log/syslog"))

    # LOG-003: brute-force telemetry
    checks.append(_check_brute_force())

    # LOG-004: fail2ban / crowdsec
    checks.append(_check_fail2ban_crowdsec())

    # LOG-005: auditd
    checks.append(_check_auditd())

    return checks
