"""Miscellaneous security checks: world-writable files, systemd sandboxing, TLS expiry, failed-login telemetry."""

import glob
import logging
import os
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

from common import (
    STATUS_CRITICAL,
    STATUS_INFO,
    STATUS_PASS,
    STATUS_WARNING,
    make_check,
    run_cmd,
    skipped_check,
)
from envdetect import detect_environment

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_world_writable(timeout: float = 15.0) -> Optional[List[str]]:
    """Find world-writable files/dirs without sticky bit outside pseudo/container paths."""
    prune_paths = ["/proc", "/sys", "/dev", "/run", "/var/lib/docker", "/var/lib/containerd", "/snap"]
    args = ["/usr/bin/find", "/"]
    # -xdev must come before the prune expressions to stay on one filesystem
    args.append("-xdev")
    for p in prune_paths:
        args.extend(["-path", p, "-prune", "-o"])
    args.extend(["-perm", "-0002", "!", "-perm", "-1000", "-type", "f", "-print"])
    # The expression above finds files; we also need dirs.
    # Rebuild correctly: we want ( -type f OR -type d ) AND world-writable AND NOT sticky
    # find / -xdev -path /proc -prune -o ... -perm -0002 ! -perm -1000 \( -type f -o -type d \) -print
    args = ["/usr/bin/find", "/"]
    args.append("-xdev")
    for p in prune_paths:
        args.extend(["-path", p, "-prune", "-o"])
    args.extend(["-perm", "-0002", "!", "-perm", "-1000", "(", "-type", "f", "-o", "-type", "d", ")", "-print"])
    result = run_cmd(args, timeout=timeout)
    if result.timed_out:
        logger.warning("find world-writable timed out after %.1fs", timeout)
        return None
    if result.returncode != 0:
        logger.warning("find world-writable returned %d: %s", result.returncode, result.stderr)
        return None
    lines = [ln.strip() for ln in result.stdout.splitlines() if ln.strip()]
    return lines


def _parse_systemd_units(unit_dir: str = "/etc/systemd/system") -> List[str]:
    """Return local .service unit paths in unit_dir (not symlinks, not vendor)."""
    units = []
    try:
        for path in glob.glob(os.path.join(unit_dir, "*.service")):
            # Skip symlinks (vendor units)
            if os.path.islink(path):
                continue
            units.append(path)
    except OSError as exc:
        logger.warning("Failed to list units in %s: %s", unit_dir, exc)
    return units


def _read_unit_sandboxing(unit_path: str) -> Dict[str, bool]:
    """Read a systemd unit file and report which sandboxing directives are present."""
    directives = {
        "NoNewPrivileges": False,
        "ProtectSystem": False,
        "PrivateTmp": False,
        "ProtectHome": False,
        "ProtectKernelTunables": False,
        "ProtectKernelModules": False,
    }
    try:
        with open(unit_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                for key in directives:
                    if line.startswith(key + "=") or line == key:
                        directives[key] = True
    except OSError as exc:
        logger.warning("Failed to read unit %s: %s", unit_path, exc)
    return directives


def _get_tls_ports() -> List[int]:
    """Return local listening TCP ports that may have TLS (from ss)."""
    result = run_cmd(["/usr/bin/ss", "-tlnH"], timeout=5.0)
    if result.returncode != 0:
        logger.warning("ss failed: %s", result.stderr)
        return []
    ports = []
    for line in result.stdout.splitlines():
        # ss -tlnH output: State Recv-Q Send-Q Local Address:Port Peer Address:Port
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]
        # local is like 0.0.0.0:443 or [::]:443 or 127.0.0.1:8443
        if ":" not in local:
            continue
        port_str = local.rsplit(":", 1)[-1]
        try:
            port = int(port_str)
        except ValueError:
            continue
        if port not in ports:
            ports.append(port)
    return ports


def _check_tls_expiry(port: int, handshake_fn: Optional[Callable] = None) -> Optional[Dict]:
    """Perform a local TLS handshake to 127.0.0.1:port and return expiry info."""
    if handshake_fn is not None:
        return handshake_fn(port)
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname="localhost") as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return None
                not_after = cert.get("notAfter")
                exp_dt = datetime.strptime(str(not_after), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days = (exp_dt - now).total_seconds() / 86400
                return {"port": port, "days_to_expiry": days, "expires_at": exp_dt.isoformat()}
    except ssl.SSLCertVerificationError as exc:
        logger.warning("TLS cert verification failed on port %d: %s", port, exc)
        return None
    except (OSError, socket.timeout) as exc:
        logger.warning("TLS handshake failed on port %d: %s", port, exc)
        return None


def _parse_failed_logins(log_path: str = "/var/log/auth.log") -> Dict[str, int]:
    """Parse auth.log for failed SSH logins and return {ip: count}."""
    counts: Dict[str, int] = {}
    pattern = re.compile(r"Failed password for (?:invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)")
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                m = pattern.search(line)
                if m:
                    ip = m.group(2)
                    counts[ip] = counts.get(ip, 0) + 1
    except OSError as exc:
        logger.warning("Failed to read %s: %s", log_path, exc)
    return counts


# ---------------------------------------------------------------------------
# Check functions
# ---------------------------------------------------------------------------


def check_world_writable() -> Dict:
    """MSC-001: World-writable files/dirs without sticky bit."""
    category = "misc"
    title = "World-writable files and directories without sticky bit"
    what = "Checks for world-writable files and directories outside pseudo-filesystems and container layers that lack the sticky bit."
    risk = "World-writable paths without sticky bit allow any user to delete or rename other users' files."
    cmd = "find / -xdev -path /proc -prune -o ... -perm -0002 ! -perm -1000"

    files = _find_world_writable(timeout=15.0)
    if files is None:
        return skipped_check(
            id="MSC-001",
            category=category,
            title=title,
            what_it_checks=what,
            risk=risk,
            command=cmd,
            reason="find command timed out or failed to execute",
        )
    if not files:
        return make_check(
            id="MSC-001",
            category=category,
            title=title,
            status=STATUS_PASS,
            what_it_checks=what,
            risk=risk,
            command=cmd,
            current_value="No world-writable paths without sticky bit found",
            recommended_value="",
            details=["All world-writable paths have the sticky bit set or are in excluded locations."],
        )
    details = files[:20]
    if len(files) > 20:
        details.append("... and {} more".format(len(files) - 20))
    return make_check(
        id="MSC-001",
        category=category,
        title=title,
        status=STATUS_WARNING,
        what_it_checks=what,
        risk=risk,
        command=cmd,
        current_value="{} world-writable paths without sticky bit".format(len(files)),
        recommended_value="Add sticky bit (chmod +t) or remove world-write permission",
        details=details,
    )


def check_systemd_sandboxing() -> List[Dict]:
    """MSC-002: Review systemd unit sandboxing for local units."""
    category = "misc"
    title = "Systemd unit sandboxing directives"
    what = "Reviews local systemd service units for missing sandboxing directives (NoNewPrivileges, ProtectSystem, PrivateTmp, ProtectHome)."
    risk = "Units without sandboxing directives run with broader privileges than necessary."
    cmd = "systemctl show --property=NoNewPrivileges,ProtectSystem,PrivateTmp,ProtectHome"

    unit_dir = "/etc/systemd/system"
    if not os.path.isdir(unit_dir):
        return [
            skipped_check(
                id="MSC-002",
                category=category,
                title=title,
                what_it_checks=what,
                risk=risk,
                command=cmd,
                reason="Directory /etc/systemd/system does not exist",
            )
        ]

    unit_paths = _parse_systemd_units(unit_dir)
    if not unit_paths:
        return [
            skipped_check(
                id="MSC-002",
                category=category,
                title=title,
                what_it_checks=what,
                risk=risk,
                command=cmd,
                reason="No local .service unit files found in /etc/systemd/system",
            )
        ]

    checks = []
    for unit_path in unit_paths:
        unit_name = os.path.basename(unit_path)
        directives = _read_unit_sandboxing(unit_path)
        missing = [k for k, v in directives.items() if not v]
        if not missing:
            checks.append(
                make_check(
                    id="MSC-002",
                    category=category,
                    title="Unit {} sandboxing".format(unit_name),
                    status=STATUS_PASS,
                    what_it_checks=what,
                    risk=risk,
                    command=cmd,
                    current_value="All sandboxing directives present",
                    recommended_value="",
                    details=["Unit {} has all recommended sandboxing directives.".format(unit_name)],
                )
            )
        else:
            details = ["Missing directives in {}: {}".format(unit_name, ", ".join(missing))]
            status = STATUS_INFO if len(missing) <= 2 else STATUS_WARNING
            checks.append(
                make_check(
                    id="MSC-002",
                    category=category,
                    title="Unit {} sandboxing".format(unit_name),
                    status=status,
                    what_it_checks=what,
                    risk=risk,
                    command=cmd,
                    current_value="Missing: {}".format(", ".join(missing)),
                    recommended_value="Add missing directives to [Service] section",
                    details=details,
                )
            )
    return checks


def check_tls_expiry(handshake_fn: Optional[Callable] = None) -> List[Dict]:
    """MSC-003: TLS certificate expiry on local listening ports."""
    category = "misc"
    title = "TLS certificate expiry on local listening ports"
    what = "Performs local TLS handshakes on listening ports and reports days until certificate expiry."
    risk = "Expired or soon-to-expire certificates cause TLS connection failures."
    cmd = "ss -tlnH && openssl s_client -connect 127.0.0.1:PORT"

    ports = _get_tls_ports()
    if not ports:
        return [
            skipped_check(
                id="MSC-003",
                category=category,
                title=title,
                what_it_checks=what,
                risk=risk,
                command=cmd,
                reason="No local listening TCP ports found via ss",
            )
        ]

    checks = []
    for port in ports:
        info = _check_tls_expiry(port, handshake_fn=handshake_fn)
        if info is None:
            checks.append(
                skipped_check(
                    id="MSC-003",
                    category=category,
                    title="TLS port {}".format(port),
                    what_it_checks=what,
                    risk=risk,
                    command=cmd,
                    reason="TLS handshake failed or no certificate returned for port {}".format(port),
                )
            )
            continue
        days = info["days_to_expiry"]
        if days < 0:
            status = STATUS_CRITICAL
            current = "Certificate on port {} expired {} days ago".format(port, abs(days))
            rec = "Renew the TLS certificate immediately"
        elif days < 3:
            status = STATUS_CRITICAL
            current = "Certificate on port {} expires in {:.1f} days".format(port, days)
            rec = "Renew the TLS certificate before it expires"
        elif days < 14:
            status = STATUS_WARNING
            current = "Certificate on port {} expires in {:.1f} days".format(port, days)
            rec = "Plan certificate renewal within 14 days"
        else:
            status = STATUS_PASS
            current = "Certificate on port {} valid for {:.1f} more days".format(port, days)
            rec = ""
        checks.append(
            make_check(
                id="MSC-003",
                category=category,
                title="TLS port {}".format(port),
                status=status,
                what_it_checks=what,
                risk=risk,
                command=cmd,
                current_value=current,
                recommended_value=rec,
                details=["Expires at: {}".format(info["expires_at"])],
            )
        )
    return checks


def check_failed_logins() -> Dict:
    """MSC-004: Failed-login telemetry from auth.log."""
    category = "misc"
    title = "Failed SSH login attempts by source IP"
    what = "Summarises failed SSH login attempts by source IP from /var/log/auth.log."
    risk = "High failure counts from a single IP may indicate brute-force attacks."
    cmd = "grep 'Failed password' /var/log/auth.log"

    env = detect_environment()
    fail2ban_active = env.fail2ban
    crowdsec_active = env.crowdsec

    counts = _parse_failed_logins()
    if not counts:
        reason = "No failed login entries found in /var/log/auth.log"
        if fail2ban_active or crowdsec_active:
            reason += " (fail2ban/crowdsec active, failures may be blocked before logging)"
        return skipped_check(
            id="MSC-004",
            category=category,
            title=title,
            what_it_checks=what,
            risk=risk,
            command=cmd,
            reason=reason,
        )

    top_ip = max(counts, key=lambda ip: counts[ip])
    top_count = counts[top_ip]
    details = ["{}: {} failures".format(ip, cnt) for ip, cnt in sorted(counts.items(), key=lambda x: -x[1])[:10]]

    if top_count > 100:
        if fail2ban_active or crowdsec_active:
            status = STATUS_INFO
            current = "Top IP {} has {} failures (fail2ban/crowdsec active)".format(top_ip, top_count)
            rec = "Failures are being handled by fail2ban/crowdsec"
        else:
            status = STATUS_WARNING
            current = "Top IP {} has {} failures".format(top_ip, top_count)
            rec = "Consider enabling fail2ban or reviewing SSH configuration"
    else:
        status = STATUS_PASS
        current = "Top IP {} has {} failures".format(top_ip, top_count)
        rec = ""

    return make_check(
        id="MSC-004",
        category=category,
        title=title,
        status=status,
        what_it_checks=what,
        risk=risk,
        command=cmd,
        current_value=current,
        recommended_value=rec,
        details=details,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run_checks() -> List[Dict]:
    """Run all miscellaneous checks and return a list of result dicts."""
    results: List[Dict] = []
    results.append(check_world_writable())
    results.extend(check_systemd_sandboxing())
    results.extend(check_tls_expiry())
    results.append(check_failed_logins())
    return results
