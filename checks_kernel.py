"""checks_kernel.py - Kernel & Network Stack Hardening (sysctl) checks."""

import os
import re

from common import (
    STATUS_PASS,
    STATUS_WARNING,
    STATUS_CRITICAL,
    STATUS_INFO,
    STATUS_SKIPPED,
    run_cmd,
    make_check,
    skipped_check,
)


def _is_container_or_multihomed() -> bool:
    """
    Detect if the host requires loose rp_filter (mode 2) instead of strict (mode 1).
    True if:
    - Docker is present (/var/lib/docker or docker binary)
    - Kubernetes is present (/etc/kubernetes or kubelet)
    - WireGuard is present (/etc/wireguard or wg binary)
    - Multiple default routes or >1 non-loopback interface with a gateway
    """
    # 1. Docker
    if os.path.isdir("/var/lib/docker"):
        return True
    rc, _, _ = run_cmd(["which", "docker"])
    if rc == 0:
        return True

    # 2. Kubernetes
    if os.path.isdir("/etc/kubernetes"):
        return True
    rc, _, _ = run_cmd(["which", "kubelet"])
    if rc == 0:
        return True

    # 3. WireGuard
    if os.path.isdir("/etc/wireguard"):
        return True
    rc, _, _ = run_cmd(["which", "wg"])
    if rc == 0:
        return True

    # 4. Multi-homed / Multiple default routes
    rc, out, _ = run_cmd(["ip", "route", "show", "default"])
    if rc == 0:
        lines = [l for l in out.strip().splitlines() if l.strip()]
        if len(lines) > 1:
            return True

    # 5. >1 non-loopback interface with a gateway
    rc, out, _ = run_cmd(["ip", "-o", "-4", "addr", "show"])
    if rc == 0:
        non_loopback_with_gw = 0
        for line in out.strip().splitlines():
            if "lo:" in line:
                continue
            if "inet" in line:
                non_loopback_with_gw += 1
                # Check for default route via this interface implicitly by counting interfaces
                # Actually, the "multiple default routes" check above covers the routing table.
                # The requirement says: "more than one default-route or >1 non-loopback interface with its own gateway"
                # The "ip route show default" check is the most reliable for "multiple default routes".
                # The "non-loopback interface with its own gateway" is tricky without parsing routes per interface.
                # We'll stick to the multi-default-route check as the primary multi-homed indicator.
                pass
        # If we didn't return True on multiple default routes, we might still have a multi-homed host
        # where interfaces have gateways but no multiple default routes (e.g., static routes).
        # But the requirement specifically mentions "more than one default-route OR >1 non-loopback interface with its own gateway".
        # Let's check for gateways on interfaces.
        rc2, out2, _ = run_cmd(["ip", "-o", "-4", "route", "show"])
        if rc2 == 0:
            gateways = set()
            for line in out2.strip().splitlines():
                if "via" in line:
                    parts = line.split()
                    if len(parts) > 1:
                        gateways.add(parts[1])
            if len(gateways) > 1:
                return True

    return False


def _read_sysctl(key: str) -> tuple[bool, str]:
    """Read a single sysctl key. Returns (found, value)."""
    rc, out, err = run_cmd(["sysctl", "-n", key])
    if rc != 0:
        return False, ""
    return True, out.strip()


def _check_rpf() -> dict:
    try:
        found_all, val_all = _read_sysctl("net.ipv4.conf.all.rp_filter")
        found_def, val_def = _read_sysctl("net.ipv4.conf.default.rp_filter")

        if not found_all or not found_def:
            return skipped_check(
                "KRN-001", "kernel",
                "rp_filter = 1 for all and default (anti IP spoofing)",
                "Checks that the kernel enforces strict reverse path filtering on all interfaces and the default interface.",
                "An attacker can spoof source IPs to bypass firewall rules or poison ARP tables.",
                "sysctl -n net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter",
                "rp_filter keys not found (kernel may lack IPv4)",
                "sysctl_baseline",
            )

        multi_homed = _is_container_or_multihomed()
        current = f"all={val_all}, default={val_def}"
        details = [
            f"net.ipv4.conf.all.rp_filter = {val_all}",
            f"net.ipv4.conf.default.rp_filter = {val_def}",
        ]

        if multi_homed:
            if val_all == "2" and val_def == "2":
                status = STATUS_PASS
                rec = "2 (loose)"
                manual = "sysctl -w net.ipv4.conf.all.rp_filter=2 net.ipv4.conf.default.rp_filter=2"
                details.append("Loose mode (2) is appropriate for Docker/Kubernetes/WireGuard/multi-homed hosts.")
            elif val_all == "1" and val_def == "1":
                status = STATUS_PASS
                rec = "1 (strict) or 2 (loose)"
                manual = "sysctl -w net.ipv4.conf.all.rp_filter=2 net.ipv4.conf.default.rp_filter=2"
                details.append("Strict mode (1) is acceptable, but loose (2) is recommended for containerized environments.")
            elif val_all == "0" or val_def == "0":
                status = STATUS_WARNING
                rec = "2 (loose)"
                manual = "sysctl -w net.ipv4.conf.all.rp_filter=2 net.ipv4.conf.default.rp_filter=2"
                details.append("rp_filter is disabled (0); loose mode (2) is recommended to avoid breaking container networking.")
            else:
                status = STATUS_WARNING
                rec = "2 (loose)"
                manual = "sysctl -w net.ipv4.conf.all.rp_filter=2 net.ipv4.conf.default.rp_filter=2"
                details.append("Mixed rp_filter values; loose mode (2) is recommended for consistency on containerized hosts.")
        else:
            if val_all == "1" and val_def == "1":
                status = STATUS_PASS
                rec = "1 (strict)"
                manual = "sysctl -w net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.default.rp_filter=1"
            elif val_all == "2" and val_def == "2":
                status = STATUS_WARNING
                rec = "1 (strict)"
                manual = "sysctl -w net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.default.rp_filter=1"
            elif val_all == "0" or val_def == "0":
                status = STATUS_CRITICAL
                rec = "1 (strict)"
                manual = "sysctl -w net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.default.rp_filter=1"
            else:
                status = STATUS_WARNING
                rec = "1 (strict)"
                manual = "sysctl -w net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.default.rp_filter=1"

        return make_check(
            "KRN-001", "kernel",
            "rp_filter = 1 for all and default (anti IP spoofing)",
            status,
            "Reverse path filtering verifies that the source IP of an incoming packet can be routed back via the same interface it arrived on. "
            "Strict mode (1) drops packets whose source is unreachable via the receiving interface, blocking common IP-spoofing attacks. "
            "Loose mode (2) only checks that the source is reachable via some interface, which is necessary for asymmetric routing in containerized environments.",
            "Without strict rp_filter, an attacker on the same network segment can forge source addresses to bypass stateful firewalls, "
            "poison ARP caches, and inject traffic that appears to come from trusted hosts. "
            "On containerized hosts, strict mode can break Docker/Kubernetes networking, so loose mode is accepted.",
            "sysctl -n net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter",
            current,
            rec,
            details,
            "sysctl_baseline",
            manual,
        )
    except Exception as exc:
        return skipped_check(
            "KRN-001", "kernel",
            "rp_filter = 1 for all and default (anti IP spoofing)",
            "Checks that the kernel enforces strict reverse path filtering on all interfaces and the default interface.",
            "An attacker can spoof source IPs to bypass firewall rules or poison ARP tables.",
            "sysctl -n net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter",
            f"Unexpected error: {exc}",
            "sysctl_baseline",
        )


def _check_accept_redirects() -> dict:
    try:
        found_v4, val_v4 = _read_sysctl("net.ipv4.conf.all.accept_redirects")
        found_v6, val_v6 = _read_sysctl("net.ipv6.conf.all.accept_redirects")

        if not found_v4:
            return skipped_check(
                "KRN-002", "kernel",
                "accept_redirects = 0 for IPv4 and IPv6 (anti ICMP MITM)",
                "Checks that the kernel ignores ICMP redirect messages on all interfaces for both IPv4 and IPv6.",
                "An attacker can send forged ICMP redirects to reroute traffic through a rogue gateway.",
                "sysctl -n net.ipv4.conf.all.accept_redirects net.ipv6.conf.all.accept_redirects",
                "net.ipv4.conf.all.accept_redirects not found",
                "sysctl_baseline",
            )

        current_parts = [f"ipv4={val_v4}"]
        details = [f"net.ipv4.conf.all.accept_redirects = {val_v4}"]
        if found_v6:
            current_parts.append(f"ipv6={val_v6}")
            details.append(f"net.ipv6.conf.all.accept_redirects = {val_v6}")
        else:
            details.append("net.ipv6.conf.all.accept_redirects = (IPv6 not available)")

        current = ", ".join(current_parts)

        v4_ok = val_v4 == "0"
        v6_ok = (not found_v6) or val_v6 == "0"

        if v4_ok and v6_ok:
            status = STATUS_PASS
            rec = "0 (disabled)"
            manual = "sysctl -w net.ipv4.conf.all.accept_redirects=0"
        elif not v4_ok:
            status = STATUS_CRITICAL
            rec = "0 (disabled)"
            manual = "sysctl -w net.ipv4.conf.all.accept_redirects=0"
        else:
            status = STATUS_WARNING
            rec = "0 (disabled)"
            manual = "sysctl -w net.ipv4.conf.all.accept_redirects=0 net.ipv6.conf.all.accept_redirects=0"

        return make_check(
            "KRN-002", "kernel",
            "accept_redirects = 0 for IPv4 and IPv6 (anti ICMP MITM)",
            status,
            "ICMP redirect messages tell the host to send future packets via a different gateway. "
            "Disabling accept_redirects prevents a compromised or malicious host from rerouting your traffic through an attacker-controlled path.",
            "An attacker on the same L2 segment can send forged ICMP redirects to hijack sessions, perform man-in-the-middle attacks, "
            "and silently eavesdrop or modify traffic destined for other hosts.",
            "sysctl -n net.ipv4.conf.all.accept_redirects net.ipv6.conf.all.accept_redirects",
            current,
            rec,
            details,
            "sysctl_baseline",
            manual,
        )
    except Exception as exc:
        return skipped_check(
            "KRN-002", "kernel",
            "accept_redirects = 0 for IPv4 and IPv6 (anti ICMP MITM)",
            "Checks that the kernel ignores ICMP redirect messages on all interfaces for both IPv4 and IPv6.",
            "An attacker can send forged ICMP redirects to reroute traffic through a rogue gateway.",
            "sysctl -n net.ipv4.conf.all.accept_redirects net.ipv6.conf.all.accept_redirects",
            f"Unexpected error: {exc}",
            "sysctl_baseline",
        )


def _check_send_redirects() -> dict:
    try:
        found, val = _read_sysctl("net.ipv4.conf.all.send_redirects")
        if not found:
            return skipped_check(
                "KRN-003", "kernel",
                "net.ipv4.conf.all.send_redirects = 0",
                "Checks that the kernel does not send ICMP redirect messages to other hosts.",
                "As a router or host that forwards packets, sending redirects can leak topology and enable MITM.",
                "sysctl -n net.ipv4.conf.all.send_redirects",
                "net.ipv4.conf.all.send_redirects not found",
                "sysctl_baseline",
            )

        current = val
        details = [f"net.ipv4.conf.all.send_redirects = {val}"]

        if val == "0":
            status = STATUS_PASS
            rec = "0 (disabled)"
            manual = "sysctl -w net.ipv4.conf.all.send_redirects=0"
        else:
            status = STATUS_WARNING
            rec = "0 (disabled)"
            manual = "sysctl -w net.ipv4.conf.all.send_redirects=0"

        return make_check(
            "KRN-003", "kernel",
            "net.ipv4.conf.all.send_redirects = 0",
            status,
            "When a host acts as a router or forwards packets, it may send ICMP redirects telling other hosts to use a better path. "
            "Disabling send_redirects prevents the host from inadvertently altering other hosts' routing decisions.",
            "If this host forwards traffic, sending redirects can expose internal network structure and allow an attacker to influence "
            "how other hosts route their packets, enabling traffic interception.",
            "sysctl -n net.ipv4.conf.all.send_redirects",
            current,
            rec,
            details,
            "sysctl_baseline",
            manual,
        )
    except Exception as exc:
        return skipped_check(
            "KRN-003", "kernel",
            "net.ipv4.conf.all.send_redirects = 0",
            "Checks that the kernel does not send ICMP redirect messages to other hosts.",
            "As a router or host that forwards packets, sending redirects can leak topology and enable MITM.",
            "sysctl -n net.ipv4.conf.all.send_redirects",
            f"Unexpected error: {exc}",
            "sysctl_baseline",
        )


def _check_syncookies() -> dict:
    try:
        found, val = _read_sysctl("net.ipv4.tcp_syncookies")
        if not found:
            return skipped_check(
                "KRN-004", "kernel",
                "net.ipv4.tcp_syncookies = 1 (SYN flood protection)",
                "Checks that TCP SYN cookies are enabled to defend against SYN flood denial-of-service attacks.",
                "Without SYN cookies, an attacker can exhaust the connection backlog and make the host unresponsive.",
                "sysctl -n net.ipv4.tcp_syncookies",
                "net.ipv4.tcp_syncookies not found",
                "sysctl_baseline",
            )

        current = val
        details = [f"net.ipv4.tcp_syncookies = {val}"]

        if val == "1":
            status = STATUS_PASS
            rec = "1 (enabled)"
            manual = "sysctl -w net.ipv4.tcp_syncookies=1"
        else:
            status = STATUS_CRITICAL
            rec = "1 (enabled)"
            manual = "sysctl -w net.ipv4.tcp_syncookies=1"

        return make_check(
            "KRN-004", "kernel",
            "net.ipv4.tcp_syncookies = 1 (SYN flood protection)",
            status,
            "SYN cookies allow the kernel to accept new TCP connections even when the SYN backlog is full, by encoding connection state "
            "into the initial sequence number instead of allocating a half-open socket.",
            "An attacker can flood the host with SYN packets to fill the connection backlog, causing legitimate connections to be dropped "
            "and making the service unavailable (SYN flood DoS).",
            "sysctl -n net.ipv4.tcp_syncookies",
            current,
            rec,
            details,
            "sysctl_baseline",
            manual,
        )
    except Exception as exc:
        return skipped_check(
            "KRN-004", "kernel",
            "net.ipv4.tcp_syncookies = 1 (SYN flood protection)",
            "Checks that TCP SYN cookies are enabled to defend against SYN flood denial-of-service attacks.",
            "Without SYN cookies, an attacker can exhaust the connection backlog and make the host unresponsive.",
            "sysctl -n net.ipv4.tcp_syncookies",
            f"Unexpected error: {exc}",
            "sysctl_baseline",
        )


def _check_source_route() -> dict:
    try:
        found, val = _read_sysctl("net.ipv4.conf.all.accept_source_route")
        if not found:
            return skipped_check(
                "KRN-005", "kernel",
                "net.ipv4.conf.all.accept_source_route = 0",
                "Checks that the kernel does not accept source routing (record route) options in IP packets.",
                "An attacker can use source routing to force traffic through a compromised intermediate host.",
                "sysctl -n net.ipv4.conf.all.accept_source_route",
                "net.ipv4.conf.all.accept_source_route not found",
                "sysctl_baseline",
            )

        current = val
        details = [f"net.ipv4.conf.all.accept_source_route = {val}"]

        if val == "0":
            status = STATUS_PASS
            rec = "0 (disabled)"
            manual = "sysctl -w net.ipv4.conf.all.accept_source_route=0"
        else:
            status = STATUS_WARNING
            rec = "0 (disabled)"
            manual = "sysctl -w net.ipv4.conf.all.accept_source_route=0"

        return make_check(
            "KRN-005", "kernel",
            "net.ipv4.conf.all.accept_source_route = 0",
            status,
            "IP source routing allows the sender to specify the path packets must take. Disabling accept_source_route prevents remote hosts "
            "from dictating the route of packets arriving at this machine.",
            "An attacker can use source routing to force traffic through a malicious intermediate host, enabling traffic sniffing, "
            "session hijacking, or bypassing firewall rules that assume a direct path.",
            "sysctl -n net.ipv4.conf.all.accept_source_route",
            current,
            rec,
            details,
            "sysctl_baseline",
            manual,
        )
    except Exception as exc:
        return skipped_check(
            "KRN-005", "kernel",
            "net.ipv4.conf.all.accept_source_route = 0",
            "Checks that the kernel does not accept source routing (record route) options in IP packets.",
            "An attacker can use source routing to force traffic through a compromised intermediate host.",
            "sysctl -n net.ipv4.conf.all.accept_source_route",
            f"Unexpected error: {exc}",
            "sysctl_baseline",
        )


def _check_dmesg_restrict() -> dict:
    try:
        found, val = _read_sysctl("kernel.dmesg_restrict")
        if not found:
            return skipped_check(
                "KRN-006", "kernel",
                "kernel.dmesg_restrict = 1",
                "Checks that only privileged users can read kernel ring buffer messages via dmesg.",
                "Kernel messages often contain sensitive data such as memory addresses, MAC addresses, and hardware details.",
                "sysctl -n kernel.dmesg_restrict",
                "kernel.dmesg_restrict not found",
                "sysctl_baseline",
            )

        current = val
        details = [f"kernel.dmesg_restrict = {val}"]

        if val == "1":
            status = STATUS_PASS
            rec = "1 (restricted)"
            manual = "sysctl -w kernel.dmesg_restrict=1"
        else:
            status = STATUS_WARNING
            rec = "1 (restricted)"
            manual = "sysctl -w kernel.dmesg_restrict=1"

        return make_check(
            "KRN-006", "kernel",
            "kernel.dmesg_restrict = 1",
            status,
            "The kernel ring buffer (readable via dmesg or /dev/kmsg) contains boot messages, hardware info, and runtime events. "
            "Restricting access to root prevents unprivileged users from reading potentially sensitive kernel diagnostics.",
            "An unprivileged user can read dmesg to learn kernel memory addresses (aiding info-leak exploits), MAC addresses, "
            "network topology, and other details useful for crafting targeted attacks.",
            "sysctl -n kernel.dmesg_restrict",
            current,
            rec,
            details,
            "sysctl_baseline",
            manual,
        )
    except Exception as exc:
        return skipped_check(
            "KRN-006", "kernel",
            "kernel.dmesg_restrict = 1",
            "Checks that only privileged users can read kernel ring buffer messages via dmesg.",
            "Kernel messages often contain sensitive data such as memory addresses, MAC addresses, and hardware details.",
            "sysctl -n kernel.dmesg_restrict",
            f"Unexpected error: {exc}",
            "sysctl_baseline",
        )


def _check_kptr_restrict() -> dict:
    try:
        found, val = _read_sysctl("kernel.kptr_restrict")
        if not found:
            return skipped_check(
                "KRN-007", "kernel",
                "kernel.kptr_restrict = 2 (kernel pointer protection)",
                "Checks that kernel pointer addresses are hidden from unprivileged users.",
                "Exposing kernel pointer addresses helps attackers defeat KASLR and craft reliable kernel exploits.",
                "sysctl -n kernel.kptr_restrict",
                "kernel.kptr_restrict not found",
                "sysctl_baseline",
            )

        current = val
        details = [f"kernel.kptr_restrict = {val}"]

        if val == "2":
            status = STATUS_PASS
            rec = "2 (hidden from all unprivileged)"
            manual = "sysctl -w kernel.kptr_restrict=2"
        elif val == "1":
            status = STATUS_WARNING
            rec = "2 (hidden from all unprivileged)"
            manual = "sysctl -w kernel.kptr_restrict=2"
        else:
            status = STATUS_CRITICAL
            rec = "2 (hidden from all unprivileged)"
            manual = "sysctl -w kernel.kptr_restrict=2"

        return make_check(
            "KRN-007", "kernel",
            "kernel.kptr_restrict = 2 (kernel pointer protection)",
            status,
            "Kernel pointer addresses are exposed in /proc/kallsyms and other interfaces. Setting kptr_restrict to 2 hides these addresses "
            "from all unprivileged processes, protecting the effectiveness of KASLR (Kernel Address Space Layout Randomization).",
            "If kernel pointer addresses are visible, an attacker can compute the base of kernel modules and defeat KASLR, "
            "making it much easier to develop reliable kernel exploits for privilege escalation.",
            "sysctl -n kernel.kptr_restrict",
            current,
            rec,
            details,
            "sysctl_baseline",
            manual,
        )
    except Exception as exc:
        return skipped_check(
            "KRN-007", "kernel",
            "kernel.kptr_restrict = 2 (kernel pointer protection)",
            "Checks that kernel pointer addresses are hidden from unprivileged users.",
            "Exposing kernel pointer addresses helps attackers defeat KASLR and craft reliable kernel exploits.",
            "sysctl -n kernel.kptr_restrict",
            f"Unexpected error: {exc}",
            "sysctl_baseline",
        )


def run_checks() -> list[dict]:
    """Run all kernel/sysctl checks and return one dict per check id."""
    return [
        _check_rpf(),
        _check_accept_redirects(),
        _check_send_redirects(),
        _check_syncookies(),
        _check_source_route(),
        _check_dmesg_restrict(),
        _check_kptr_restrict(),
    ]
