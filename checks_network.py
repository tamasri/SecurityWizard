"""checks_network.py — Network Surface, Ports & Firewall Auditor.

Implements the 'network' category checks:
  NET-001  Listening TCP/UDP sockets (ss -tulpn)
  NET-002  Dangerous services exposed on all interfaces (0.0.0.0 / ::)
  NET-003  UFW firewall status and default policies
  NET-004  Docker published ports bypassing UFW (DOCKER-USER chain)
"""

import logging
import re

from common import (
    STATUS_CRITICAL,
    STATUS_INFO,
    STATUS_PASS,
    STATUS_SKIPPED,
    make_check,
    run_cmd,
    skipped_check,
)
from config import get_config

logger = logging.getLogger("securitywizard")

_PROCESS_RE = re.compile(r'users:\(\("([^"]+)",pid=(\d+)')


def parse_ss_line(line: str):
    """Parse a single line of `ss -tulnpH` output.

    Returns a dict with keys proto, state, addr, port, process, pid,
    or None if the line is empty or too short.
    """
    line = line.strip()
    if not line:
        return None
    parts = line.split()
    if len(parts) < 4:
        return None
    proto = parts[0]
    state = parts[1]
    local = parts[4]
    if ":" in local:
        addr, port = local.rsplit(":", 1)
        addr = addr.strip("[]")
    else:
        addr = local
        port = ""
    process_name = ""
    pid = ""
    if len(parts) > 5:
        proc_part = " ".join(parts[5:])
        m = _PROCESS_RE.search(proc_part)
        if m:
            process_name = m.group(1)
            pid = m.group(2)
    return {
        "proto": proto,
        "state": state,
        "addr": addr,
        "port": port,
        "process": process_name,
        "pid": pid,
    }


def _parse_ss_output(output: str) -> list:
    """Parse ss -tulnpH output into a list of dicts.

    Each dict has keys: proto, state, addr, port, process, pid.
    """
    results = []
    for line in output.splitlines():
        parsed = parse_ss_line(line)
        if parsed is not None:
            results.append(parsed)
    return results


def _is_dangerous_port(port: str) -> bool:
    """Return True if the port is in the dangerous services list."""
    try:
        p = int(port)
    except (ValueError, TypeError):
        return False
    dangerous_ports = {
        2375,
        2376,
        3306,
        5432,
        6379,
        27017,
        9200,
        9300,
        11211,
        5984,
        1433,
        3389,
        5900,
        2379,
        10250,
    }
    return p in dangerous_ports


def _is_exposed_to_all(addr: str) -> bool:
    """Return True if the address binds to all interfaces."""
    return addr in ("0.0.0.0", "::", "*")


def check_net_001():
    """NET-001: Listening TCP/UDP sockets (ss -tulnpH)."""
    cmd = ["ss", "-tulnpH"]
    res = run_cmd(cmd)
    rc, out, err = res.returncode, res.stdout, res.stderr

    if rc == 127:
        return skipped_check(
            "NET-001",
            "network",
            "Listening TCP/UDP sockets (ss -tulnpH)",
            "Enumerates every TCP and UDP socket currently in LISTEN state, "
            "showing the protocol, local address and port, peer address, "
            "and the owning process name and PID.",
            "Without a complete inventory of listening sockets, an administrator "
            "cannot tell which services are reachable from the network, making it "
            "easy to miss a forgotten database or cache server that is exposed "
            "to the world.",
            "ss -tulnpH",
            "ss binary not found; install iproute2 (apt install iproute2)",
        )

    if rc != 0:
        return skipped_check(
            "NET-001",
            "network",
            "Listening TCP/UDP sockets (ss -tulnpH)",
            "Enumerates every TCP and UDP socket currently in LISTEN state, "
            "showing the protocol, local address and port, peer address, "
            "and the owning process name and PID.",
            "Without a complete inventory of listening sockets, an administrator "
            "cannot tell which services are reachable from the network, making it "
            "easy to miss a forgotten database or cache server that is exposed "
            "to the world.",
            "ss -tulnpH",
            f"ss returned error: {err.strip()}",
        )

    sockets = _parse_ss_output(out)
    details = []
    for s in sockets:
        proto = s["proto"].upper()
        addr = s["addr"]
        port = s["port"]
        process = s["process"] or "unknown"
        pid = s["pid"] or "0"
        local_display = f"[{addr}]:{port}" if ":" in addr and not addr.startswith("0.") else f"{addr}:{port}"
        line = f"{proto}  {local_display}  {process} (pid {pid})"
        details.append(line)

    current_value = f"{len(sockets)} listening socket(s)"
    return make_check(
        "NET-001",
        "network",
        "Listening TCP/UDP sockets (ss -tulnpH)",
        STATUS_INFO,
        "Enumerates every TCP and UDP socket currently in LISTEN state, "
        "showing the protocol, local address and port, peer address, "
        "and the owning process name and PID.",
        "Without a complete inventory of listening sockets, an administrator "
        "cannot tell which services are reachable from the network, making it "
        "easy to miss a forgotten database or cache server that is exposed "
        "to the world.",
        "ss -tulnpH",
        current_value,
        "Review each socket and confirm every listening service is intentional.",
        details=details,
        remediation_id=None,
        manual_command="ss -tulnpH",
    )


def check_net_002():
    """NET-002: Dangerous services exposed on all interfaces."""
    cmd = ["ss", "-tulnpH"]
    res = run_cmd(cmd)
    rc, out, err = res.returncode, res.stdout, res.stderr

    if rc == 127:
        return skipped_check(
            "NET-002",
            "network",
            "Dangerous services exposed on all interfaces (0.0.0.0 / ::)",
            "Scans all listening sockets and flags well-known backend services "
            "(PostgreSQL, MySQL, Redis, MongoDB, Elasticsearch, Memcached, CouchDB, "
            "SQL Server, RDP, VNC, Docker API, etcd, Kubelet) that are bound to "
            "0.0.0.0, ::, or * instead of 127.0.0.1.",
            "A database or cache engine listening on all interfaces is reachable "
            "from any host on the network. An attacker who scans the subnet can "
            "connect directly, read or modify data, and often escalate privileges "
            "through SQL injection or unauthenticated admin APIs.",
            "ss -tulnpH",
            "ss binary not found; install iproute2 (apt install iproute2)",
        )

    if rc != 0:
        return skipped_check(
            "NET-002",
            "network",
            "Dangerous services exposed on all interfaces (0.0.0.0 / ::)",
            "Scans all listening sockets and flags well-known backend services "
            "(PostgreSQL, MySQL, Redis, MongoDB, Elasticsearch, Memcached, CouchDB, "
            "SQL Server, RDP, VNC, Docker API, etcd, Kubelet) that are bound to "
            "0.0.0.0, ::, or * instead of 127.0.0.1.",
            "A database or cache engine listening on all interfaces is reachable "
            "from any host on the network. An attacker who scans the subnet can "
            "connect directly, read or modify data, and often escalate privileges "
            "through SQL injection or unauthenticated admin APIs.",
            "ss -tulnpH",
            f"ss returned error: {err.strip()}",
        )

    sockets = _parse_ss_output(out)
    dangerous = []
    try:
        cfg = get_config()
    except Exception:
        cfg = None

    for s in sockets:
        addr = s["addr"]
        port = s["port"]
        if not (_is_exposed_to_all(addr) and _is_dangerous_port(port)):
            continue
        process = s["process"] or "unknown"
        pid = s["pid"] or "0"
        proto = s["proto"].upper()
        local_display = f"[{addr}]:{port}" if ":" in addr and not addr.startswith("0.") else f"{addr}:{port}"

        allowed = False
        if cfg is not None:
            try:
                port_int = int(port)
                allow_entry = cfg.allowed_listener(port_int, process)
                if allow_entry is not None:
                    allowed = True
            except (ValueError, TypeError):
                pass
            except Exception as exc:
                logger.warning("allowed_listener failed for port %s process %s: %s", port, process, exc)

        if allowed:
            continue

        dangerous.append(f"{proto}  {local_display}  {process} (pid {pid})")

    if dangerous:
        status = STATUS_CRITICAL
        current_value = f"{len(dangerous)} dangerous service(s) on all interfaces"
        recommended = "Bind these services to 127.0.0.1 or use UFW to restrict access."
    else:
        status = STATUS_PASS
        current_value = "No dangerous services bound to all interfaces"
        recommended = "Keep backend services bound to 127.0.0.1."

    return make_check(
        "NET-002",
        "network",
        "Dangerous services exposed on all interfaces (0.0.0.0 / ::)",
        status,
        "Scans all listening sockets and flags well-known backend services "
        "(PostgreSQL, MySQL, Redis, MongoDB, Elasticsearch, Memcached, CouchDB, "
        "SQL Server, RDP, VNC, Docker API, etcd, Kubelet) that are bound to "
        "0.0.0.0, ::, or * instead of 127.0.0.1.",
        "A database or cache engine listening on all interfaces is reachable "
        "from any host on the network. An attacker who scans the subnet can "
        "connect directly, read or modify data, and often escalate privileges "
        "through SQL injection or unauthenticated admin APIs.",
        "ss -tulnpH",
        current_value,
        recommended,
        details=dangerous,
        remediation_id=None,
        manual_command="ss -tulnpH | grep -E ':(2375|2376|3306|5432|6379|27017|9200|9300|11211|5984|1433|3389|5900|2379|10250)\\s'",
    )


def check_net_003():
    """NET-003: Firewall backend detection and INPUT chain policy evaluation."""
    from firewall import detect_firewall, evaluate_firewall

    info = detect_firewall()
    eval_result = evaluate_firewall(info)

    status = eval_result["status"]
    current_value = eval_result["current_value"]
    recommended = eval_result["recommended"]
    details = eval_result["details"]

    # Determine manual command based on backend
    if info.backend == "ufw":
        manual_cmd = "ufw default deny incoming && ufw default allow outgoing && ufw enable"
    elif info.backend.startswith("iptables"):
        manual_cmd = "iptables -P INPUT DROP && iptables -A INPUT -j REJECT --reject-with icmp-host-prohibited"
    elif info.backend == "nftables":
        manual_cmd = "nft add rule inet filter input ct state established,related accept && nft add rule inet filter input tcp dport 22 accept"
    elif info.backend == "firewalld":
        manual_cmd = "firewall-cmd --set-default-zone=drop && firewall-cmd --add-port=22/tcp --permanent"
    else:
        manual_cmd = "apt install ufw && ufw default deny incoming && ufw default allow outgoing && ufw enable"

    return make_check(
        "NET-003",
        "network",
        "Firewall backend detection and INPUT chain policy",
        status,
        "Detects the active firewall backend (nftables, iptables, UFW, or firewalld) "
        "and evaluates the INPUT chain default policy and final rule. "
        "A firewall is considered secure if the default policy is DROP or if there "
        "is a final REJECT/DROP rule.",
        "Without an active firewall with a default-deny incoming policy, "
        "every port that a local service opens is reachable from the network. "
        "An attacker can probe all 65535 ports and find any forgotten service.",
        "firewall.py detect_firewall()",
        current_value,
        recommended,
        details=details,
        remediation_id="ufw_baseline",
        manual_command=manual_cmd,
    )


def check_net_004():
    """NET-004: Docker published ports bypassing UFW (DOCKER-USER chain)."""
    from docker_ports import assess_docker_ports

    result = assess_docker_ports()
    status = result["status"]
    current_value = result["current_value"]
    recommended = result["recommended"]
    details = result["details"]

    if status == STATUS_SKIPPED:
        return make_check(
            "NET-004",
            "network",
            "Docker published ports bypassing UFW (DOCKER-USER chain)",
            STATUS_PASS,
            "Docker is not installed on this system, so there are no container "
            "published ports that could bypass the UFW firewall rules. "
            "This check is informational when Docker is absent.",
            "If Docker were present, published ports (-p flag) create iptables "
            "rules in the DOCKER chain that are evaluated before UFW rules in "
            "the DOCKER-USER chain. Without isolation rules in DOCKER-USER, "
            "container ports are directly reachable from the network, bypassing "
            "any UFW restrictions an administrator may have configured.",
            "docker --version; iptables -L DOCKER-USER -n -v; docker ps --format '{{.Names}} {{.Ports}}'",
            current_value,
            "No action needed while Docker is absent.",
            details=details,
            remediation_id="docker_user_isolation",
            manual_command="",
        )

    manual_cmd = "iptables -I DOCKER-USER -j RETURN -m comment --comment 'SecurityWizard: allow established' && iptables -I DOCKER-USER -j ACCEPT -m state --state ESTABLISHED,RELATED && iptables -I DOCKER-USER -j DROP -m comment --comment 'SecurityWizard: drop all other'"

    return make_check(
        "NET-004",
        "network",
        "Docker published ports bypassing UFW (DOCKER-USER chain)",
        status,
        "Checks whether Docker's DOCKER-USER iptables chain contains "
        "isolation rules that restrict access to container published ports "
        "before they reach the UFW firewall. Without these rules, published "
        "ports bypass UFW entirely.",
        "Docker inserts iptables rules in the DOCKER chain for published "
        "ports, and these are evaluated before the DOCKER-USER chain. If "
        "DOCKER-USER only has the default RETURN rule, container ports are "
        "directly reachable from the network, bypassing any UFW restrictions.",
        "iptables -L DOCKER-USER -n -v; docker ps --format '{{.Names}} {{.Ports}}'",
        current_value,
        recommended,
        details=details,
        remediation_id="docker_user_isolation",
        manual_command=manual_cmd,
    )


def run_checks() -> list:
    """Run all network category checks and return a list of result dicts."""
    checks = []

    try:
        checks.append(check_net_001())
    except Exception as e:
        checks.append(
            skipped_check(
                "NET-001",
                "network",
                "Listening TCP/UDP sockets (ss -tulnpH)",
                "Enumerates every TCP and UDP socket currently in LISTEN state.",
                "Without a socket inventory, exposed services go unnoticed.",
                "ss -tulnpH",
                f"Unexpected error: {e}",
            )
        )

    try:
        checks.append(check_net_002())
    except Exception as e:
        checks.append(
            skipped_check(
                "NET-002",
                "network",
                "Dangerous services exposed on all interfaces (0.0.0.0 / ::)",
                "Flags backend services bound to all interfaces instead of loopback.",
                "Exposed databases and caches are reachable from any network host.",
                "ss -tulnpH",
                f"Unexpected error: {e}",
            )
        )

    try:
        checks.append(check_net_003())
    except Exception as e:
        checks.append(
            skipped_check(
                "NET-003",
                "network",
                "UFW firewall status and default policies",
                "Checks UFW active state and default incoming policy.",
                "Without default-deny incoming, all open ports are reachable.",
                "ufw status verbose",
                f"Unexpected error: {e}",
                remediation_id="ufw_baseline",
            )
        )

    try:
        checks.append(check_net_004())
    except Exception as e:
        checks.append(
            skipped_check(
                "NET-004",
                "network",
                "Docker published ports bypassing UFW (DOCKER-USER chain)",
                "Checks if Docker published ports bypass UFW via DOCKER-USER chain.",
                "Container ports can bypass firewall rules entirely.",
                "iptables -L DOCKER-USER -n -v; docker ps",
                f"Unexpected error: {e}",
                remediation_id="docker_user_isolation",
            )
        )

    return checks
