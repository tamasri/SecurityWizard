"""checks_network.py — Network Surface, Ports & Firewall Auditor.

Implements the 'network' category checks:
  NET-001  Listening TCP/UDP sockets (ss -tulpn)
  NET-002  Dangerous services exposed on all interfaces (0.0.0.0 / ::)
  NET-003  UFW firewall status and default policies
  NET-004  Docker published ports bypassing UFW (DOCKER-USER chain)
"""

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


def _parse_ss_output(output: str) -> list:
    """Parse ss -tulpn output into a list of dicts.

    Each dict has keys: proto, state, local, remote, process, pid.
    """
    results = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        # Skip the header line
        if line.startswith("State") or line.startswith("Netid"):
            continue

        parts = line.split()
        if len(parts) < 4:
            continue

        proto = parts[0]
        # ss -tulpn output columns:
        # State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
        # or: Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
        # UDP lines have no state column, so shift indices.
        if proto.upper() in ("UDP", "UDP-LITE"):
            # No state column for UDP
            recv_q = parts[1]
            send_q = parts[2]
            local = parts[3]
            remote = parts[4] if len(parts) > 4 else "*"
            process_part = parts[5] if len(parts) > 5 else ""
        else:
            # TCP has a state column
            state = parts[1]
            recv_q = parts[2]
            send_q = parts[3]
            local = parts[4]
            remote = parts[5] if len(parts) > 5 else "*"
            process_part = parts[6] if len(parts) > 6 else ""

        # Extract process name and PID from process_part
        process_name = ""
        pid = ""
        if process_part:
            # Format: users:(("name",pid=123,fd=4))
            if "users:" in process_part:
                inner = process_part.split("users:")[-1].strip()
                # inner looks like (("name",pid=123,fd=4))
                # Extract name between first ( and first ,
                inner_stripped = inner.strip("()")
                if "," in inner_stripped:
                    name_part = inner_stripped.split(",")[0].strip().strip('"')
                    process_name = name_part
                # Extract pid
                if "pid=" in inner_stripped:
                    pid_part = inner_stripped.split("pid=")[-1]
                    pid = pid_part.split(",")[0].strip(")")

        # Parse local address and port
        # local can be like "0.0.0.0:80", "[::]:80", "127.0.0.1:5432", "*:80"
        if ":" in local:
            # Split on the last colon to handle IPv6
            addr, port = local.rsplit(":", 1)
            # Remove brackets from IPv6 addresses
            addr = addr.strip("[]")
        else:
            addr = local
            port = ""

        results.append({
            "proto": proto,
            "state": parts[1] if proto.upper() not in ("UDP", "UDP-LITE") else "",
            "local": local,
            "remote": remote,
            "process": process_name,
            "pid": pid,
            "addr": addr,
            "port": port,
        })

    return results


def _is_dangerous_port(port: str) -> bool:
    """Return True if the port is in the dangerous services list."""
    try:
        p = int(port)
    except (ValueError, TypeError):
        return False
    dangerous_ports = {
        2375, 2376, 3306, 5432, 6379,
        27017, 9200, 11211, 5984, 1433, 3389, 5900,
    }
    return p in dangerous_ports


def _is_exposed_to_all(addr: str) -> bool:
    """Return True if the address binds to all interfaces."""
    return addr in ("0.0.0.0", "::", "*")


def check_net_001():
    """NET-001: Listening TCP/UDP sockets (ss -tulpn)."""
    cmd = ["ss", "-tulpn"]
    rc, out, err = run_cmd(cmd)

    if rc == 127:
        return skipped_check(
            "NET-001", "network",
            "Listening TCP/UDP sockets (ss -tulpn)",
            "Enumerates every TCP and UDP socket currently in LISTEN state, "
            "showing the protocol, local address and port, peer address, "
            "and the owning process name and PID.",
            "Without a complete inventory of listening sockets, an administrator "
            "cannot tell which services are reachable from the network, making it "
            "easy to miss a forgotten database or cache server that is exposed "
            "to the world.",
            "ss -tulpn",
            "ss binary not found; install iproute2 (apt install iproute2)",
        )

    if rc != 0:
        return skipped_check(
            "NET-001", "network",
            "Listening TCP/UDP sockets (ss -tulpn)",
            "Enumerates every TCP and UDP socket currently in LISTEN state, "
            "showing the protocol, local address and port, peer address, "
            "and the owning process name and PID.",
            "Without a complete inventory of listening sockets, an administrator "
            "cannot tell which services are reachable from the network, making it "
            "easy to miss a forgotten database or cache server that is exposed "
            "to the world.",
            "ss -tulpn",
            f"ss returned error: {err.strip()}",
        )

    sockets = _parse_ss_output(out)
    details = []
    for s in sockets:
        proto = s["proto"].upper()
        local = s["local"]
        process = s["process"] or "unknown"
        pid = s["pid"] or "0"
        state = s.get("state", "")
        if proto.startswith("TCP"):
            line = f"TCP  {local}  {process} (pid {pid})"
            if state:
                line += f"  [{state}]"
        else:
            line = f"{proto}  {local}  {process} (pid {pid})"
        details.append(line)

    current_value = f"{len(sockets)} listening socket(s)"
    return make_check(
        "NET-001", "network",
        "Listening TCP/UDP sockets (ss -tulpn)",
        STATUS_INFO,
        "Enumerates every TCP and UDP socket currently in LISTEN state, "
        "showing the protocol, local address and port, peer address, "
        "and the owning process name and PID.",
        "Without a complete inventory of listening sockets, an administrator "
        "cannot tell which services are reachable from the network, making it "
        "easy to miss a forgotten database or cache server that is exposed "
        "to the world.",
        "ss -tulpn",
        current_value,
        "Review each socket and confirm every listening service is intentional.",
        details=details,
        remediation_id=None,
        manual_command="ss -tulpn",
    )


def check_net_002():
    """NET-002: Dangerous services exposed on all interfaces."""
    cmd = ["ss", "-tulpn"]
    rc, out, err = run_cmd(cmd)

    if rc == 127:
        return skipped_check(
            "NET-002", "network",
            "Dangerous services exposed on all interfaces (0.0.0.0 / ::)",
            "Scans all listening sockets and flags well-known backend services "
            "(PostgreSQL, MySQL, Redis, MongoDB, Elasticsearch, Memcached, CouchDB, "
            "SQL Server, RDP, VNC, Docker API) that are bound to 0.0.0.0, ::, or * "
            "instead of 127.0.0.1.",
            "A database or cache engine listening on all interfaces is reachable "
            "from any host on the network. An attacker who scans the subnet can "
            "connect directly, read or modify data, and often escalate privileges "
            "through SQL injection or unauthenticated admin APIs.",
            "ss -tulpn",
            "ss binary not found; install iproute2 (apt install iproute2)",
        )

    if rc != 0:
        return skipped_check(
            "NET-002", "network",
            "Dangerous services exposed on all interfaces (0.0.0.0 / ::)",
            "Scans all listening sockets and flags well-known backend services "
            "(PostgreSQL, MySQL, Redis, MongoDB, Elasticsearch, Memcached, CouchDB, "
            "SQL Server, RDP, VNC, Docker API) that are bound to 0.0.0.0, ::, or * "
            "instead of 127.0.0.1.",
            "A database or cache engine listening on all interfaces is reachable "
            "from any host on the network. An attacker who scans the subnet can "
            "connect directly, read or modify data, and often escalate privileges "
            "through SQL injection or unauthenticated admin APIs.",
            "ss -tulpn",
            f"ss returned error: {err.strip()}",
        )

    sockets = _parse_ss_output(out)
    dangerous = []
    for s in sockets:
        addr = s["addr"]
        port = s["port"]
        if _is_exposed_to_all(addr) and _is_dangerous_port(port):
            process = s["process"] or "unknown"
            pid = s["pid"] or "0"
            proto = s["proto"].upper()
            dangerous.append(f"{proto}  {s['local']}  {process} (pid {pid})  port {port}")

    if dangerous:
        status = STATUS_CRITICAL
        current_value = f"{len(dangerous)} dangerous service(s) on all interfaces"
        recommended = "Bind these services to 127.0.0.1 or use UFW to restrict access."
    else:
        status = STATUS_PASS
        current_value = "No dangerous services bound to all interfaces"
        recommended = "Keep backend services bound to 127.0.0.1."

    return make_check(
        "NET-002", "network",
        "Dangerous services exposed on all interfaces (0.0.0.0 / ::)",
        status,
        "Scans all listening sockets and flags well-known backend services "
        "(PostgreSQL, MySQL, Redis, MongoDB, Elasticsearch, Memcached, CouchDB, "
        "SQL Server, RDP, VNC, Docker API) that are bound to 0.0.0.0, ::, or * "
        "instead of 127.0.0.1.",
        "A database or cache engine listening on all interfaces is reachable "
        "from any host on the network. An attacker who scans the subnet can "
        "connect directly, read or modify data, and often escalate privileges "
        "through SQL injection or unauthenticated admin APIs.",
        "ss -tulpn",
        current_value,
        recommended,
        details=dangerous,
        remediation_id=None,
        manual_command="ss -tulpn | grep -E ':(2375|2376|3306|5432|6379|27017|9200|11211|5984|1433|3389|5900)\\s'",
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
        "NET-003", "network",
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
    # First check if docker is available
    rc_docker, _, err_docker = run_cmd(["docker", "--version"])
    if rc_docker == 127:
        return make_check(
            "NET-004", "network",
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
            "Docker not installed; no container ports to check.",
            "No action needed while Docker is absent.",
            details=["Docker is not installed on this host."],
            remediation_id="docker_user_isolation",
            manual_command="",
        )

    # Docker is installed; check DOCKER-USER chain
    rc_ipt, out_ipt, err_ipt = run_cmd(["iptables", "-L", "DOCKER-USER", "-n", "-v"])
    if rc_ipt != 0:
        return skipped_check(
            "NET-004", "network",
            "Docker published ports bypassing UFW (DOCKER-USER chain)",
            "Checks whether Docker's DOCKER-USER iptables chain contains "
            "isolation rules that restrict access to container published ports "
            "before they reach the UFW firewall. Without these rules, published "
            "ports bypass UFW entirely.",
            "Docker inserts iptables rules in the DOCKER chain for published "
            "ports, and these are evaluated before the DOCKER-USER chain. If "
            "DOCKER-USER only has the default RETURN rule, container ports are "
            "directly reachable from the network, bypassing any UFW restrictions.",
            "iptables -L DOCKER-USER -n -v",
            f"iptables returned error: {err_ipt.strip()}",
            remediation_id="docker_user_isolation",
        )

    # Check if DOCKER-USER has only the default RETURN rule
    has_only_return = True
    for line in out_ipt.splitlines():
        if line.strip().startswith("RETURN") and "0" in line:
            continue
        if line.strip().startswith("Chain DOCKER-USER"):
            continue
        if line.strip().startswith("target") or line.strip().startswith("pkts"):
            continue
        has_only_return = False
        break

    # Check for published ports
    rc_ps, out_ps, _ = run_cmd(["docker", "ps", "--format", "{{.Names}} {{.Ports}}"])
    published_ports = []
    if rc_ps == 0:
        for line in out_ps.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                port_str = parts[-1]
                if "0.0.0.0" in port_str or "::" in port_str:
                    published_ports.append(line)

    if published_ports and has_only_return:
        status = STATUS_CRITICAL
        current_value = f"{len(published_ports)} published port(s) on 0.0.0.0, DOCKER-USER has only RETURN"
        recommended = "Add DOCKER-USER chain rules to restrict access to container ports."
        manual_cmd = "iptables -I DOCKER-USER -j RETURN -m comment --comment 'SecurityWizard: allow established' && iptables -I DOCKER-USER -j ACCEPT -m state --state ESTABLISHED,RELATED && iptables -I DOCKER-USER -j DROP -m comment --comment 'SecurityWizard: drop all other'"
    elif published_ports:
        status = STATUS_WARNING
        current_value = f"{len(published_ports)} published port(s) on 0.0.0.0, DOCKER-USER has isolation rules"
        recommended = "Review DOCKER-USER chain rules to ensure they cover all published ports."
        manual_cmd = "iptables -L DOCKER-USER -n -v"
    else:
        status = STATUS_PASS
        current_value = "No Docker published ports on 0.0.0.0"
        recommended = "Keep container ports bound to 127.0.0.1 or add DOCKER-USER isolation rules."
        manual_cmd = ""

    details = []
    if published_ports:
        details.append("Published ports on 0.0.0.0:")
        details.extend(published_ports)
    else:
        details.append("No Docker containers with published ports on 0.0.0.0.")
    if has_only_return:
        details.append("DOCKER-USER chain contains only the default RETURN rule.")
    else:
        details.append("DOCKER-USER chain contains custom isolation rules.")

    return make_check(
        "NET-004", "network",
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
        checks.append(skipped_check(
            "NET-001", "network",
            "Listening TCP/UDP sockets (ss -tulpn)",
            "Enumerates every TCP and UDP socket currently in LISTEN state.",
            "Without a socket inventory, exposed services go unnoticed.",
            "ss -tulpn",
            f"Unexpected error: {e}",
        ))

    try:
        checks.append(check_net_002())
    except Exception as e:
        checks.append(skipped_check(
            "NET-002", "network",
            "Dangerous services exposed on all interfaces (0.0.0.0 / ::)",
            "Flags backend services bound to all interfaces instead of loopback.",
            "Exposed databases and caches are reachable from any network host.",
            "ss -tulpn",
            f"Unexpected error: {e}",
        ))

    try:
        checks.append(check_net_003())
    except Exception as e:
        checks.append(skipped_check(
            "NET-003", "network",
            "UFW firewall status and default policies",
            "Checks UFW active state and default incoming policy.",
            "Without default-deny incoming, all open ports are reachable.",
            "ufw status verbose",
            f"Unexpected error: {e}",
            remediation_id="ufw_baseline",
        ))

    try:
        checks.append(check_net_004())
    except Exception as e:
        checks.append(skipped_check(
            "NET-004", "network",
            "Docker published ports bypassing UFW (DOCKER-USER chain)",
            "Checks if Docker published ports bypass UFW via DOCKER-USER chain.",
            "Container ports can bypass firewall rules entirely.",
            "iptables -L DOCKER-USER -n -v; docker ps",
            f"Unexpected error: {e}",
            remediation_id="docker_user_isolation",
        ))

    return checks
