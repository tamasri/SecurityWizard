"""docker_ports.py — Docker published ports vs DOCKER-USER chain.

Provides a single function ``assess_docker_ports()`` that returns a dict with
``status``, ``current_value``, ``recommended``, and ``details``.  It is used by
``checks_network.check_net_004`` and can also be called directly from tests.

The function:
  1. Detects whether Docker is installed.
  2. Retrieves the list of published ports bound to 0.0.0.0 or ::.
  3. Parses the DOCKER-USER chain (iptables or nftables).
  4. For each published port, decides whether it is protected by a DROP/REJECT
     rule in DOCKER-USER or explicitly allowlisted via config.
  5. Returns a status dict.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional

from common import run_cmd, STATUS_PASS, STATUS_WARNING, STATUS_CRITICAL, STATUS_SKIPPED
from config import get_config

logger = logging.getLogger(__name__)


def _is_docker_installed() -> bool:
    """Return True if the docker binary is available."""
    rc, _, _ = run_cmd(["docker", "--version"])
    return rc == 0


def _get_published_ports() -> List[Dict[str, Any]]:
    """Return a list of dicts describing each published port on 0.0.0.0 or ::.

    Each dict has keys: container, host_ip, host_port, container_port, protocol.
    """
    rc, out, err = run_cmd(
        ["docker", "ps", "--format", "{{json .}}"]
    )
    if rc != 0:
        logger.warning("docker ps failed: %s", err.strip())
        return []

    ports: List[Dict[str, Any]] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse docker ps JSON: %s", e)
            continue

        name = data.get("Names", "").strip()
        port_info = data.get("Ports", "")

        # Parse the Ports field, e.g. "0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp"
        for part in port_info.split(","):
            part = part.strip()
            if not part:
                continue
            # Expect format like "host_ip:host_port->container_port/proto"
            m = re.match(
                r"^(\[?[\d.]+|\[?[\da-f:]+\]?|\*|::)?:(\d+)->(\d+)/(tcp|udp|sctp)$",
                part
            )
            if m:
                raw_ip = m.group(1) or "0.0.0.0"
                host_ip = raw_ip.strip("[]")
                host_port = int(m.group(2))
                container_port = int(m.group(3))
                protocol = m.group(4)
                ports.append({
                    "container": name,
                    "host_ip": host_ip,
                    "host_port": host_port,
                    "container_port": container_port,
                    "protocol": protocol,
                })

    return ports


def _parse_iptables_docker_user() -> List[Dict[str, Any]]:
    """Parse `iptables -S DOCKER-USER` output into a list of rule dicts.

    Each dict has keys: protocol, dport, ct_orig_dst_port, ct_orig_dst,
    interface, target, comment.
    """
    rc, out, err = run_cmd(["iptables", "-S", "DOCKER-USER"])
    if rc != 0:
        logger.warning("iptables -S DOCKER-USER failed: %s", err.strip())
        return []

    rules: List[Dict[str, Any]] = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("-N DOCKER-USER") or line.startswith("-P DOCKER-USER"):
            continue

        # Parse iptables rule line
        # Example: -A DOCKER-USER -m conntrack --ctorigdstport 80 -j DROP
        # Example: -A DOCKER-USER -p tcp --dport 80 -j ACCEPT
        # Example: -A DOCKER-USER -i eth0 -j DROP
        # Example: -A DOCKER-USER -j RETURN

        protocol = None
        dport = None
        ct_orig_dst_port = None
        ct_orig_dst = None
        interface = None
        target = None
        comment = None

        tokens = line.split()
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok == "-p":
                i += 1
                if i < len(tokens):
                    protocol = tokens[i]
            elif tok == "--dport":
                i += 1
                if i < len(tokens):
                    dport = tokens[i]
            elif tok == "--ctorigdstport":
                i += 1
                if i < len(tokens):
                    ct_orig_dst_port = tokens[i]
            elif tok == "--ctorigdst":
                i += 1
                if i < len(tokens):
                    ct_orig_dst = tokens[i]
            elif tok == "-i":
                i += 1
                if i < len(tokens):
                    interface = tokens[i]
            elif tok == "-j":
                i += 1
                if i < len(tokens):
                    target = tokens[i]
            elif tok == "-m":
                # Skip the match module name
                i += 1
            elif tok == "--comment":
                i += 1
                if i < len(tokens):
                    comment = tokens[i].strip("'")
            i += 1

        rules.append({
            "protocol": protocol,
            "dport": dport,
            "ct_orig_dst_port": ct_orig_dst_port,
            "ct_orig_dst": ct_orig_dst,
            "interface": interface,
            "target": target,
            "comment": comment,
        })

    return rules


def _parse_nft_docker_user() -> List[Dict[str, Any]]:
    """Parse `nft list chain ip filter DOCKER-USER` output into a list of rule dicts.

    Each dict has keys: protocol, dport, ct_orig_dst_port, ct_orig_dst,
    interface, target, comment.
    """
    rc, out, err = run_cmd(["nft", "list", "chain", "ip", "filter", "DOCKER-USER"])
    if rc != 0:
        logger.warning("nft list chain ip filter DOCKER-USER failed: %s", err.strip())
        return []

    rules: List[Dict[str, Any]] = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("chain") or line.startswith("policy"):
            continue

        # Parse nft rule line
        # Example: tcp dport 80 ct original proto-dst 80 drop
        # Example: ct original proto-dst 80 drop
        # Example: iifname "eth0" drop
        # Example: return

        protocol = None
        dport = None
        ct_orig_dst_port = None
        ct_orig_dst = None
        interface = None
        target = None
        comment = None

        # Look for protocol
        if line.startswith("tcp "):
            protocol = "tcp"
        elif line.startswith("udp "):
            protocol = "udp"
        elif line.startswith("sctp "):
            protocol = "sctp"

        # Look for dport
        m = re.search(r"dport\s+(\d+)", line)
        if m:
            dport = m.group(1)

        # Look for ct original proto-dst
        m = re.search(r"ct\s+original\s+proto-dst\s+(\d+)", line)
        if m:
            ct_orig_dst_port = m.group(1)

        # Look for ct original dst
        m = re.search(r"ct\s+original\s+dst\s+(\S+)", line)
        if m:
            ct_orig_dst = m.group(1)

        # Look for interface
        m = re.search(r'iifname\s+"?(\S+?)"?\s', line)
        if m:
            interface = m.group(1)

        # Look for target (last word)
        words = line.split()
        if words:
            last = words[-1]
            if last in ("drop", "reject", "accept", "return"):
                target = last.upper()
            elif last in ("DROP", "REJECT", "ACCEPT", "RETURN"):
                target = last

        # Look for comment
        m = re.search(r'comment\s+"([^"]+)"', line)
        if m:
            comment = m.group(1)

        rules.append({
            "protocol": protocol,
            "dport": dport,
            "ct_orig_dst_port": ct_orig_dst_port,
            "ct_orig_dst": ct_orig_dst,
            "interface": interface,
            "target": target,
            "comment": comment,
        })

    return rules


def _is_protected(
    port: int,
    protocol: str,
    rules: List[Dict[str, Any]],
) -> bool:
    """Return True if the port is dropped or rejected in DOCKER-USER.

    A port is protected if there is a rule with target DROP or REJECT that
    matches the port via dport or ct_orig_dst_port, or if there is a blanket
    DROP/REJECT rule at the end of the chain after an ESTABLISHED/RELATED accept.
    """
    # Check for explicit port match
    for rule in rules:
        target = rule.get("target")
        if target not in ("DROP", "REJECT"):
            continue

        dport = rule.get("dport")
        ct_port = rule.get("ct_orig_dst_port")
        ct_dst = rule.get("ct_orig_dst")
        proto = rule.get("protocol")

        # If the rule specifies a protocol, it must match
        if proto and proto != protocol:
            continue

        # Match by dport
        if dport:
            try:
                if int(dport) == port:
                    return True
            except ValueError:
                pass

        # Match by ct_orig_dst_port
        if ct_port:
            try:
                if int(ct_port) == port:
                    return True
            except ValueError:
                pass

        # Match by ct_orig_dst (IP address)
        if ct_dst:
            # If ct_orig_dst is an IP, it means the rule applies to traffic
            # destined for that IP. Published ports are typically 0.0.0.0 or ::,
            # so this is less common but we handle it.
            pass

    # Check for blanket DROP/REJECT at the end (after ESTABLISHED/RELATED accept)
    # This pattern is common: ACCEPT ESTABLISHED,RELATED then DROP everything else
    has_established_accept = False
    for rule in rules:
        target = rule.get("target")
        if target == "ACCEPT":
            comment = rule.get("comment") or ""
            if "ESTABLISHED" in comment or "RELATED" in comment:
                has_established_accept = True
                break

    if has_established_accept:
        # Check if the last rule is DROP or REJECT
        for rule in reversed(rules):
            target = rule.get("target")
            if target in ("DROP", "REJECT"):
                return True
            if target == "ACCEPT":
                # If we hit an ACCEPT before the end, the blanket DROP doesn't cover it
                break

    return False


def assess_docker_ports() -> Dict[str, Any]:
    """Assess Docker published ports vs DOCKER-USER chain.

    Returns a dict with keys: status, current_value, recommended, details.
    """
    # Check if Docker is installed
    if not _is_docker_installed():
        return {
            "status": STATUS_SKIPPED,
            "current_value": "Docker is not installed on this host.",
            "recommended": "",
            "details": ["Docker is not installed on this host."],
        }

    # Get published ports
    ports = _get_published_ports()

    # Only consider ports bound to 0.0.0.0 or ::
    public_ports = [p for p in ports if p["host_ip"] in ("0.0.0.0", "::", "*")]

    if not public_ports:
        return {
            "status": STATUS_PASS,
            "current_value": "No Docker published ports on 0.0.0.0 or ::",
            "recommended": "Keep container ports bound to 127.0.0.1 or add DOCKER-USER isolation rules.",
            "details": ["No Docker containers with published ports on 0.0.0.0 or ::."],
        }

    # Try to parse DOCKER-USER chain
    rules = _parse_iptables_docker_user()
    if not rules:
        rules = _parse_nft_docker_user()

    if not rules:
        # Could not parse DOCKER-USER chain
        return {
            "status": STATUS_WARNING,
            "current_value": f"{len(public_ports)} published port(s) on 0.0.0.0 or ::, DOCKER-USER chain not found",
            "recommended": "Ensure DOCKER-USER chain exists and contains isolation rules.",
            "details": [f"{len(public_ports)} published port(s) on 0.0.0.0 or ::, but DOCKER-USER chain could not be parsed."],
        }

    # Check each port
    unprotected = []
    protected = []
    allowlisted = []

    cfg = get_config()

    for p in public_ports:
        port = p["host_port"]
        protocol = p["protocol"]
        container = p["container"]

        # Check if allowlisted
        allow = cfg.allowed_public_port(port, container)
        if allow:
            allowlisted.append(f"{container} port {port}/{protocol} (allowlisted)")
            continue

        # Check if protected by DOCKER-USER
        if _is_protected(port, protocol, rules):
            protected.append(f"{container} port {port}/{protocol} (protected by DOCKER-USER)")
        else:
            unprotected.append(f"{container} port {port}/{protocol} (unprotected)")

    details = []
    if allowlisted:
        details.append("Allowlisted ports:")
        details.extend(allowlisted)
    if protected:
        details.append("Protected ports:")
        details.extend(protected)
    if unprotected:
        details.append("Unprotected ports:")
        details.extend(unprotected)

    if unprotected:
        status = STATUS_CRITICAL
        current_value = f"{len(unprotected)} unprotected published port(s) on 0.0.0.0 or ::"
        recommended = "Add DOCKER-USER chain rules to restrict access to unprotected container ports."
    elif allowlisted or protected:
        status = STATUS_PASS
        current_value = f"All {len(public_ports)} published port(s) on 0.0.0.0 or :: are allowlisted or protected"
        recommended = "Keep container ports bound to 127.0.0.1 or add DOCKER-USER isolation rules."
    else:
        status = STATUS_WARNING
        current_value = f"{len(public_ports)} published port(s) on 0.0.0.0 or ::, DOCKER-USER chain rules not matching"
        recommended = "Review DOCKER-USER chain rules to ensure they cover all published ports."

    return {
        "status": status,
        "current_value": current_value,
        "recommended": recommended,
        "details": details,
    }
