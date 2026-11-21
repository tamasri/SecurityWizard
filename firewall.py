"""firewall.py — Firewall backend detection and rule parsing.

Detects the active firewall backend (nftables, iptables-legacy, iptables-nft,
ufw, firewalld) and parses INPUT chain policy and rules into typed data.
"""

import logging
import re
from typing import Any, Dict, List

from common import run_cmd

logger = logging.getLogger(__name__)


class FirewallInfo:
    """Typed data about the detected firewall backend."""

    def __init__(self):
        self.backend: str = ""
        self.active: bool = False
        self.default_policy: str = ""
        self.final_rule: str = ""
        self.accepts_established: bool = False
        self.allowed_ports: List[int] = []
        self.evidence: List[str] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "backend": self.backend,
            "active": self.active,
            "default_policy": self.default_policy,
            "final_rule": self.final_rule,
            "accepts_established": self.accepts_established,
            "allowed_ports": self.allowed_ports,
            "evidence": self.evidence,
        }


def _detect_iptables_version() -> str:
    """Return 'nft', 'legacy', or '' based on iptables --version output."""
    rc, out, err = run_cmd(["iptables", "--version"])
    if rc != 0:
        return ""
    if "(nf_tables)" in out or "nf_tables" in out:
        return "nft"
    if "(legacy)" in out or "legacy" in out:
        return "legacy"
    return ""


def _parse_iptables_input(output: str) -> Dict[str, Any]:
    """Parse `iptables -S INPUT` output.

    Returns a dict with keys: policy, final_rule, accepts_established, allowed_ports.
    """
    policy = ""
    final_rule = ""
    accepts_established = False
    allowed_ports: List[int] = []

    lines = output.splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith("-P INPUT"):
            parts = line.split()
            if len(parts) >= 3:
                policy = parts[2]
        elif line.startswith("-A INPUT"):
            # Check for established/related
            if "ESTABLISHED,RELATED" in line or "state" in line and "RELATED" in line:
                accepts_established = True
            # Check for REJECT or DROP as final rule
            if "REJECT" in line:
                final_rule = "REJECT"
            elif "DROP" in line:
                final_rule = "DROP"
            # Extract allowed ports
            port_match = re.search(r"-dport\s+(\d+)", line)
            if port_match:
                allowed_ports.append(int(port_match.group(1)))
            # Also check for multiport
            multiport_match = re.search(r"-m\s+multiport\s+-p\s+tcp\s+-dports?\s+([\d,\s]+)", line)
            if multiport_match:
                for p in multiport_match.group(1).split(","):
                    p = p.strip()
                    if p.isdigit():
                        allowed_ports.append(int(p))

    return {
        "policy": policy,
        "final_rule": final_rule,
        "accepts_established": accepts_established,
        "allowed_ports": allowed_ports,
    }


def _parse_nft_input(output: str) -> Dict[str, Any]:
    """Parse `nft list chain inet filter input` output.

    Returns a dict with keys: policy, final_rule, accepts_established, allowed_ports.
    """
    policy = ""
    final_rule = ""
    accepts_established = False
    allowed_ports: List[int] = []

    lines = output.splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        # Check for policy declaration
        if "policy" in line:
            policy_match = re.search(r"policy\s+(\w+)", line)
            if policy_match:
                policy = policy_match.group(1).upper()
        # Check for established/related
        if "ct state established,related" in line or "ct state related,established" in line:
            accepts_established = True
        # Check for explicit drop/reject rules (not the policy declaration)
        if re.search(r"\bdrop\b", line) and "policy" not in line:
            final_rule = "DROP"
        elif re.search(r"\breject\b", line) and "policy" not in line:
            final_rule = "REJECT"
        # Extract ports
        port_match = re.search(r"dport\s+(\d+)", line)
        if port_match:
            allowed_ports.append(int(port_match.group(1)))

    return {
        "policy": policy,
        "final_rule": final_rule,
        "accepts_established": accepts_established,
        "allowed_ports": allowed_ports,
    }


def _parse_ufw_status(output: str) -> Dict[str, Any]:
    """Parse `ufw status verbose` output.

    Returns a dict with keys: policy, final_rule, accepts_established, allowed_ports.
    """
    policy = ""
    final_rule = ""
    accepts_established = True  # UFW allows established by default
    allowed_ports: List[int] = []

    lines = output.splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if "Default:" in line:
            # e.g. "Default: deny (incoming), allow (outgoing), disabled (routed)"
            if "deny (incoming)" in line:
                policy = "DROP"
            elif "allow (incoming)" in line:
                policy = "ACCEPT"
        # Extract allowed ports from lines like "22/tcp ALLOW Anywhere"
        port_match = re.search(r"^(\d+)/tcp\s+ALLOW", line)
        if port_match:
            allowed_ports.append(int(port_match.group(1)))
        # Also UDP
        port_match_udp = re.search(r"^(\d+)/udp\s+ALLOW", line)
        if port_match_udp:
            allowed_ports.append(int(port_match_udp.group(1)))

    # UFW doesn't have an explicit final REJECT rule; policy DROP acts as final drop
    if policy == "DROP":
        final_rule = "DROP"

    return {
        "policy": policy,
        "final_rule": final_rule,
        "accepts_established": accepts_established,
        "allowed_ports": allowed_ports,
    }


def detect_firewall() -> FirewallInfo:
    """Detect the active firewall backend and parse INPUT chain rules.

    Returns a FirewallInfo instance with populated fields.
    """
    info = FirewallInfo()

    # Check for nftables
    rc_nft, out_nft, _ = run_cmd(["nft", "list", "ruleset"])
    if rc_nft == 0 and out_nft.strip():
        info.backend = "nftables"
        info.active = True
        parsed = _parse_nft_input(out_nft)
        info.default_policy = parsed["policy"]
        info.final_rule = parsed["final_rule"]
        info.accepts_established = parsed["accepts_established"]
        info.allowed_ports = parsed["allowed_ports"]
        info.evidence.append(f"nftables active, policy={info.default_policy}, final={info.final_rule}")
        return info

    # Check for UFW
    rc_ufw, out_ufw, _ = run_cmd(["ufw", "status", "verbose"])
    if rc_ufw == 0:
        active = "Status: active" in out_ufw
        if active:
            info.backend = "ufw"
            info.active = True
            parsed = _parse_ufw_status(out_ufw)
            info.default_policy = parsed["policy"]
            info.final_rule = parsed["final_rule"]
            info.accepts_established = parsed["accepts_established"]
            info.allowed_ports = parsed["allowed_ports"]
            info.evidence.append(f"UFW active, policy={info.default_policy}, final={info.final_rule}")
            return info

    # Check for firewalld
    rc_fw, out_fw, _ = run_cmd(["firewall-cmd", "--state"])
    if rc_fw == 0 and "running" in out_fw:
        info.backend = "firewalld"
        info.active = True
        info.default_policy = "ACCEPT"  # firewalld default is rich rules, no simple policy
        info.final_rule = ""
        info.accepts_established = True
        info.allowed_ports = []
        info.evidence.append("firewalld active")
        return info

    # Check for iptables (nft or legacy)
    ipt_version = _detect_iptables_version()
    if ipt_version:
        rc_ipt, out_ipt, _ = run_cmd(["iptables", "-S", "INPUT"])
        if rc_ipt == 0:
            info.backend = f"iptables-{ipt_version}"
            info.active = True
            parsed = _parse_iptables_input(out_ipt)
            info.default_policy = parsed["policy"]
            info.final_rule = parsed["final_rule"]
            info.accepts_established = parsed["accepts_established"]
            info.allowed_ports = parsed["allowed_ports"]
            info.evidence.append(
                f"iptables-{ipt_version} active, policy={info.default_policy}, final={info.final_rule}"
            )
            return info

    # No firewall detected
    info.backend = "none"
    info.active = False
    info.evidence.append("No firewall backend detected")
    return info


def evaluate_firewall(info: FirewallInfo) -> Dict[str, Any]:
    """Evaluate the firewall state and return a dict with status and details.

    Returns a dict with keys: status, current_value, recommended, details.
    """
    if not info.active:
        return {
            "status": "CRITICAL",
            "current_value": "No firewall active",
            "recommended": "Install and enable a firewall (nftables, iptables, or UFW).",
            "details": info.evidence,
        }

    if info.default_policy == "DROP" or info.final_rule in ("DROP", "REJECT"):
        return {
            "status": "PASS",
            "current_value": f"{info.backend} active, policy={info.default_policy}, final={info.final_rule or 'none'}",
            "recommended": "Default deny or final reject rule is in place.",
            "details": info.evidence,
        }

    # Policy ACCEPT with no final reject
    if info.default_policy == "ACCEPT":
        return {
            "status": "WARNING",
            "current_value": f"{info.backend} active, policy=ACCEPT, no final reject",
            "recommended": "Set default policy to DROP or add a final REJECT/DROP rule.",
            "details": info.evidence,
        }

    # Unknown policy state
    return {
        "status": "WARNING",
        "current_value": f"{info.backend} active, policy={info.default_policy or 'unknown'}",
        "recommended": "Review firewall policy and rules.",
        "details": info.evidence,
    }
