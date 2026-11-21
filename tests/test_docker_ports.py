"""Tests for docker_ports.py."""

import json
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

from common import STATUS_CRITICAL, STATUS_PASS, STATUS_SKIPPED
from docker_ports import assess_docker_ports


def _make_docker_ps_output(ports: List[Dict[str, Any]]) -> str:
    """Create docker ps --format '{{json .}}' output from a list of port dicts."""
    lines = []
    for p in ports:
        data = {
            "Names": p["container"],
            "Ports": f"0.0.0.0:{p['host_port']}->{p['container_port']}/{p['protocol']}",
        }
        lines.append(json.dumps(data))
    return "\n".join(lines)


def _make_iptables_output(rules: List[Dict[str, Any]]) -> str:
    """Create iptables -S DOCKER-USER output from a list of rule dicts."""
    lines = ["-N DOCKER-USER", "-P DOCKER-USER ACCEPT"]
    for r in rules:
        parts = ["-A", "DOCKER-USER"]
        if r.get("protocol"):
            parts.extend(["-p", r["protocol"]])
        if r.get("dport"):
            parts.extend(["--dport", r["dport"]])
        if r.get("ct_orig_dst_port"):
            parts.extend(["-m", "conntrack", "--ctorigdstport", r["ct_orig_dst_port"]])
        if r.get("ct_orig_dst"):
            parts.extend(["-m", "conntrack", "--ctorigdst", r["ct_orig_dst"]])
        if r.get("interface"):
            parts.extend(["-i", r["interface"]])
        if r.get("comment"):
            parts.extend(["-m", "comment", "--comment", f"'{r['comment']}'"])
        if r.get("target"):
            parts.extend(["-j", r["target"]])
        lines.append(" ".join(parts))
    return "\n".join(lines)


def _make_nft_output(rules: List[Dict[str, Any]]) -> str:
    """Create nft list chain ip filter DOCKER-USER output from a list of rule dicts."""
    lines = ["chain ip filter DOCKER-USER {", "    type filter hook prerouting priority mangle; policy accept;"]
    for r in rules:
        parts = []
        if r.get("protocol"):
            parts.append(r["protocol"])
        if r.get("dport"):
            parts.append(f"dport {r['dport']}")
        if r.get("ct_orig_dst_port"):
            parts.append(f"ct original proto-dst {r['ct_orig_dst_port']}")
        if r.get("ct_orig_dst"):
            parts.append(f"ct original dst {r['ct_orig_dst']}")
        if r.get("interface"):
            parts.append(f'iifname "{r["interface"]}"')
        if r.get("comment"):
            parts.append(f'comment "{r["comment"]}"')
        if r.get("target"):
            parts.append(r["target"].lower())
        lines.append("    " + " ".join(parts))
    lines.append("}")
    return "\n".join(lines)


def test_docker_not_installed():
    """Test that Docker not installed returns SKIPPED."""
    with patch("docker_ports.run_cmd") as mock_run:
        mock_run.return_value = (127, "", "not found")
        result = assess_docker_ports()
        assert result["status"] == STATUS_SKIPPED
        assert "Docker is not installed" in result["current_value"]


def test_no_published_ports():
    """Test that no published ports returns PASS."""
    with patch("docker_ports.run_cmd") as mock_run:
        # First call: docker --version
        mock_run.return_value = (0, "Docker version 24.0.0", "")
        # Second call: docker ps
        mock_run.return_value = (0, "", "")
        result = assess_docker_ports()
        assert result["status"] == STATUS_PASS
        assert "No Docker published ports" in result["current_value"]


def test_protected_host_iptables():
    """Test a protected host with DOCKER-USER DROP rules."""
    ports = [
        {"container": "web", "host_port": 80, "container_port": 80, "protocol": "tcp"},
        {"container": "api", "host_port": 443, "container_port": 443, "protocol": "tcp"},
    ]
    rules = [
        {"protocol": "tcp", "dport": "80", "target": "DROP"},
        {"protocol": "tcp", "dport": "443", "target": "DROP"},
    ]

    def side_effect(cmd, timeout=20):
        if cmd[0] == "docker" and cmd[1] == "--version":
            return (0, "Docker version 24.0.0", "")
        elif cmd[0] == "docker" and cmd[1] == "ps":
            return (0, _make_docker_ps_output(ports), "")
        elif cmd[0] == "iptables":
            return (0, _make_iptables_output(rules), "")
        return (1, "", "unexpected command")

    with patch("docker_ports.run_cmd", side_effect=side_effect):
        result = assess_docker_ports()
        assert result["status"] == STATUS_PASS
        assert "2 published port(s)" in result["current_value"]


def test_unprotected_host_iptables():
    """Test an unprotected host with only RETURN in DOCKER-USER."""
    ports = [
        {"container": "web", "host_port": 80, "container_port": 80, "protocol": "tcp"},
    ]
    rules = [
        {"target": "RETURN"},
    ]

    def side_effect(cmd, timeout=20):
        if cmd[0] == "docker" and cmd[1] == "--version":
            return (0, "Docker version 24.0.0", "")
        elif cmd[0] == "docker" and cmd[1] == "ps":
            return (0, _make_docker_ps_output(ports), "")
        elif cmd[0] == "iptables":
            return (0, _make_iptables_output(rules), "")
        return (1, "", "unexpected command")

    with patch("docker_ports.run_cmd", side_effect=side_effect):
        result = assess_docker_ports()
        assert result["status"] == STATUS_CRITICAL
        assert "1 unprotected published port(s)" in result["current_value"]


def test_allowlisted_port():
    """Test that an allowlisted port is not reported as unprotected."""
    ports = [
        {"container": "web", "host_port": 80, "container_port": 80, "protocol": "tcp"},
    ]
    rules = [
        {"target": "RETURN"},
    ]

    def side_effect(cmd, timeout=20):
        if cmd[0] == "docker" and cmd[1] == "--version":
            return (0, "Docker version 24.0.0", "")
        elif cmd[0] == "docker" and cmd[1] == "ps":
            return (0, _make_docker_ps_output(ports), "")
        elif cmd[0] == "iptables":
            return (0, _make_iptables_output(rules), "")
        return (1, "", "unexpected command")

    with patch("docker_ports.run_cmd", side_effect=side_effect):
        with patch("docker_ports.get_config") as mock_cfg:
            mock_cfg.return_value.allowed_public_port.return_value = MagicMock()
            result = assess_docker_ports()
            assert result["status"] == STATUS_PASS
            assert "allowlisted" in result["current_value"]


def test_blanket_drop_rule():
    """Test that a blanket DROP rule after ESTABLISHED/RELATED accept protects all ports."""
    ports = [
        {"container": "web", "host_port": 80, "container_port": 80, "protocol": "tcp"},
        {"container": "api", "host_port": 443, "container_port": 443, "protocol": "tcp"},
    ]
    rules = [
        {"target": "ACCEPT", "comment": "ESTABLISHED,RELATED"},
        {"target": "DROP"},
    ]

    def side_effect(cmd, timeout=20):
        if cmd[0] == "docker" and cmd[1] == "--version":
            return (0, "Docker version 24.0.0", "")
        elif cmd[0] == "docker" and cmd[1] == "ps":
            return (0, _make_docker_ps_output(ports), "")
        elif cmd[0] == "iptables":
            return (0, _make_iptables_output(rules), "")
        return (1, "", "unexpected command")

    with patch("docker_ports.run_cmd", side_effect=side_effect):
        result = assess_docker_ports()
        assert result["status"] == STATUS_PASS
        assert "2 published port(s)" in result["current_value"]


def test_nftables_backend():
    """Test that nftables backend is used when iptables fails."""
    ports = [
        {"container": "web", "host_port": 80, "container_port": 80, "protocol": "tcp"},
    ]
    rules = [
        {"protocol": "tcp", "dport": "80", "target": "DROP"},
    ]

    def side_effect(cmd, timeout=20):
        if cmd[0] == "docker" and cmd[1] == "--version":
            return (0, "Docker version 24.0.0", "")
        elif cmd[0] == "docker" and cmd[1] == "ps":
            return (0, _make_docker_ps_output(ports), "")
        elif cmd[0] == "iptables":
            return (1, "", "iptables: command not found")
        elif cmd[0] == "nft":
            return (0, _make_nft_output(rules), "")
        return (1, "", "unexpected command")

    with patch("docker_ports.run_cmd", side_effect=side_effect):
        result = assess_docker_ports()
        assert result["status"] == STATUS_PASS
        assert "1 published port(s)" in result["current_value"]
