"""tests/test_firewall.py — Regression tests for firewall detection and parsing."""

import pytest
from unittest.mock import patch
from firewall import detect_firewall, evaluate_firewall, FirewallInfo, _parse_iptables_input, _parse_nft_input, _parse_ufw_status
from common import STATUS_PASS, STATUS_WARNING, STATUS_CRITICAL


def _mock_run_cmd(monkeypatch, responses: dict):
    """Monkeypatch run_cmd to return predefined responses."""
    def fake_run_cmd(args, timeout=20):
        key = " ".join(args)
        if key in responses:
            return responses[key]
        return 127, "", "not found"
    monkeypatch.setattr("firewall.run_cmd", fake_run_cmd)


def test_iptables_accept_with_final_reject(monkeypatch):
    """iptables with -P INPUT ACCEPT and a final REJECT rule should be PASS."""
    iptables_output = """-P INPUT ACCEPT
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp-host-prohibited"""
    _mock_run_cmd(monkeypatch, {
        "nft list ruleset": (127, "", "not found"),
        "ufw status verbose": (127, "", "not found"),
        "firewall-cmd --state": (127, "", "not found"),
        "iptables --version": (0, "iptables v1.8.7 (legacy)", ""),
        "iptables -S INPUT": (0, iptables_output, ""),
    })
    info = detect_firewall()
    assert info.backend == "iptables-legacy"
    assert info.active is True
    assert info.default_policy == "ACCEPT"
    assert info.final_rule == "REJECT"
    assert info.accepts_established is True
    assert 22 in info.allowed_ports
    assert 80 in info.allowed_ports

    result = evaluate_firewall(info)
    assert result["status"] == STATUS_PASS


def test_iptables_nft_backend(monkeypatch):
    """iptables-nft backend should be detected correctly."""
    iptables_output = """-P INPUT DROP
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT"""
    _mock_run_cmd(monkeypatch, {
        "nft list ruleset": (127, "", "not found"),
        "ufw status verbose": (127, "", "not found"),
        "firewall-cmd --state": (127, "", "not found"),
        "iptables --version": (0, "iptables v1.8.7 (nf_tables)", ""),
        "iptables -S INPUT": (0, iptables_output, ""),
    })
    info = detect_firewall()
    assert info.backend == "iptables-nft"
    assert info.active is True
    assert info.default_policy == "DROP"
    assert info.final_rule == ""
    assert info.accepts_established is True
    assert 22 in info.allowed_ports

    result = evaluate_firewall(info)
    assert result["status"] == STATUS_PASS


def test_ufw_active(monkeypatch):
    """UFW active with deny incoming should be PASS."""
    ufw_output = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New: deny (profile)

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
80/tcp                     ALLOW       Anywhere"""
    _mock_run_cmd(monkeypatch, {
        "nft list ruleset": (127, "", "not found"),
        "ufw status verbose": (0, ufw_output, ""),
    })
    info = detect_firewall()
    assert info.backend == "ufw"
    assert info.active is True
    assert info.default_policy == "DROP"
    assert info.final_rule == "DROP"
    assert info.accepts_established is True
    assert 22 in info.allowed_ports
    assert 80 in info.allowed_ports

    result = evaluate_firewall(info)
    assert result["status"] == STATUS_PASS


def test_nftables_ruleset(monkeypatch):
    """nftables ruleset should be detected and parsed."""
    nft_output = """table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        tcp dport 22 accept
        tcp dport 80 accept
    }
}"""
    _mock_run_cmd(monkeypatch, {
        "nft list ruleset": (0, nft_output, ""),
    })
    info = detect_firewall()
    assert info.backend == "nftables"
    assert info.active is True
    assert info.default_policy == "DROP"
    assert info.final_rule == ""
    assert info.accepts_established is True
    assert 22 in info.allowed_ports
    assert 80 in info.allowed_ports

    result = evaluate_firewall(info)
    assert result["status"] == STATUS_PASS


def test_no_firewall(monkeypatch):
    """No firewall backend should be CRITICAL."""
    _mock_run_cmd(monkeypatch, {
        "nft list ruleset": (127, "", "not found"),
        "ufw status verbose": (127, "", "not found"),
        "firewall-cmd --state": (127, "", "not found"),
        "iptables --version": (127, "", "not found"),
    })
    info = detect_firewall()
    assert info.backend == "none"
    assert info.active is False

    result = evaluate_firewall(info)
    assert result["status"] == STATUS_CRITICAL


def test_iptables_accept_no_final_reject(monkeypatch):
    """iptables with ACCEPT policy and no final reject should be WARNING."""
    iptables_output = """-P INPUT ACCEPT
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT"""
    _mock_run_cmd(monkeypatch, {
        "nft list ruleset": (127, "", "not found"),
        "ufw status verbose": (127, "", "not found"),
        "firewall-cmd --state": (127, "", "not found"),
        "iptables --version": (0, "iptables v1.8.7 (legacy)", ""),
        "iptables -S INPUT": (0, iptables_output, ""),
    })
    info = detect_firewall()
    assert info.backend == "iptables-legacy"
    assert info.default_policy == "ACCEPT"
    assert info.final_rule == ""

    result = evaluate_firewall(info)
    assert result["status"] == STATUS_WARNING


def test_parse_iptables_input():
    """Unit test for _parse_iptables_input with sample output."""
    output = """-P INPUT DROP
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
-A INPUT -j DROP"""
    result = _parse_iptables_input(output)
    assert result["policy"] == "DROP"
    assert result["final_rule"] == "DROP"
    assert result["accepts_established"] is True
    assert 22 in result["allowed_ports"]
    assert 443 in result["allowed_ports"]


def test_parse_nft_input():
    """Unit test for _parse_nft_input with sample output."""
    output = """table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        tcp dport 22 accept
        tcp dport 80 accept
    }
}"""
    result = _parse_nft_input(output)
    assert result["policy"] == "DROP"
    assert result["final_rule"] == ""
    assert result["accepts_established"] is True
    assert 22 in result["allowed_ports"]
    assert 80 in result["allowed_ports"]


def test_parse_ufw_status():
    """Unit test for _parse_ufw_status with sample output."""
    output = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New: deny (profile)

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
80/tcp                     ALLOW       Anywhere"""
    result = _parse_ufw_status(output)
    assert result["policy"] == "DROP"
    assert result["final_rule"] == "DROP"
    assert result["accepts_established"] is True
    assert 22 in result["allowed_ports"]
    assert 80 in result["allowed_ports"]
