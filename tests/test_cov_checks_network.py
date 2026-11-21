"""checks_network: ss parsing, NET-001..004 and run_checks (commands, firewall and docker data mocked)."""

from types import SimpleNamespace

import pytest

import checks_network
from common import STATUS_CRITICAL, STATUS_INFO, STATUS_PASS, STATUS_SKIPPED, STATUS_WARNING, CmdResult

SS_OUTPUT = (
    'tcp   LISTEN 0 4096    0.0.0.0:22     0.0.0.0:*  users:(("sshd",pid=812,fd=3))\n'
    'tcp   LISTEN 0 511   127.0.0.1:6379   0.0.0.0:*  users:(("redis-server",pid=901,fd=6))\n'
    'tcp   LISTEN 0 4096    0.0.0.0:3306   0.0.0.0:*  users:(("mysqld",pid=77,fd=9))\n'
    'tcp   LISTEN 0 4096       [::]:5432      [::]:*  users:(("postgres",pid=78,fd=4))\n'
    "tcp   LISTEN 0 128        [::1]:9200      [::]:*\n"
    'udp   UNCONN 0 0       0.0.0.0:68     0.0.0.0:*  users:(("dhclient",pid=640,fd=5))\n'
)


# ---- parsing --------------------------------------------------------------------------------------------------------


def test_parse_ss_line_extracts_every_field():
    parsed = checks_network.parse_ss_line('tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=812,fd=3))')
    assert parsed == {
        "proto": "tcp",
        "state": "LISTEN",
        "addr": "0.0.0.0",
        "port": "22",
        "process": "sshd",
        "pid": "812",
    }


def test_parse_ss_line_ipv6_and_missing_process():
    parsed = checks_network.parse_ss_line("tcp LISTEN 0 128 [::]:5432 [::]:*")
    assert parsed["addr"] == "::" and parsed["port"] == "5432" and parsed["process"] == "" and parsed["pid"] == ""


def test_parse_ss_line_local_address_without_port():
    parsed = checks_network.parse_ss_line("raw UNCONN 0 0 * *")
    assert parsed["addr"] == "*" and parsed["port"] == ""


@pytest.mark.parametrize("line", ["", "   ", "tcp LISTEN 0 4096", "tcp LISTEN"])
def test_parse_ss_line_ignores_short_or_empty_lines(line):
    assert checks_network.parse_ss_line(line) is None


def test_parse_ss_output_skips_unparseable_lines():
    assert len(checks_network._parse_ss_output(SS_OUTPUT + "\nbroken\n")) == 6


@pytest.mark.parametrize(
    "port, expected",
    [("3306", True), ("6379", True), ("2375", True), ("22", False), ("x", False), (None, False), ("", False)],
)
def test_dangerous_ports(port, expected):
    assert checks_network._is_dangerous_port(port) is expected


@pytest.mark.parametrize(
    "addr, expected",
    [("0.0.0.0", True), ("::", True), ("*", True), ("127.0.0.1", False), ("::1", False), ("10.0.0.5", False)],
)
def test_exposed_to_all(addr, expected):
    assert checks_network._is_exposed_to_all(addr) is expected


# ---- NET-001 -------------------------------------------------------------------------------------------------------


def _ss(monkeypatch, result):
    monkeypatch.setattr(checks_network, "run_cmd", lambda args, timeout=None: result)


def test_net001_without_ss(monkeypatch):
    _ss(monkeypatch, CmdResult(127, "", "", not_found=True))
    result = checks_network.check_net_001()
    assert result["status"] == STATUS_SKIPPED and "iproute2" in result["current_value"]


def test_net001_ss_error(monkeypatch):
    _ss(monkeypatch, CmdResult(1, "", "operation not permitted"))
    result = checks_network.check_net_001()
    assert result["status"] == STATUS_SKIPPED and "operation not permitted" in result["current_value"]


def test_net001_lists_every_socket_with_its_process(monkeypatch):
    _ss(monkeypatch, CmdResult(0, SS_OUTPUT, ""))
    result = checks_network.check_net_001()
    assert result["status"] == STATUS_INFO and result["current_value"] == "6 listening socket(s)"
    text = "\n".join(result["details"])
    assert "sshd" in text and "812" in text and "5432" in text


# ---- NET-002 --------------------------------------------------------------------------------------------------------


def _config(monkeypatch, allowed=(), broken=False, listener_error=False):
    def allowed_listener(port, process):
        if listener_error:
            raise RuntimeError("lookup failed")
        return object() if (port, process) in allowed else None

    if broken:

        def get_config():
            raise RuntimeError("no config")
    else:

        def get_config():
            return SimpleNamespace(allowed_listener=allowed_listener)

    monkeypatch.setattr(checks_network, "get_config", get_config)


def test_net002_without_ss_or_with_error(monkeypatch):
    _ss(monkeypatch, CmdResult(127, "", "", not_found=True))
    assert checks_network.check_net_002()["status"] == STATUS_SKIPPED
    _ss(monkeypatch, CmdResult(2, "", "bad"))
    result = checks_network.check_net_002()
    assert result["status"] == STATUS_SKIPPED and "bad" in result["current_value"]


def test_net002_flags_private_services_on_all_interfaces(monkeypatch):
    _ss(monkeypatch, CmdResult(0, SS_OUTPUT, ""))
    _config(monkeypatch)
    result = checks_network.check_net_002()
    assert result["status"] == STATUS_CRITICAL and result["current_value"] == "2 dangerous service(s) on all interfaces"
    text = "\n".join(result["details"])
    assert "mysqld (pid 77)" in text and "postgres (pid 78)" in text and "[::]:5432" in text
    assert "redis" not in text and "9200" not in text  # loopback only


def test_net002_passes_when_nothing_dangerous_is_exposed(monkeypatch):
    _ss(monkeypatch, CmdResult(0, 'tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n', ""))
    _config(monkeypatch)
    result = checks_network.check_net_002()
    assert result["status"] == STATUS_PASS and "No dangerous services" in result["current_value"]


def test_net002_honours_the_configured_allowlist(monkeypatch):
    _ss(monkeypatch, CmdResult(0, SS_OUTPUT, ""))
    _config(monkeypatch, allowed={(3306, "mysqld"), (5432, "postgres")})
    assert checks_network.check_net_002()["status"] == STATUS_PASS


def test_net002_survives_a_broken_configuration(monkeypatch):
    _ss(monkeypatch, CmdResult(0, SS_OUTPUT, ""))
    _config(monkeypatch, broken=True)
    assert checks_network.check_net_002()["status"] == STATUS_CRITICAL
    _config(monkeypatch, listener_error=True)
    assert checks_network.check_net_002()["status"] == STATUS_CRITICAL


def test_net002_unknown_process_and_non_numeric_port(monkeypatch):
    _ss(monkeypatch, CmdResult(0, "tcp LISTEN 0 4096 0.0.0.0:3306 0.0.0.0:*\ntcp LISTEN 0 1 0.0.0.0:x 0.0.0.0:*\n", ""))
    _config(monkeypatch)
    result = checks_network.check_net_002()
    assert result["status"] == STATUS_CRITICAL and "unknown (pid 0)" in "\n".join(result["details"])


# ---- NET-003 --------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "backend, expected",
    [
        ("ufw", "ufw default deny incoming"),
        ("iptables-nft", "iptables -P INPUT DROP"),
        ("iptables-legacy", "iptables -P INPUT DROP"),
        ("nftables", "nft add rule inet filter input"),
        ("firewalld", "firewall-cmd --set-default-zone=drop"),
        ("none", "apt install ufw"),
    ],
)
def test_net003_manual_command_follows_the_backend(monkeypatch, backend, expected):
    import firewall

    monkeypatch.setattr(firewall, "detect_firewall", lambda: SimpleNamespace(backend=backend))
    monkeypatch.setattr(
        firewall,
        "evaluate_firewall",
        lambda info: {"status": STATUS_PASS, "current_value": "policy DROP", "recommended": "keep", "details": ["d"]},
    )
    result = checks_network.check_net_003()
    assert result["id"] == "NET-003" and result["status"] == STATUS_PASS and expected in result["manual_command"]
    assert result["remediation_id"] == "ufw_baseline"


# ---- NET-004 --------------------------------------------------------------------------------------------------------


def _docker_ports(monkeypatch, status):
    import docker_ports

    monkeypatch.setattr(
        docker_ports,
        "assess_docker_ports",
        lambda: {"status": status, "current_value": "value", "recommended": "rec", "details": ["detail"]},
    )


def test_net004_without_docker_is_informational(monkeypatch):
    _docker_ports(monkeypatch, STATUS_SKIPPED)
    result = checks_network.check_net_004()
    assert result["id"] == "NET-004" and result["status"] == STATUS_PASS and result["manual_command"] == ""


@pytest.mark.parametrize("status", [STATUS_PASS, STATUS_CRITICAL, STATUS_WARNING])
def test_net004_reports_the_assessment(monkeypatch, status):
    _docker_ports(monkeypatch, status)
    result = checks_network.check_net_004()
    assert result["status"] == status and result["current_value"] == "value"


def test_net004_manual_command_keeps_established_traffic_and_only_filters_the_public_interface(monkeypatch):
    """Regression: the old command inserted a blanket DROP at the top of DOCKER-USER, cutting every container off."""
    _docker_ports(monkeypatch, STATUS_CRITICAL)
    command = checks_network.check_net_004()["manual_command"]
    steps = [part.strip() for part in command.splitlines()[-1].split("&&")]
    assert len(steps) == 3
    # `-I` inserts at the top, so the LAST command ends up FIRST: it must be the established-traffic accept
    assert "ESTABLISHED,RELATED -j ACCEPT" in steps[-1]
    assert steps[0].endswith("--ctstate NEW -j DROP")
    assert all("-i eth0" in step for step in steps)  # only traffic arriving from outside


# ---- run_checks -----------------------------------------------------------------------------------------------------


def test_run_checks_reports_every_failure_as_a_skipped_check(monkeypatch):
    def boom():
        raise RuntimeError("kaboom")

    for name in ("check_net_001", "check_net_002", "check_net_003", "check_net_004"):
        monkeypatch.setattr(checks_network, name, boom)
    results = checks_network.run_checks()
    assert len(results) == 4 and all(r["status"] == STATUS_SKIPPED and "kaboom" in r["current_value"] for r in results)
    assert results[2]["remediation_id"] == "ufw_baseline" and results[3]["remediation_id"] == "docker_user_isolation"


def test_run_checks_happy_path(monkeypatch):
    for name, check_id in (
        ("check_net_001", "NET-001"),
        ("check_net_002", "NET-002"),
        ("check_net_003", "NET-003"),
        ("check_net_004", "NET-004"),
    ):
        monkeypatch.setattr(checks_network, name, lambda cid=check_id: {"id": cid, "status": STATUS_PASS})
    assert [r["id"] for r in checks_network.run_checks()] == ["NET-001", "NET-002", "NET-003", "NET-004"]
