from checks_network import (
    _is_dangerous_port,
    _is_exposed_to_all,
    _parse_ss_output,
    check_net_001,
    check_net_002,
    parse_ss_line,
)


def test_parse_ss_line_tcp_ipv4():
    line = 'tcp   LISTEN 0      4096         0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=812,fd=3))'
    result = parse_ss_line(line)
    assert result is not None
    assert result["proto"] == "tcp"
    assert result["state"] == "LISTEN"
    assert result["addr"] == "0.0.0.0"
    assert result["port"] == "22"
    assert result["process"] == "sshd"
    assert result["pid"] == "812"


def test_parse_ss_line_tcp_loopback():
    line = 'tcp   LISTEN 0      511        127.0.0.1:6379       0.0.0.0:*    users:(("redis-server",pid=901,fd=6))'
    result = parse_ss_line(line)
    assert result is not None
    assert result["proto"] == "tcp"
    assert result["state"] == "LISTEN"
    assert result["addr"] == "127.0.0.1"
    assert result["port"] == "6379"
    assert result["process"] == "redis-server"
    assert result["pid"] == "901"


def test_parse_ss_line_tcp_ipv6_all():
    line = 'tcp   LISTEN 0      4096            [::]:443            [::]:*    users:(("docker-proxy",pid=1500,fd=4))'
    result = parse_ss_line(line)
    assert result is not None
    assert result["proto"] == "tcp"
    assert result["state"] == "LISTEN"
    assert result["addr"] == "::"
    assert result["port"] == "443"
    assert result["process"] == "docker-proxy"
    assert result["pid"] == "1500"


def test_parse_ss_line_tcp_ipv6_loopback_no_process():
    line = "tcp   LISTEN 0      128             [::1]:5432          [::]:*"
    result = parse_ss_line(line)
    assert result is not None
    assert result["proto"] == "tcp"
    assert result["state"] == "LISTEN"
    assert result["addr"] == "::1"
    assert result["port"] == "5432"
    assert result["process"] == ""
    assert result["pid"] == ""


def test_parse_ss_line_udp_ipv4():
    line = 'udp   UNCONN 0      0            0.0.0.0:68         0.0.0.0:*    users:(("dhclient",pid=640,fd=5))'
    result = parse_ss_line(line)
    assert result is not None
    assert result["proto"] == "udp"
    assert result["state"] == "UNCONN"
    assert result["addr"] == "0.0.0.0"
    assert result["port"] == "68"
    assert result["process"] == "dhclient"
    assert result["pid"] == "640"


def test_parse_ss_line_tcp_ipv4_mapped():
    line = 'tcp   LISTEN 0      4096     [::ffff:10.0.0.5]:8080       *:*    users:(("app",pid=77,fd=9),("app",pid=78,fd=9))'
    result = parse_ss_line(line)
    assert result is not None
    assert result["proto"] == "tcp"
    assert result["state"] == "LISTEN"
    assert result["addr"] == "::ffff:10.0.0.5"
    assert result["port"] == "8080"
    assert result["process"] == "app"
    assert result["pid"] == "77"


def test_parse_ss_line_empty():
    assert parse_ss_line("") is None
    assert parse_ss_line("   ") is None


def test_parse_ss_line_short_line():
    assert parse_ss_line("tcp LISTEN") is None


def test_parse_ss_output_multiple_lines():
    output = """tcp   LISTEN 0      4096         0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=812,fd=3))
tcp   LISTEN 0      511        127.0.0.1:6379       0.0.0.0:*    users:(("redis-server",pid=901,fd=6))
udp   UNCONN 0      0            0.0.0.0:68         0.0.0.0:*    users:(("dhclient",pid=640,fd=5))"""
    results = _parse_ss_output(output)
    assert len(results) == 3
    assert results[0]["process"] == "sshd"
    assert results[1]["process"] == "redis-server"
    assert results[2]["proto"] == "udp"


def test_is_exposed_to_all():
    assert _is_exposed_to_all("0.0.0.0") is True
    assert _is_exposed_to_all("::") is True
    assert _is_exposed_to_all("*") is True
    assert _is_exposed_to_all("127.0.0.1") is False
    assert _is_exposed_to_all("::1") is False
    assert _is_exposed_to_all("10.0.0.5") is False


def test_is_dangerous_port():
    assert _is_dangerous_port("3306") is True
    assert _is_dangerous_port("5432") is True
    assert _is_dangerous_port("6379") is True
    assert _is_dangerous_port("27017") is True
    assert _is_dangerous_port("1433") is True
    assert _is_dangerous_port("2375") is True
    assert _is_dangerous_port("2376") is True
    assert _is_dangerous_port("9200") is True
    assert _is_dangerous_port("9300") is True
    assert _is_dangerous_port("11211") is True
    assert _is_dangerous_port("2379") is True
    assert _is_dangerous_port("10250") is True
    assert _is_dangerous_port("80") is False
    assert _is_dangerous_port("443") is False
    assert _is_dangerous_port("22") is False
    assert _is_dangerous_port("abc") is False


def test_check_net_001_with_mocked_ss(monkeypatch):
    ss_output = """tcp   LISTEN 0      4096         0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=812,fd=3))
tcp   LISTEN 0      511        127.0.0.1:6379       0.0.0.0:*    users:(("redis-server",pid=901,fd=6))"""

    from common import CmdResult

    monkeypatch.setattr("checks_network.run_cmd", lambda cmd, timeout=20.0: CmdResult(0, ss_output, ""))
    result = check_net_001()
    assert result["id"] == "NET-001"
    assert result["status"] == "INFO"
    assert "2 listening socket(s)" in result["current_value"]
    assert len(result["details"]) == 2


def test_check_net_002_dangerous_exposed(monkeypatch):
    ss_output = """tcp   LISTEN 0      4096         0.0.0.0:5432         0.0.0.0:*    users:(("postgres",pid=900,fd=3))
tcp   LISTEN 0      511        127.0.0.1:6379       0.0.0.0:*    users:(("redis-server",pid=901,fd=6))"""

    from common import CmdResult

    monkeypatch.setattr("checks_network.run_cmd", lambda cmd, timeout=20.0: CmdResult(0, ss_output, ""))
    result = check_net_002()
    assert result["id"] == "NET-002"
    assert result["status"] == "CRITICAL"
    assert "1 dangerous service(s)" in result["current_value"]
    assert len(result["details"]) == 1
    assert "postgres" in result["details"][0]


def test_check_net_002_no_dangerous(monkeypatch):
    ss_output = """tcp   LISTEN 0      4096         0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=812,fd=3))
tcp   LISTEN 0      511        127.0.0.1:6379       0.0.0.0:*    users:(("redis-server",pid=901,fd=6))"""

    from common import CmdResult

    monkeypatch.setattr("checks_network.run_cmd", lambda cmd, timeout=20.0: CmdResult(0, ss_output, ""))
    result = check_net_002()
    assert result["id"] == "NET-002"
    assert result["status"] == "PASS"
    assert "No dangerous services" in result["current_value"]
    assert len(result["details"]) == 0


def test_check_net_001_ss_not_found(monkeypatch):
    from common import CmdResult

    monkeypatch.setattr("checks_network.run_cmd", lambda cmd, timeout=20.0: CmdResult(127, "", "command not found"))
    result = check_net_001()
    assert result["id"] == "NET-001"
    assert result["status"] == "SKIPPED"
    assert "ss binary not found" in result["current_value"]


def test_check_net_002_ss_not_found(monkeypatch):
    from common import CmdResult

    monkeypatch.setattr("checks_network.run_cmd", lambda cmd, timeout=20.0: CmdResult(127, "", "command not found"))
    result = check_net_002()
    assert result["id"] == "NET-002"
    assert result["status"] == "SKIPPED"
    assert "ss binary not found" in result["current_value"]


def test_check_net_002_ipv6_all_interfaces(monkeypatch):
    ss_output = 'tcp   LISTEN 0      4096            [::]:5432            [::]:*    users:(("postgres",pid=900,fd=3))'

    from common import CmdResult

    monkeypatch.setattr("checks_network.run_cmd", lambda cmd, timeout=20.0: CmdResult(0, ss_output, ""))
    result = check_net_002()
    assert result["id"] == "NET-002"
    assert result["status"] == "CRITICAL"
    assert "1 dangerous service(s)" in result["current_value"]
    assert "postgres" in result["details"][0]
    assert "[::]:5432" in result["details"][0]


def test_check_net_002_ipv4_mapped_not_exposed(monkeypatch):
    ss_output = 'tcp   LISTEN 0      4096     [::ffff:10.0.0.5]:5432       *:*    users:(("postgres",pid=900,fd=3))'

    from common import CmdResult

    monkeypatch.setattr("checks_network.run_cmd", lambda cmd, timeout=20.0: CmdResult(0, ss_output, ""))
    result = check_net_002()
    assert result["id"] == "NET-002"
    assert result["status"] == "PASS"
    assert "No dangerous services" in result["current_value"]
    assert len(result["details"]) == 0
