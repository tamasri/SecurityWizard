import os
import tempfile
import pytest
from datetime import date, timedelta
from config import (
    Config, ConfigError, AcceptedRisk, ListenerAllow, DockerSockAllow,
    DockerPublicPortAllow, DockerPrivilegedAllow, SudoRuleAllow, SuidFileAllow,
    load_config, get_config, reset_config, example_config
)


@pytest.fixture(autouse=True)
def clean_config():
    reset_config()
    yield
    reset_config()


def test_load_config_missing_file_returns_defaults(tmp_path):
    config = load_config(str(tmp_path / "nonexistent.toml"))
    assert isinstance(config, Config)
    assert config.listeners == []
    assert config.docker_sock_containers == []
    assert config.docker_public_ports == []
    assert config.docker_privileged == []
    assert config.sudo_rules == []
    assert config.suid_files == []
    assert config.accepted_risks == []


def test_load_config_valid_file(tmp_path):
    toml_content = """
[allow]
listeners = [
    {port = 80, process = "traefik", reason = "HTTP"},
    {port = 443, reason = "HTTPS"},
]
docker_sock_containers = [
    {name = "coolify", reason = "Orchestrator"},
]
docker_public_ports = [
    {port = 80, container = "traefik", reason = "Public HTTP"},
    {port = 443, reason = "Public HTTPS"},
]
docker_privileged = [
    {name = "coolify", reason = "Needs privileged"},
]
sudo_rules = [
    {user = "deploy", command = "/usr/bin/systemctl restart myapp", reason = "Deploy restart"},
]
suid_files = [
    {path = "/usr/bin/passwd", reason = "Standard SUID"},
]

[[accepted_risk]]
check_id = "ssh_password_auth"
reason = "Disabled for specific users"
expires = "2025-12-31"

[[accepted_risk]]
check_id = "kernel_sysctl"
reason = "Container networking"
match = "net.ipv4.ip_forward"
"""
    config_file = tmp_path / "config.toml"
    config_file.write_text(toml_content)
    config = load_config(str(config_file))
    assert len(config.listeners) == 2
    assert config.listeners[0].port == 80
    assert config.listeners[0].process == "traefik"
    assert config.listeners[1].port == 443
    assert config.listeners[1].process is None
    assert len(config.docker_sock_containers) == 1
    assert config.docker_sock_containers[0].name == "coolify"
    assert len(config.docker_public_ports) == 2
    assert config.docker_public_ports[0].port == 80
    assert config.docker_public_ports[0].container == "traefik"
    assert config.docker_public_ports[1].container is None
    assert len(config.docker_privileged) == 1
    assert config.docker_privileged[0].name == "coolify"
    assert len(config.sudo_rules) == 1
    assert config.sudo_rules[0].user == "deploy"
    assert config.sudo_rules[0].command == "/usr/bin/systemctl restart myapp"
    assert len(config.suid_files) == 1
    assert config.suid_files[0].path == "/usr/bin/passwd"
    assert len(config.accepted_risks) == 2
    assert config.accepted_risks[0].check_id == "ssh_password_auth"
    assert config.accepted_risks[1].match == "net.ipv4.ip_forward"


def test_load_config_bad_type_raises(tmp_path):
    toml_content = """
[allow]
listeners = [
    {port = "80", reason = "Bad port type"},
]
"""
    config_file = tmp_path / "config.toml"
    config_file.write_text(toml_content)
    with pytest.raises(ConfigError, match="must be an integer"):
        load_config(str(config_file))


def test_load_config_bad_type_name_raises(tmp_path):
    toml_content = """
[allow]
docker_sock_containers = [
    {name = 123, reason = "Bad name type"},
]
"""
    config_file = tmp_path / "config.toml"
    config_file.write_text(toml_content)
    with pytest.raises(ConfigError, match="must be a string"):
        load_config(str(config_file))


def test_load_config_unknown_key_warns(tmp_path, caplog):
    toml_content = """
[allow]
listeners = [
    {port = 80, reason = "OK"},
]
unknown_key = "ignored"
"""
    config_file = tmp_path / "config.toml"
    config_file.write_text(toml_content)
    with caplog.at_level("WARNING"):
        config = load_config(str(config_file))
    assert len(config.listeners) == 1
    assert "unknown_key" in caplog.text


def test_is_accepted_unexpired(tmp_path):
    future_date = (date.today() + timedelta(days=30)).strftime("%Y-%m-%d")
    toml_content = f"""
[[accepted_risk]]
check_id = "test_check"
reason = "Still valid"
expires = "{future_date}"
"""
    config_file = tmp_path / "config.toml"
    config_file.write_text(toml_content)
    config = load_config(str(config_file))
    risk = config.is_accepted("test_check")
    assert risk is not None
    assert risk.check_id == "test_check"
    assert risk.reason == "Still valid"


def test_is_accepted_expired(tmp_path):
    past_date = (date.today() - timedelta(days=1)).strftime("%Y-%m-%d")
    toml_content = f"""
[[accepted_risk]]
check_id = "test_check"
reason = "Expired"
expires = "{past_date}"
"""
    config_file = tmp_path / "config.toml"
    config_file.write_text(toml_content)
    config = load_config(str(config_file))
    risk = config.is_accepted("test_check")
    assert risk is None


def test_is_accepted_no_expiry(tmp_path):
    toml_content = """
[[accepted_risk]]
check_id = "test_check"
reason = "No expiry"
"""
    config_file = tmp_path / "config.toml"
    config_file.write_text(toml_content)
    config = load_config(str(config_file))
    risk = config.is_accepted("test_check")
    assert risk is not None
    assert risk.expires is None


def test_is_accepted_with_match(tmp_path):
    toml_content = """
[[accepted_risk]]
check_id = "kernel_sysctl"
reason = "Container networking"
match = "net.ipv4.ip_forward"
"""
    config_file = tmp_path / "config.toml"
    config_file.write_text(toml_content)
    config = load_config(str(config_file))
    assert config.is_accepted("kernel_sysctl", "net.ipv4.ip_forward=1") is not None
    assert config.is_accepted("kernel_sysctl", "net.ipv4.tcp_tw_reuse=1") is None


def test_allowed_listener_port_only(tmp_path):
    toml_content = """
[allow]
listeners = [
    {port = 80, reason = "HTTP"},
]
"""
    config_file = tmp_path / "config.toml"
    config_file.write_text(toml_content)
    config = load_config(str(config_file))
    assert config.allowed_listener(80) is not None
    assert config.allowed_listener(443) is None


def test_allowed_listener_with_process(tmp_path):
    toml_content = """
[allow]
listeners = [
    {port = 80, process = "traefik", reason = "HTTP"},
]
"""
    config_file = tmp_path / "config.toml"
    config_file.write_text(toml_content)
    config = load_config(str(config_file))
    assert config.allowed_listener(80, "traefik") is not None
    assert config.allowed_listener(80, "nginx") is None
    assert config.allowed_listener(80) is not None


def test_allowed_docker_sock(tmp_path):
    toml_content = """
[allow]
docker_sock_containers = [
    {name = "coolify", reason = "Orchestrator"},
]
"""
    config_file = tmp_path / "config.toml"
    config_file.write_text(toml_content)
    config = load_config(str(config_file))
    assert config.allowed_docker_sock("coolify") is not None
    assert config.allowed_docker_sock("other") is None


def test_allowed_public_port(tmp_path):
    toml_content = """
[allow]
docker_public_ports = [
    {port = 80, container = "traefik", reason = "Public HTTP"},
    {port = 443, reason = "Public HTTPS"},
]
"""
    config_file = tmp_path / "config.toml"
    config_file.write_text(toml_content)
    config = load_config(str(config_file))
    assert config.allowed_public_port(80, "traefik") is not None
    assert config.allowed_public_port(80, "nginx") is None
    assert config.allowed_public_port(443) is not None
    assert config.allowed_public_port(443, "anything") is not None
    assert config.allowed_public_port(8080) is None


def test_allowed_sudo_rule(tmp_path):
    toml_content = """
[allow]
sudo_rules = [
    {user = "deploy", command = "/usr/bin/systemctl restart myapp", reason = "Deploy restart"},
]
"""
    config_file = tmp_path / "config.toml"
    config_file.write_text(toml_content)
    config = load_config(str(config_file))
    assert config.allowed_sudo_rule("deploy", "/usr/bin/systemctl restart myapp") is not None
    assert config.allowed_sudo_rule("deploy", "/usr/bin/systemctl stop myapp") is None
    assert config.allowed_sudo_rule("admin", "/usr/bin/systemctl restart myapp") is None


def test_allowed_suid(tmp_path):
    toml_content = """
[allow]
suid_files = [
    {path = "/usr/bin/passwd", reason = "Standard SUID"},
]
"""
    config_file = tmp_path / "config.toml"
    config_file.write_text(toml_content)
    config = load_config(str(config_file))
    assert config.allowed_suid("/usr/bin/passwd") is not None
    assert config.allowed_suid("/usr/bin/sudo") is None


def test_get_config_uses_cache(tmp_path):
    toml_content = """
[allow]
listeners = [
    {port = 80, reason = "HTTP"},
]
"""
    config_file = tmp_path / "config.toml"
    config_file.write_text(toml_content)
    config1 = load_config(str(config_file))
    config2 = get_config()
    assert config1 is config2


def test_reset_config_clears_cache(tmp_path):
    toml_content = """
[allow]
listeners = [
    {port = 80, reason = "HTTP"},
]
"""
    config_file = tmp_path / "config.toml"
    config_file.write_text(toml_content)
    load_config(str(config_file))
    reset_config()
    config = get_config()
    assert config.listeners == []


def test_example_config_returns_string():
    example = example_config()
    assert isinstance(example, str)
    assert "allow" in example
    assert "accepted_risk" in example
    assert "listeners" in example


def test_load_config_env_var(tmp_path, monkeypatch):
    toml_content = """
[allow]
listeners = [
    {port = 80, reason = "HTTP"},
]
"""
    config_file = tmp_path / "env_config.toml"
    config_file.write_text(toml_content)
    monkeypatch.setenv("SECURITYWIZARD_CONFIG", str(config_file))
    config = load_config()
    assert len(config.listeners) == 1
    assert config.listeners[0].port == 80


def test_load_config_invalid_toml(tmp_path):
    config_file = tmp_path / "config.toml"
    config_file.write_text("invalid toml {{{")
    with pytest.raises(ConfigError, match="Invalid TOML"):
        load_config(str(config_file))
