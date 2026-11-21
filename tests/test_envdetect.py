"""Tests for envdetect.detect_environment and helper predicates."""

import pytest
from envdetect import (
    Environment,
    FakeFS,
    FakeRunner,
    detect_environment,
    reset_environment_cache,
    is_container_host,
    is_multi_homed,
)
from common import CmdResult


class DictFS(FakeFS):
    """FakeFS backed by a dict of path -> content."""
    def __init__(self, files: dict):
        self._files = files
    def path_exists(self, path: str) -> bool:
        return path in self._files
    def read_text(self, path: str, default: str = "") -> str:
        return self._files.get(path, default)


class ScriptedRunner(FakeRunner):
    """FakeRunner that returns canned CmdResult objects per command prefix."""
    def __init__(self, responses: dict):
        self._responses = responses
    def run(self, args, timeout=20.0):
        key = " ".join(args)
        for prefix, result in self._responses.items():
            if key.startswith(prefix):
                return result
        return CmdResult(returncode=127, stdout="", stderr="not found", not_found=True)


@pytest.fixture(autouse=True)
def _reset_cache():
    reset_environment_cache()
    yield
    reset_environment_cache()


def _os_release_content(os_id: str, version: str) -> str:
    return f'ID={os_id}\nVERSION_ID={version}\n'


# ---------------------------------------------------------------------------
# Plain Debian 12
# ---------------------------------------------------------------------------

def test_plain_debian_12():
    fs = DictFS({
        "/etc/os-release": _os_release_content("debian", "12"),
    })
    runner = ScriptedRunner({
        "docker --version": CmdResult(127, "", "not found", not_found=True),
        "docker ps -q": CmdResult(127, "", "not found", not_found=True),
        "docker ps -a --filter label=coolify -q": CmdResult(127, "", "not found", not_found=True),
        "systemctl is-active kubelet": CmdResult(3, "inactive\n", ""),
        "wg show": CmdResult(1, "", "no devices"),
        "systemctl is-active fail2ban": CmdResult(3, "inactive\n", ""),
        "pgrep -x fail2ban-server": CmdResult(1, "", ""),
        "systemctl is-active crowdsec": CmdResult(3, "inactive\n", ""),
        "pgrep -x csd": CmdResult(1, "", ""),
        "systemctl is-active auditd": CmdResult(3, "inactive\n", ""),
        "pgrep -x auditd": CmdResult(1, "", ""),
        "aa-status": CmdResult(127, "", "not found", not_found=True),
        "getenforce": CmdResult(127, "", "not found", not_found=True),
    })
    env = detect_environment(fs=fs, runner=runner)
    assert env.os_id == "debian"
    assert env.os_version == "12"
    assert env.docker_socket is False
    assert env.docker_binary is False
    assert env.docker_running_containers == 0
    assert env.coolify is False
    assert env.kubernetes is False
    assert env.wireguard is False
    assert env.cloud_provider == ""
    assert env.fail2ban is False
    assert env.crowdsec is False
    assert env.auditd is False
    assert env.apparmor is False
    assert env.selinux is False
    assert env.python_ge_312 in (True, False)  # depends on build machine


# ---------------------------------------------------------------------------
# Ubuntu 24.04 Oracle ARM64 Coolify host
# ---------------------------------------------------------------------------

def test_ubuntu_2404_oracle_arm64_coolify():
    fs = DictFS({
        "/etc/os-release": _os_release_content("ubuntu", "24.04"),
        "/var/run/docker.sock": "",
        "/data/coolify": "",
        "/sys/class/dmi/id/sys_vendor": "Oracle Corporation\n",
        "/sys/class/dmi/id/product_name": "Oracle Cloud\n",
        "/sys/class/dmi/id/chassis_asset_tag": "OCP-12345\n",
        "/sys/module/apparmor": "",
    })
    runner = ScriptedRunner({
        "docker --version": CmdResult(0, "Docker version 26.0.1, build 8633ee1\n", ""),
        "docker ps -q": CmdResult(0, "abc123\ndef456\nghi789\n", ""),
        "docker ps -a --filter label=coolify -q": CmdResult(0, "abc123\ndef456\n", ""),
        "systemctl is-active kubelet": CmdResult(3, "inactive\n", ""),
        "wg show": CmdResult(1, "", "no devices"),
        "systemctl is-active fail2ban": CmdResult(0, "active\n", ""),
        "pgrep -x fail2ban-server": CmdResult(0, "1234\n", ""),
        "systemctl is-active crowdsec": CmdResult(0, "active\n", ""),
        "pgrep -x csd": CmdResult(0, "5678\n", ""),
        "systemctl is-active auditd": CmdResult(3, "inactive\n", ""),
        "pgrep -x auditd": CmdResult(1, "", ""),
        "aa-status": CmdResult(0, "apparmor is active.\n", ""),
        "getenforce": CmdResult(127, "", "not found", not_found=True),
    })
    env = detect_environment(fs=fs, runner=runner)
    assert env.os_id == "ubuntu"
    assert env.os_version == "24.04"
    assert env.docker_socket is True
    assert env.docker_binary is True
    assert env.docker_running_containers == 3
    assert env.coolify is True
    assert env.kubernetes is False
    assert env.wireguard is False
    assert env.cloud_provider == "oracle"
    assert any("Oracle" in h for h in env.cloud_hints)
    assert env.fail2ban is True
    assert env.crowdsec is True
    assert env.auditd is False
    assert env.apparmor is True
    assert env.selinux is False
    assert is_container_host(env) is True


# ---------------------------------------------------------------------------
# GCP VM
# ---------------------------------------------------------------------------

def test_gcp_vm():
    fs = DictFS({
        "/etc/os-release": _os_release_content("ubuntu", "24.04"),
        "/sys/class/dmi/id/sys_vendor": "Google\n",
        "/sys/class/dmi/id/product_name": "Google Compute Engine\n",
        "/sys/class/dmi/id/chassis_asset_tag": "gcp-xyz\n",
    })
    runner = ScriptedRunner({
        "docker --version": CmdResult(127, "", "not found", not_found=True),
        "docker ps -q": CmdResult(127, "", "not found", not_found=True),
        "docker ps -a --filter label=coolify -q": CmdResult(127, "", "not found", not_found=True),
        "systemctl is-active kubelet": CmdResult(3, "inactive\n", ""),
        "wg show": CmdResult(1, "", "no devices"),
        "systemctl is-active fail2ban": CmdResult(3, "inactive\n", ""),
        "pgrep -x fail2ban-server": CmdResult(1, "", ""),
        "systemctl is-active crowdsec": CmdResult(3, "inactive\n", ""),
        "pgrep -x csd": CmdResult(1, "", ""),
        "systemctl is-active auditd": CmdResult(3, "inactive\n", ""),
        "pgrep -x auditd": CmdResult(1, "", ""),
        "aa-status": CmdResult(127, "", "not found", not_found=True),
        "getenforce": CmdResult(127, "", "not found", not_found=True),
    })
    env = detect_environment(fs=fs, runner=runner)
    assert env.cloud_provider == "gcp"
    assert any("Google" in h for h in env.cloud_hints)
    assert env.docker_socket is False
    assert env.coolify is False
    assert env.kubernetes is False


# ---------------------------------------------------------------------------
# Kubernetes node
# ---------------------------------------------------------------------------

def test_kubernetes_node():
    fs = DictFS({
        "/etc/os-release": _os_release_content("debian", "12"),
        "/etc/kubernetes": "",
        "/sys/class/dmi/id/sys_vendor": "Amazon EC2\n",
        "/sys/class/dmi/id/product_name": "Nitro System\n",
        "/sys/class/dmi/id/chassis_asset_tag": "aws-abc\n",
    })
    runner = ScriptedRunner({
        "docker --version": CmdResult(0, "Docker version 26.0.1\n", ""),
        "docker ps -q": CmdResult(0, "aaa\nbbb\n", ""),
        "docker ps -a --filter label=coolify -q": CmdResult(0, "", ""),
        "systemctl is-active kubelet": CmdResult(0, "active\n", ""),
        "wg show": CmdResult(1, "", "no devices"),
        "systemctl is-active fail2ban": CmdResult(3, "inactive\n", ""),
        "pgrep -x fail2ban-server": CmdResult(1, "", ""),
        "systemctl is-active crowdsec": CmdResult(3, "inactive\n", ""),
        "pgrep -x csd": CmdResult(1, "", ""),
        "systemctl is-active auditd": CmdResult(0, "active\n", ""),
        "pgrep -x auditd": CmdResult(0, "42\n", ""),
        "aa-status": CmdResult(127, "", "not found", not_found=True),
        "getenforce": CmdResult(0, "Enforcing\n", ""),
    })
    env = detect_environment(fs=fs, runner=runner)
    assert env.kubernetes is True
    assert env.cloud_provider == "aws"
    assert env.docker_running_containers == 2
    assert env.auditd is True
    assert env.selinux is True
    assert env.selinux_mode == "enforcing"
    assert is_container_host(env) is True


# ---------------------------------------------------------------------------
# Cache behaviour
# ---------------------------------------------------------------------------

def test_cache_returns_same_object():
    fs = DictFS({"/etc/os-release": _os_release_content("ubuntu", "24.04")})
    runner = ScriptedRunner({
        "docker --version": CmdResult(127, "", "nf", not_found=True),
        "docker ps -q": CmdResult(127, "", "nf", not_found=True),
        "docker ps -a --filter label=coolify -q": CmdResult(127, "", "nf", not_found=True),
        "systemctl is-active kubelet": CmdResult(3, "inactive\n", ""),
        "wg show": CmdResult(1, "", ""),
        "systemctl is-active fail2ban": CmdResult(3, "inactive\n", ""),
        "pgrep -x fail2ban-server": CmdResult(1, "", ""),
        "systemctl is-active crowdsec": CmdResult(3, "inactive\n", ""),
        "pgrep -x csd": CmdResult(1, "", ""),
        "systemctl is-active auditd": CmdResult(3, "inactive\n", ""),
        "pgrep -x auditd": CmdResult(1, "", ""),
        "aa-status": CmdResult(127, "", "nf", not_found=True),
        "getenforce": CmdResult(127, "", "nf", not_found=True),
    })
    env1 = detect_environment(fs=fs, runner=runner)
    env2 = detect_environment(fs=fs, runner=runner)
    assert env1 is env2

    reset_environment_cache()
    env3 = detect_environment(fs=fs, runner=runner)
    assert env3 is not env1


# ---------------------------------------------------------------------------
# Helper predicates
# ---------------------------------------------------------------------------

def test_is_container_host_false():
    env = Environment()
    assert is_container_host(env) is False


def test_is_container_host_true_docker():
    env = Environment(docker_socket=True)
    assert is_container_host(env) is True


def test_is_container_host_true_k8s():
    env = Environment(kubernetes=True)
    assert is_container_host(env) is True


def test_json_serialisable():
    env = Environment(
        os_id="ubuntu", os_version="24.04", architecture="aarch64",
        python_version="3.12", python_ge_312=True,
        docker_socket=True, docker_binary=True, docker_running_containers=35,
        coolify=True, kubernetes=False, wireguard=False,
        cloud_provider="oracle", cloud_hints=["sys_vendor=Oracle Corporation"],
        fail2ban=True, crowdsec=True, auditd=False,
        apparmor=True, selinux=False, selinux_mode="",
    )
    d = env.to_dict()
    assert d["docker_running_containers"] == 35
    assert d["cloud_provider"] == "oracle"
    assert isinstance(d["cloud_hints"], list)
    import json
    json.dumps(d)
