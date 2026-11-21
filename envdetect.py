"""Environment detection for SecurityWizard.

Detects container runtimes, orchestration layers, cloud providers, and
security tooling using injectable filesystem and command runners so that
tests can run without touching a real system.
"""

from __future__ import annotations

import logging
import os
import platform
import sys
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("securitywizard")


# ---------------------------------------------------------------------------
# Injectable interfaces
# ---------------------------------------------------------------------------


class FakeFS:
    """Minimal filesystem abstraction for injection.

    ``path_exists`` and ``read_text`` are the only methods used by
    ``detect_environment``.  Tests build a dict of path -> content and wrap
    it in a thin adapter, or simply pass a dict itself (duck typing).
    """

    def path_exists(self, path: str) -> bool:
        raise NotImplementedError

    def read_text(self, path: str, default: str = "") -> str:
        raise NotImplementedError


class FakeRunner:
    """Minimal command runner for injection.

    ``run`` mirrors the signature of ``common.run_cmd``.
    """

    def run(self, args: List[str], timeout: float = 20.0) -> Any:
        raise NotImplementedError


def _default_fs() -> FakeFS:
    class _RealFS(FakeFS):
        def path_exists(self, path: str) -> bool:
            return os.path.exists(path)

        def read_text(self, path: str, default: str = "") -> str:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return f.read()
            except Exception as exc:
                logger.warning("envdetect: failed to read %s: %s", path, exc)
                return default

    return _RealFS()


def _default_runner() -> FakeRunner:
    from common import run_cmd as _run_cmd

    class _RealRunner(FakeRunner):
        def run(self, args: List[str], timeout: float = 20.0) -> Any:
            return _run_cmd(args, timeout=timeout)

    return _RealRunner()


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Environment:
    os_id: str = ""
    os_version: str = ""
    architecture: str = ""
    python_version: str = ""
    python_ge_312: bool = False
    docker_socket: bool = False
    docker_binary: bool = False
    docker_running_containers: int = 0
    coolify: bool = False
    kubernetes: bool = False
    wireguard: bool = False
    cloud_provider: str = ""
    cloud_hints: List[str] = field(default_factory=list)
    fail2ban: bool = False
    crowdsec: bool = False
    auditd: bool = False
    apparmor: bool = False
    selinux: bool = False
    selinux_mode: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Individual probes
# ---------------------------------------------------------------------------


def _probe_os_release(fs: FakeFS) -> tuple:
    """Return (os_id, os_version) from /etc/os-release."""
    content = fs.read_text("/etc/os-release")
    os_id = ""
    version = ""
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("ID="):
            os_id = line[3:].strip().strip('"')
        elif line.startswith("VERSION_ID="):
            version = line[11:].strip().strip('"')
    return os_id, version


def _probe_architecture() -> str:
    return platform.machine() or "unknown"


def _probe_python_version() -> tuple:
    ver = f"{sys.version_info.major}.{sys.version_info.minor}"
    return ver, (sys.version_info >= (3, 12))


def _probe_docker(fs: FakeFS, runner: FakeRunner) -> tuple:
    """Return (has_socket, has_binary, running_containers)."""
    socket_ok = fs.path_exists("/var/run/docker.sock")
    binary_ok = runner.run(["docker", "--version"]).ok()
    count = 0
    if socket_ok or binary_ok:
        result = runner.run(["docker", "ps", "-q"])
        if result.ok():
            lines = [ln for ln in result.stdout.strip().splitlines() if ln.strip()]
            count = len(lines)
    return socket_ok, binary_ok, count


def _probe_coolify(fs: FakeFS, runner: FakeRunner) -> bool:
    if fs.path_exists("/data/coolify"):
        return True
    result = runner.run(["docker", "ps", "-a", "--filter", "label=coolify", "-q"])
    if result.ok():
        lines = [ln for ln in result.stdout.strip().splitlines() if ln.strip()]
        if lines:
            return True
    return False


def _probe_kubernetes(fs: FakeFS, runner: FakeRunner) -> bool:
    if fs.path_exists("/etc/kubernetes"):
        return True
    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        return True
    result = runner.run(["systemctl", "is-active", "kubelet"])
    if result.ok() and result.stdout.strip() == "active":
        return True
    return False


def _probe_wireguard(fs: FakeFS, runner: FakeRunner) -> bool:
    if fs.path_exists("/etc/wireguard"):
        return True
    result = runner.run(["wg", "show"])
    if result.ok() and result.stdout.strip():
        return True
    return False


def _probe_cloud(fs: FakeFS) -> tuple:
    """Return (provider, hints)."""
    sys_vendor = fs.read_text("/sys/class/dmi/id/sys_vendor", "").strip()
    product_name = fs.read_text("/sys/class/dmi/id/product_name", "").strip()
    chassis_tag = fs.read_text("/sys/class/dmi/id/chassis_asset_tag", "").strip()

    hints = []
    if sys_vendor:
        hints.append(f"sys_vendor={sys_vendor}")
    if product_name:
        hints.append(f"product_name={product_name}")
    if chassis_tag:
        hints.append(f"chassis_asset_tag={chassis_tag}")

    provider = ""
    if "oracle" in sys_vendor.lower() or "oracle" in product_name.lower():
        provider = "oracle"
    elif "amazon" in sys_vendor.lower() or "nitro" in product_name.lower():
        provider = "aws"
    elif "google" in sys_vendor.lower() or "google" in product_name.lower():
        provider = "gcp"
    elif ("microsoft" in sys_vendor.lower() or "microsoft" in product_name.lower()) and chassis_tag:
        provider = "azure"
    return provider, hints


def _probe_fail2ban(runner: FakeRunner) -> bool:
    result = runner.run(["systemctl", "is-active", "fail2ban"])
    if result.ok() and result.stdout.strip() == "active":
        return True
    result = runner.run(["pgrep", "-x", "fail2ban-server"])
    return result.ok()


def _probe_crowdsec(runner: FakeRunner) -> bool:
    result = runner.run(["systemctl", "is-active", "crowdsec"])
    if result.ok() and result.stdout.strip() == "active":
        return True
    result = runner.run(["pgrep", "-x", "csd"])
    return result.ok()


def _probe_auditd(runner: FakeRunner) -> bool:
    result = runner.run(["systemctl", "is-active", "auditd"])
    if result.ok() and result.stdout.strip() == "active":
        return True
    result = runner.run(["pgrep", "-x", "auditd"])
    return result.ok()


def _probe_apparmor(fs: FakeFS, runner: FakeRunner) -> bool:
    if fs.path_exists("/sys/module/apparmor"):
        return True
    result = runner.run(["aa-status"])
    return result.ok()


def _probe_selinux(runner: FakeRunner) -> tuple:
    result = runner.run(["getenforce"])
    if result.ok():
        mode = result.stdout.strip().lower()
        if mode in ("enforcing", "permissive"):
            return True, mode
    return False, ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_env_cache: Optional[Environment] = None


def detect_environment(fs: Optional[FakeFS] = None, runner: Optional[FakeRunner] = None) -> Environment:
    """Detect the current environment and cache the result per process.

    Pass ``fs`` and ``runner`` for testing; they default to real
    filesystem and subprocess access.
    """
    global _env_cache
    if _env_cache is not None:
        return _env_cache

    if fs is None:
        fs = _default_fs()
    if runner is None:
        runner = _default_runner()

    os_id, os_version = _probe_os_release(fs)
    arch = _probe_architecture()
    py_ver, py_ge_312 = _probe_python_version()
    docker_sock, docker_bin, docker_count = _probe_docker(fs, runner)
    coolify = _probe_coolify(fs, runner)
    kubernetes = _probe_kubernetes(fs, runner)
    wireguard = _probe_wireguard(fs, runner)
    cloud_provider, cloud_hints = _probe_cloud(fs)
    fail2ban = _probe_fail2ban(runner)
    crowdsec = _probe_crowdsec(runner)
    auditd = _probe_auditd(runner)
    apparmor = _probe_apparmor(fs, runner)
    selinux, selinux_mode = _probe_selinux(runner)

    env = Environment(
        os_id=os_id,
        os_version=os_version,
        architecture=arch,
        python_version=py_ver,
        python_ge_312=py_ge_312,
        docker_socket=docker_sock,
        docker_binary=docker_bin,
        docker_running_containers=docker_count,
        coolify=coolify,
        kubernetes=kubernetes,
        wireguard=wireguard,
        cloud_provider=cloud_provider,
        cloud_hints=cloud_hints,
        fail2ban=fail2ban,
        crowdsec=crowdsec,
        auditd=auditd,
        apparmor=apparmor,
        selinux=selinux,
        selinux_mode=selinux_mode,
    )
    _env_cache = env
    return env


def reset_environment_cache() -> None:
    """Clear the cached Environment so the next call re-detects."""
    global _env_cache
    _env_cache = None


def is_container_host(env: Environment) -> bool:
    """True if Docker or Kubernetes was detected."""
    return env.docker_socket or env.docker_binary or env.kubernetes


def is_multi_homed(env: Environment) -> bool:
    """True if the host has more than one network interface (excluding lo).

    Uses ``ip -o link show`` and counts lines whose index is not 1 (lo).
    """
    # is_multi_homed does not need fs/runner injected; it is a convenience
    # predicate that other modules can call.  We use the default runner.
    runner = _default_runner()
    result = runner.run(["ip", "-o", "link", "show"])
    if not result.ok():
        logger.warning("is_multi_homed: ip -o link show failed: %s", result.stderr)
        return False
    count = 0
    for line in result.stdout.strip().splitlines():
        parts = line.split(":")
        if len(parts) >= 2 and parts[0].strip() != "1":
            count += 1
    return count > 1
