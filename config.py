import logging
import os
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Dict, List, Optional

try:
    import tomllib
except ImportError:
    import tomli as tomllib

logger = logging.getLogger(__name__)


class ConfigError(Exception):
    """Raised when the configuration file is malformed or has wrong types."""


@dataclass
class ListenerAllow:
    port: int
    process: Optional[str] = None
    reason: str = ""


@dataclass
class DockerSockAllow:
    name: str
    reason: str = ""


@dataclass
class DockerPublicPortAllow:
    port: int
    container: Optional[str] = None
    reason: str = ""


@dataclass
class DockerPrivilegedAllow:
    name: str
    reason: str = ""


@dataclass
class SudoRuleAllow:
    user: str
    command: str
    reason: str = ""


@dataclass
class SuidFileAllow:
    path: str
    reason: str = ""


@dataclass
class AcceptedRisk:
    check_id: str
    reason: str
    expires: Optional[str] = None
    match: Optional[str] = None


@dataclass
class Config:
    listeners: List[ListenerAllow] = field(default_factory=list)
    docker_sock_containers: List[DockerSockAllow] = field(default_factory=list)
    docker_public_ports: List[DockerPublicPortAllow] = field(default_factory=list)
    docker_privileged: List[DockerPrivilegedAllow] = field(default_factory=list)
    sudo_rules: List[SudoRuleAllow] = field(default_factory=list)
    suid_files: List[SuidFileAllow] = field(default_factory=list)
    accepted_risks: List[AcceptedRisk] = field(default_factory=list)

    def is_accepted(self, check_id: str, evidence: str = "") -> Optional[AcceptedRisk]:
        for risk in self.accepted_risks:
            if risk.check_id != check_id:
                continue
            if risk.match is not None:
                if risk.match not in evidence:
                    continue
            if risk.expires:
                try:
                    exp_date = datetime.strptime(risk.expires, "%Y-%m-%d").date()
                    if date.today() > exp_date:
                        continue
                except ValueError:
                    logger.warning(
                        "Invalid expires date '%s' for risk %s, treating as no expiry", risk.expires, check_id
                    )
            return risk
        return None

    def allowed_listener(self, port: int, process: Optional[str] = None) -> Optional[ListenerAllow]:
        for entry in self.listeners:
            if entry.port != port:
                continue
            if entry.process is not None and process is not None and entry.process != process:
                continue
            return entry
        return None

    def allowed_docker_sock(self, name: str) -> Optional[DockerSockAllow]:
        for entry in self.docker_sock_containers:
            if entry.name == name:
                return entry
        return None

    def allowed_docker_privileged(self, name: str) -> Optional[DockerPrivilegedAllow]:
        for entry in self.docker_privileged:
            if entry.name == name:
                return entry
        return None

    def allowed_public_port(self, port: int, container: Optional[str] = None) -> Optional[DockerPublicPortAllow]:
        for entry in self.docker_public_ports:
            if entry.port != port:
                continue
            if entry.container is not None and container is not None and entry.container != container:
                continue
            return entry
        return None

    def allowed_sudo_rule(self, user: str, command: str) -> Optional[SudoRuleAllow]:
        for entry in self.sudo_rules:
            if entry.user == user and entry.command == command:
                return entry
        return None

    def allowed_suid(self, path: str) -> Optional[SuidFileAllow]:
        for entry in self.suid_files:
            if entry.path == path:
                return entry
        return None


_config_cache: Optional[Config] = None


def _find_config_path() -> Optional[str]:
    env_path = os.environ.get("SECURITYWIZARD_CONFIG")
    if env_path:
        return env_path
    local_path = "./securitywizard.toml"
    if os.path.exists(local_path):
        return local_path
    etc_path = "/etc/securitywizard/config.toml"
    if os.path.exists(etc_path):
        return etc_path
    return None


def _validate_listener(entry: Any, index: int) -> ListenerAllow:
    if not isinstance(entry, dict):
        raise ConfigError(f"allow.listeners[{index}] must be a table")
    port = entry.get("port")
    if not isinstance(port, int):
        raise ConfigError(f"allow.listeners[{index}].port must be an integer")
    process = entry.get("process")
    if process is not None and not isinstance(process, str):
        raise ConfigError(f"allow.listeners[{index}].process must be a string")
    reason = entry.get("reason", "")
    if not isinstance(reason, str):
        raise ConfigError(f"allow.listeners[{index}].reason must be a string")
    return ListenerAllow(port=port, process=process, reason=reason)


def _validate_docker_sock(entry: Any, index: int) -> DockerSockAllow:
    if not isinstance(entry, dict):
        raise ConfigError(f"allow.docker_sock_containers[{index}] must be a table")
    name = entry.get("name")
    if not isinstance(name, str):
        raise ConfigError(f"allow.docker_sock_containers[{index}].name must be a string")
    reason = entry.get("reason", "")
    if not isinstance(reason, str):
        raise ConfigError(f"allow.docker_sock_containers[{index}].reason must be a string")
    return DockerSockAllow(name=name, reason=reason)


def _validate_docker_public_port(entry: Any, index: int) -> DockerPublicPortAllow:
    if not isinstance(entry, dict):
        raise ConfigError(f"allow.docker_public_ports[{index}] must be a table")
    port = entry.get("port")
    if not isinstance(port, int):
        raise ConfigError(f"allow.docker_public_ports[{index}].port must be an integer")
    container = entry.get("container")
    if container is not None and not isinstance(container, str):
        raise ConfigError(f"allow.docker_public_ports[{index}].container must be a string")
    reason = entry.get("reason", "")
    if not isinstance(reason, str):
        raise ConfigError(f"allow.docker_public_ports[{index}].reason must be a string")
    return DockerPublicPortAllow(port=port, container=container, reason=reason)


def _validate_docker_privileged(entry: Any, index: int) -> DockerPrivilegedAllow:
    if not isinstance(entry, dict):
        raise ConfigError(f"allow.docker_privileged[{index}] must be a table")
    name = entry.get("name")
    if not isinstance(name, str):
        raise ConfigError(f"allow.docker_privileged[{index}].name must be a string")
    reason = entry.get("reason", "")
    if not isinstance(reason, str):
        raise ConfigError(f"allow.docker_privileged[{index}].reason must be a string")
    return DockerPrivilegedAllow(name=name, reason=reason)


def _validate_sudo_rule(entry: Any, index: int) -> SudoRuleAllow:
    if not isinstance(entry, dict):
        raise ConfigError(f"allow.sudo_rules[{index}] must be a table")
    user = entry.get("user")
    if not isinstance(user, str):
        raise ConfigError(f"allow.sudo_rules[{index}].user must be a string")
    command = entry.get("command")
    if not isinstance(command, str):
        raise ConfigError(f"allow.sudo_rules[{index}].command must be a string")
    reason = entry.get("reason", "")
    if not isinstance(reason, str):
        raise ConfigError(f"allow.sudo_rules[{index}].reason must be a string")
    return SudoRuleAllow(user=user, command=command, reason=reason)


def _validate_suid_file(entry: Any, index: int) -> SuidFileAllow:
    if not isinstance(entry, dict):
        raise ConfigError(f"allow.suid_files[{index}] must be a table")
    path = entry.get("path")
    if not isinstance(path, str):
        raise ConfigError(f"allow.suid_files[{index}].path must be a string")
    reason = entry.get("reason", "")
    if not isinstance(reason, str):
        raise ConfigError(f"allow.suid_files[{index}].reason must be a string")
    return SuidFileAllow(path=path, reason=reason)


def _validate_accepted_risk(entry: Any, index: int) -> AcceptedRisk:
    if not isinstance(entry, dict):
        raise ConfigError(f"accepted_risks[{index}] must be a table")
    check_id = entry.get("check_id")
    if not isinstance(check_id, str):
        raise ConfigError(f"accepted_risks[{index}].check_id must be a string")
    reason = entry.get("reason")
    if not isinstance(reason, str):
        raise ConfigError(f"accepted_risks[{index}].reason must be a string")
    expires = entry.get("expires")
    if expires is not None and not isinstance(expires, str):
        raise ConfigError(f"accepted_risks[{index}].expires must be a string")
    match = entry.get("match")
    if match is not None and not isinstance(match, str):
        raise ConfigError(f"accepted_risks[{index}].match must be a string")
    return AcceptedRisk(check_id=check_id, reason=reason, expires=expires, match=match)


def _parse_config(data: Dict[str, Any]) -> Config:
    config = Config()

    allow = data.get("allow", {})
    if not isinstance(allow, dict):
        raise ConfigError("'allow' must be a table")

    for key in allow:
        if key not in (
            "listeners",
            "docker_sock_containers",
            "docker_public_ports",
            "docker_privileged",
            "sudo_rules",
            "suid_files",
        ):
            logger.warning("Unknown key in [allow]: %s", key)

    listeners = allow.get("listeners", [])
    if not isinstance(listeners, list):
        raise ConfigError("allow.listeners must be an array")
    for i, entry in enumerate(listeners):
        config.listeners.append(_validate_listener(entry, i))

    docker_sock = allow.get("docker_sock_containers", [])
    if not isinstance(docker_sock, list):
        raise ConfigError("allow.docker_sock_containers must be an array")
    for i, entry in enumerate(docker_sock):
        config.docker_sock_containers.append(_validate_docker_sock(entry, i))

    docker_ports = allow.get("docker_public_ports", [])
    if not isinstance(docker_ports, list):
        raise ConfigError("allow.docker_public_ports must be an array")
    for i, entry in enumerate(docker_ports):
        config.docker_public_ports.append(_validate_docker_public_port(entry, i))

    docker_priv = allow.get("docker_privileged", [])
    if not isinstance(docker_priv, list):
        raise ConfigError("allow.docker_privileged must be an array")
    for i, entry in enumerate(docker_priv):
        config.docker_privileged.append(_validate_docker_privileged(entry, i))

    sudo_rules = allow.get("sudo_rules", [])
    if not isinstance(sudo_rules, list):
        raise ConfigError("allow.sudo_rules must be an array")
    for i, entry in enumerate(sudo_rules):
        config.sudo_rules.append(_validate_sudo_rule(entry, i))

    suid_files = allow.get("suid_files", [])
    if not isinstance(suid_files, list):
        raise ConfigError("allow.suid_files must be an array")
    for i, entry in enumerate(suid_files):
        config.suid_files.append(_validate_suid_file(entry, i))

    accepted_risks = data.get("accepted_risk", [])
    if not isinstance(accepted_risks, list):
        raise ConfigError("accepted_risk must be an array of tables")
    for i, entry in enumerate(accepted_risks):
        config.accepted_risks.append(_validate_accepted_risk(entry, i))

    for section in ("auth", "server"):
        if section in data:
            logger.debug("Ignoring reserved section [%s]", section)

    return config


def load_config(path: Optional[str] = None) -> Config:
    global _config_cache
    if path is None:
        path = _find_config_path()
    if path is None or not os.path.exists(path):
        _config_cache = Config()
        return _config_cache
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"Invalid TOML in {path}: {e}") from e
    except Exception as e:
        raise ConfigError(f"Error reading {path}: {e}") from e
    _config_cache = _parse_config(data)
    return _config_cache


def get_config() -> Config:
    if _config_cache is None:
        return load_config()
    return _config_cache


def reset_config() -> None:
    global _config_cache
    _config_cache = None


def example_config() -> str:
    return """# SecurityWizard configuration
# Place this file at ./securitywizard.toml or /etc/securitywizard/config.toml

[allow]
# Accepted public listeners (port + optional process name)
listeners = [
    {port = 80, process = "traefik", reason = "HTTP entrypoint"},
    {port = 443, process = "traefik", reason = "HTTPS entrypoint"},
]

# Containers allowed to mount /var/run/docker.sock
docker_sock_containers = [
    {name = "coolify", reason = "Orchestrates containers"},
]

# Published Docker ports intended to be publicly reachable
docker_public_ports = [
    {port = 80, container = "traefik", reason = "Public HTTP"},
    {port = 443, container = "traefik", reason = "Public HTTPS"},
]

# Privileged containers that are expected
docker_privileged = [
    {name = "coolify", reason = "Needs privileged mode for orchestration"},
]

# Narrow sudoers entries that are expected
sudo_rules = [
    {user = "deploy", command = "/usr/bin/systemctl restart myapp", reason = "Deploy key restarts app"},
]

# SUID files that are expected
suid_files = [
    {path = "/usr/bin/passwd", reason = "Standard SUID binary"},
]

# Accepted risks: suppress specific findings with a reason and optional expiry
[[accepted_risk]]
check_id = "ssh_password_auth"
reason = "Password auth disabled via Match block for specific users"
expires = "2025-12-31"

[[accepted_risk]]
check_id = "kernel_sysctl"
reason = "Non-default value required for container networking"
match = "net.ipv4.ip_forward"
"""
