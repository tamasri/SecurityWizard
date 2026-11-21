"""Container & Docker Runtime Security Auditor."""

import json
import logging

from common import (
    STATUS_CRITICAL,
    STATUS_INFO,
    STATUS_PASS,
    STATUS_WARNING,
    make_check,
    run_cmd,
    skipped_check,
)
from config import get_config

log = logging.getLogger("securitywizard.checks.docker")

DANGEROUS_CAPS = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "ALL"}
# The Docker socket is reported by DOC-003 (with its allowlist) and is deliberately not repeated here.
SENSITIVE_HOST_PATHS = {
    "/",
    "/etc",
    "/root",
    "/home",
    "/boot",
    "/proc",
    "/sys",
    "/var/lib/docker",
}


def analyze_container(inspect_dict: dict, allowlist_fn=None) -> list[dict]:
    """
    Analyze a single container inspect dict and return a list of finding dicts.
    Each finding has: id, title, status, detail, allowed (bool), reason (str).
    allowlist_fn: optional callable that takes (check_id, container_name) and returns a truthy allow entry or None.
    """
    if allowlist_fn is None:
        cfg = get_config()

        def allowlist_fn(check_id, name):
            if check_id == "DOC-003":
                return cfg.allowed_docker_sock(name)
            elif check_id == "DOC-002":
                return cfg.allowed_docker_privileged(name)
            return None

    findings = []
    name = inspect_dict.get("Name", "").lstrip("/")
    host_cfg = inspect_dict.get("HostConfig", {})
    config_cfg = inspect_dict.get("Config", {})

    # DOC-003: docker.sock mounts
    sock_mount = any(m.get("Source") == "/var/run/docker.sock" for m in inspect_dict.get("Mounts", []))
    if sock_mount:
        allowed = allowlist_fn("DOC-003", name)
        findings.append(
            {
                "id": "DOC-003",
                "title": "Container mounts /var/run/docker.sock",
                "status": STATUS_INFO if allowed else STATUS_CRITICAL,
                "detail": f"Container '{name}' mounts /var/run/docker.sock",
                "allowed": bool(allowed),
                "reason": "accepted by configuration" if allowed else "grants full Docker daemon control",
            }
        )

    # DOC-004a: network=host
    if host_cfg.get("NetworkMode") == "host":
        findings.append(
            {
                "id": "DOC-004",
                "title": "Container uses --net=host",
                "status": STATUS_WARNING,
                "detail": f"Container '{name}' uses host network namespace",
                "allowed": False,
                "reason": "removes network isolation boundary",
            }
        )

    # DOC-004b: pid=host
    if host_cfg.get("PidMode") == "host":
        findings.append(
            {
                "id": "DOC-004",
                "title": "Container uses --pid=host",
                "status": STATUS_WARNING,
                "detail": f"Container '{name}' uses host PID namespace",
                "allowed": False,
                "reason": "removes PID isolation boundary",
            }
        )

    # DOC-002: privileged
    if host_cfg.get("Privileged", False):
        allowed = allowlist_fn("DOC-002", name)
        findings.append(
            {
                "id": "DOC-002",
                "title": "Container runs with --privileged",
                "status": STATUS_INFO if allowed else STATUS_CRITICAL,
                "detail": f"Container '{name}' runs in privileged mode",
                "allowed": bool(allowed),
                "reason": "accepted by configuration" if allowed else "grants all capabilities and host device access",
            }
        )

    # DOC-006: added capabilities
    cap_add = host_cfg.get("CapAdd", []) or []
    dangerous = [cap for cap in cap_add if cap in DANGEROUS_CAPS]
    if dangerous:
        findings.append(
            {
                "id": "DOC-006",
                "title": "Container adds dangerous capabilities",
                "status": STATUS_WARNING,
                "detail": f"Container '{name}' adds capabilities: {', '.join(dangerous)}",
                "allowed": False,
                "reason": "SYS_ADMIN/NET_ADMIN/SYS_PTRACE/ALL extend container privileges",
            }
        )

    # DOC-005: root without no-new-privileges
    user = config_cfg.get("User", "")
    if not user or user in ("0", "root"):
        sec_opts = host_cfg.get("SecurityOpt", []) or []
        if "no-new-privileges" not in sec_opts:
            findings.append(
                {
                    "id": "DOC-005",
                    "title": "Container runs as root without no-new-privileges",
                    "status": STATUS_WARNING,
                    "detail": f"Container '{name}' runs as root without no-new-privileges",
                    "allowed": False,
                    "reason": "root process can gain privileges via setuid/setgid or file capabilities",
                }
            )

    # DOC-007: writable host bind mounts of sensitive paths
    for mount in inspect_dict.get("Mounts", []):
        if mount.get("Type") != "bind":
            continue
        source = mount.get("Source", "")
        if source in SENSITIVE_HOST_PATHS and mount.get("RW", True) is not False:
            findings.append(
                {
                    "id": "DOC-007",
                    "title": "Writable host bind mount of sensitive path",
                    "status": STATUS_WARNING,
                    "detail": f"Container '{name}' mounts '{source}' read-write",
                    "allowed": False,
                    "reason": "writable mount of sensitive host path can expose or modify host files",
                }
            )

    return findings


def _docker_available() -> bool:
    """Return True if the docker CLI is present and the daemon is reachable."""
    rc, _, _ = run_cmd(["docker", "info"], timeout=5)
    return rc == 0


def _get_container_ids() -> list[str]:
    """Return a list of running container IDs."""
    rc, stdout, _ = run_cmd(["docker", "ps", "-q"], timeout=10)
    if rc != 0:
        return []
    return [line.strip() for line in stdout.splitlines() if line.strip()]


def _inspect_containers(ids: list[str]) -> list[dict]:
    """Inspect the given container IDs and return a list of JSON dicts."""
    if not ids:
        return []
    rc, stdout, _ = run_cmd(["docker", "inspect"] + ids, timeout=20)
    if rc != 0:
        return []
    try:
        data = json.loads(stdout)
        if isinstance(data, list):
            return data
    except json.JSONDecodeError:
        pass
    return []


def _check_docker_installed() -> dict:
    """DOC-001"""
    ids = _get_container_ids()
    if not _docker_available():
        return make_check(
            "DOC-001",
            "docker",
            "Docker installed and running containers",
            STATUS_INFO,
            "Checks whether the Docker engine is installed and the daemon is reachable on this host.",
            "Without Docker, container-based workloads and their security posture cannot be evaluated.",
            "docker info",
            current_value="Docker not installed or not running",
            recommended_value="Docker installed and daemon running",
        )
    count = len(ids)
    if count == 0:
        return make_check(
            "DOC-001",
            "docker",
            "Docker installed and running containers",
            STATUS_PASS,
            "Checks whether the Docker engine is installed and the daemon is reachable on this host.",
            "Without Docker, container-based workloads and their security posture cannot be evaluated.",
            "docker info",
            current_value="Docker running, 0 containers",
            recommended_value="Docker installed and daemon running",
        )
    return make_check(
        "DOC-001",
        "docker",
        "Docker installed and running containers",
        STATUS_PASS,
        "Checks whether the Docker engine is installed and the daemon is reachable on this host.",
        "Without Docker, container-based workloads and their security posture cannot be evaluated.",
        "docker ps -q",
        current_value=f"Docker running, {count} container(s)",
        recommended_value="Docker installed and daemon running",
        details=[f"{len(ids)} running container(s) found"],
    )


def _check_privileged() -> dict:
    """DOC-002"""
    ids = _get_container_ids()
    containers = _inspect_containers(ids)
    findings = []
    for c in containers:
        for f in analyze_container(c):
            if f["id"] == "DOC-002":
                findings.append(f)
    if not findings:
        return make_check(
            "DOC-002",
            "docker",
            "Containers running in --privileged mode",
            STATUS_PASS,
            "Detects containers started with the --privileged flag, which grants all Linux capabilities and access to host devices.",
            "A privileged container can escape to the host, load kernel modules, and access all devices, effectively giving the attacker root on the host.",
            "docker inspect --format '{{.HostConfig.Privileged}}' <id>",
            current_value="No privileged containers",
            recommended_value="No container should run with --privileged",
        )
    details = [f["detail"] + (" (accepted by configuration)" if f["allowed"] else "") for f in findings]
    status = STATUS_INFO if all(f["allowed"] for f in findings) else STATUS_CRITICAL
    return make_check(
        "DOC-002",
        "docker",
        "Containers running in --privileged mode",
        status,
        "Detects containers started with the --privileged flag, which grants all Linux capabilities and access to host devices.",
        "A privileged container can escape to the host, load kernel modules, and access all devices, effectively giving the attacker root on the host.",
        "docker inspect --format '{{.HostConfig.Privileged}}' <id>",
        current_value=f"{len(findings)} privileged container(s)",
        recommended_value="No container should run with --privileged",
        details=details,
        manual_command="docker update --privileged=false <container>",
    )


def _check_docker_sock() -> dict:
    """DOC-003"""
    ids = _get_container_ids()
    containers = _inspect_containers(ids)
    findings = []
    for c in containers:
        for f in analyze_container(c):
            if f["id"] == "DOC-003":
                findings.append(f)
    if not findings:
        return make_check(
            "DOC-003",
            "docker",
            "Containers mounting /var/run/docker.sock",
            STATUS_PASS,
            "Checks whether any container mounts the host Docker socket, which grants full control of the Docker daemon.",
            "With access to the Docker socket, an attacker can start a privileged container and escape to the host filesystem.",
            "docker inspect --format '{{range .Mounts}}{{.Source}}{{end}}' <id>",
            current_value="No containers mount the Docker socket",
            recommended_value="No container should mount /var/run/docker.sock",
        )
    details = [f["detail"] + (" (accepted by configuration)" if f["allowed"] else "") for f in findings]
    status = STATUS_INFO if all(f["allowed"] for f in findings) else STATUS_CRITICAL
    return make_check(
        "DOC-003",
        "docker",
        "Containers mounting /var/run/docker.sock",
        status,
        "Checks whether any container mounts the host Docker socket, which grants full control of the Docker daemon.",
        "With access to the Docker socket, an attacker can start a privileged container and escape to the host filesystem.",
        "docker inspect --format '{{range .Mounts}}{{.Source}}{{end}}' <id>",
        current_value=f"{len(findings)} container(s) mount the Docker socket",
        recommended_value="No container should mount /var/run/docker.sock",
        details=details,
        manual_command="docker run --rm -v /var/run/docker.sock:/var/run/docker.sock:ro busybox true  # verify, then remove the mount",
    )


def _check_host_namespaces() -> dict:
    """DOC-004"""
    ids = _get_container_ids()
    containers = _inspect_containers(ids)
    findings = []
    for c in containers:
        for f in analyze_container(c):
            if f["id"] == "DOC-004":
                findings.append(f)
    if not findings:
        return make_check(
            "DOC-004",
            "docker",
            "Containers using --net=host or --pid=host",
            STATUS_PASS,
            "Detects containers that share the host network or PID namespace, removing key isolation boundaries.",
            "Host network/PID sharing lets a container sniff all host traffic or see and signal host processes, weakening isolation.",
            "docker inspect --format '{{.HostConfig.NetworkMode}} {{.HostConfig.PidMode}}' <id>",
            current_value="No containers share host namespaces",
            recommended_value="Containers should use their own network and PID namespaces",
        )
    details = [f["detail"] for f in findings]
    return make_check(
        "DOC-004",
        "docker",
        "Containers using --net=host or --pid=host",
        STATUS_WARNING,
        "Detects containers that share the host network or PID namespace, removing key isolation boundaries.",
        "Host network/PID sharing lets a container sniff all host traffic or see and signal host processes, weakening isolation.",
        "docker inspect --format '{{.HostConfig.NetworkMode}} {{.HostConfig.PidMode}}' <id>",
        current_value=f"{len(findings)} container(s) share host namespaces",
        recommended_value="Containers should use their own network and PID namespaces",
        details=details,
        manual_command="docker run --rm --net=bridge --pid=private busybox true  # recreate without host namespaces",
    )


def _check_root_no_new_privs() -> dict:
    """DOC-005"""
    ids = _get_container_ids()
    containers = _inspect_containers(ids)
    findings = []
    for c in containers:
        for f in analyze_container(c):
            if f["id"] == "DOC-005":
                findings.append(f)
    if not findings:
        return make_check(
            "DOC-005",
            "docker",
            "Containers running as root without no-new-privileges",
            STATUS_PASS,
            "Checks containers running as UID 0 that lack the no-new-privileges security option, which prevents privilege escalation.",
            "A root process without no-new-privileges can gain more privileges via setuid/setgid binaries or file capabilities, aiding escape.",
            "docker inspect --format '{{.Config.User}} {{.HostConfig.SecurityOpt}}' <id>",
            current_value="All root containers have no-new-privileges",
            recommended_value="Root containers should set --security-opt no-new-privileges",
        )
    details = [f["detail"] for f in findings]
    return make_check(
        "DOC-005",
        "docker",
        "Containers running as root without no-new-privileges",
        STATUS_WARNING,
        "Checks containers running as UID 0 that lack the no-new-privileges security option, which prevents privilege escalation.",
        "A root process without no-new-privileges can gain more privileges via setuid/setgid binaries or file capabilities, aiding escape.",
        "docker inspect --format '{{.Config.User}} {{.HostConfig.SecurityOpt}}' <id>",
        current_value=f"{len(findings)} root container(s) lack no-new-privileges",
        recommended_value="Root containers should set --security-opt no-new-privileges",
        details=details,
        manual_command="docker update --security-opt no-new-privileges <container>",
    )


def _check_added_capabilities() -> dict:
    """DOC-006"""
    ids = _get_container_ids()
    containers = _inspect_containers(ids)
    findings = []
    for c in containers:
        for f in analyze_container(c):
            if f["id"] == "DOC-006":
                findings.append(f)
    if not findings:
        return make_check(
            "DOC-006",
            "docker",
            "Containers with added dangerous capabilities",
            STATUS_PASS,
            "Checks whether containers add capabilities such as SYS_ADMIN, NET_ADMIN, SYS_PTRACE, or ALL beyond the default set.",
            "Added capabilities like SYS_ADMIN or NET_ADMIN can allow a container to modify host network settings or access host devices, increasing escape risk.",
            "docker inspect --format '{{.HostConfig.CapAdd}}' <id>",
            current_value="No containers add dangerous capabilities",
            recommended_value="Containers should avoid adding dangerous capabilities",
        )
    details = [f["detail"] for f in findings]
    return make_check(
        "DOC-006",
        "docker",
        "Containers with added dangerous capabilities",
        STATUS_WARNING,
        "Checks whether containers add capabilities such as SYS_ADMIN, NET_ADMIN, SYS_PTRACE, or ALL beyond the default set.",
        "Added capabilities like SYS_ADMIN or NET_ADMIN can allow a container to modify host network settings or access host devices, increasing escape risk.",
        "docker inspect --format '{{.HostConfig.CapAdd}}' <id>",
        current_value=f"{len(findings)} container(s) add dangerous capabilities",
        recommended_value="Containers should avoid adding dangerous capabilities",
        details=details,
        manual_command="docker run --rm --cap-add=NET_ADMIN busybox true  # recreate without the added capability",
    )


def _check_sensitive_mounts() -> dict:
    """DOC-007"""
    ids = _get_container_ids()
    containers = _inspect_containers(ids)
    findings = []
    for c in containers:
        for f in analyze_container(c):
            if f["id"] == "DOC-007":
                findings.append(f)
    if not findings:
        return make_check(
            "DOC-007",
            "docker",
            "Writable host bind mounts of sensitive paths",
            STATUS_PASS,
            "Checks whether containers mount sensitive host paths such as /, /etc, /root, /home, /boot, /proc, /sys, /var/run/docker.sock, or /var/lib/docker in read-write mode.",
            "Writable mounts of sensitive host paths can expose host files to the container or allow the container to modify critical host configuration.",
            "docker inspect --format '{{range .Mounts}}{{.Source}} {{.RW}}{{end}}' <id>",
            current_value="No writable mounts of sensitive host paths",
            recommended_value="Sensitive host paths should be mounted read-only or not at all",
        )
    details = [f["detail"] for f in findings]
    return make_check(
        "DOC-007",
        "docker",
        "Writable host bind mounts of sensitive paths",
        STATUS_WARNING,
        "Checks whether containers mount sensitive host paths such as /, /etc, /root, /home, /boot, /proc, /sys, /var/run/docker.sock, or /var/lib/docker in read-write mode.",
        "Writable mounts of sensitive host paths can expose host files to the container or allow the container to modify critical host configuration.",
        "docker inspect --format '{{range .Mounts}}{{.Source}} {{.RW}}{{end}}' <id>",
        current_value=f"{len(findings)} writable mount(s) of sensitive host paths",
        recommended_value="Sensitive host paths should be mounted read-only or not at all",
        details=details,
        manual_command="docker run --rm -v /etc:/etc:ro busybox true  # recreate with read-only mount",
    )


def run_checks() -> list[dict]:
    checks = []
    for func in (
        _check_docker_installed,
        _check_privileged,
        _check_docker_sock,
        _check_host_namespaces,
        _check_root_no_new_privs,
        _check_added_capabilities,
        _check_sensitive_mounts,
    ):
        try:
            checks.append(func())
        except Exception as exc:
            cid = func.__doc__.strip() if func.__doc__ else "DOC-ERR"
            log.exception("Docker check %s failed", cid)
            checks.append(
                skipped_check(
                    cid,
                    "docker",
                    func.__doc__ or "Docker check",
                    "An internal check for Docker runtime security.",
                    "An error prevented this Docker check from completing.",
                    "internal",
                    str(exc),
                )
            )
    return checks
