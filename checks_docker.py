"""Container & Docker Runtime Security Auditor."""

import json
from common import (
    run_cmd,
    make_check,
    skipped_check,
    STATUS_PASS,
    STATUS_WARNING,
    STATUS_CRITICAL,
    STATUS_INFO,
    STATUS_SKIPPED,
)


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
            "DOC-001", "docker", "Docker installed and running containers", STATUS_INFO,
            "Checks whether the Docker engine is installed and the daemon is reachable on this host.",
            "Without Docker, container-based workloads and their security posture cannot be evaluated.",
            "docker info",
            current_value="Docker not installed or not running",
            recommended_value="Docker installed and daemon running",
        )
    count = len(ids)
    if count == 0:
        return make_check(
            "DOC-001", "docker", "Docker installed and running containers", STATUS_PASS,
            "Checks whether the Docker engine is installed and the daemon is reachable on this host.",
            "Without Docker, container-based workloads and their security posture cannot be evaluated.",
            "docker info",
            current_value="Docker running, 0 containers",
            recommended_value="Docker installed and daemon running",
        )
    return make_check(
        "DOC-001", "docker", "Docker installed and running containers", STATUS_PASS,
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
    privileged = []
    for c in containers:
        if c.get("HostConfig", {}).get("Privileged", False):
            privileged.append(c.get("Name", "").lstrip("/"))
    if not privileged:
        return make_check(
            "DOC-002", "docker", "Containers running in --privileged mode", STATUS_PASS,
            "Detects containers started with the --privileged flag, which grants all Linux capabilities and access to host devices.",
            "A privileged container can escape to the host, load kernel modules, and access all devices, effectively giving the attacker root on the host.",
            "docker inspect --format '{{.HostConfig.Privileged}}' <id>",
            current_value="No privileged containers",
            recommended_value="No container should run with --privileged",
        )
    return make_check(
        "DOC-002", "docker", "Containers running in --privileged mode", STATUS_CRITICAL,
        "Detects containers started with the --privileged flag, which grants all Linux capabilities and access to host devices.",
        "A privileged container can escape to the host, load kernel modules, and access all devices, effectively giving the attacker root on the host.",
        "docker inspect --format '{{.HostConfig.Privileged}}' <id>",
        current_value=f"{len(privileged)} privileged container(s)",
        recommended_value="No container should run with --privileged",
        details=[f"Privileged: {name}" for name in privileged],
        manual_command="docker update --privileged=false <container>",
    )


def _check_docker_sock() -> dict:
    """DOC-003"""
    ids = _get_container_ids()
    containers = _inspect_containers(ids)
    sock_mounts = []
    for c in containers:
        name = c.get("Name", "").lstrip("/")
        for m in c.get("Mounts", []):
            if m.get("Source") == "/var/run/docker.sock":
                sock_mounts.append(name)
                break
    if not sock_mounts:
        return make_check(
            "DOC-003", "docker", "Containers mounting /var/run/docker.sock", STATUS_PASS,
            "Checks whether any container mounts the host Docker socket, which grants full control of the Docker daemon.",
            "With access to the Docker socket, an attacker can start a privileged container and escape to the host filesystem.",
            "docker inspect --format '{{range .Mounts}}{{.Source}}{{end}}' <id>",
            current_value="No containers mount the Docker socket",
            recommended_value="No container should mount /var/run/docker.sock",
        )
    return make_check(
        "DOC-003", "docker", "Containers mounting /var/run/docker.sock", STATUS_CRITICAL,
        "Checks whether any container mounts the host Docker socket, which grants full control of the Docker daemon.",
        "With access to the Docker socket, an attacker can start a privileged container and escape to the host filesystem.",
        "docker inspect --format '{{range .Mounts}}{{.Source}}{{end}}' <id>",
        current_value=f"{len(sock_mounts)} container(s) mount the Docker socket",
        recommended_value="No container should mount /var/run/docker.sock",
        details=[f"Mounts docker.sock: {name}" for name in sock_mounts],
        manual_command="docker run --rm -v /var/run/docker.sock:/var/run/docker.sock:ro busybox true  # verify, then remove the mount",
    )


def _check_host_namespaces() -> dict:
    """DOC-004"""
    ids = _get_container_ids()
    containers = _inspect_containers(ids)
    offenders = []
    for c in containers:
        name = c.get("Name", "").lstrip("/")
        host_cfg = c.get("HostConfig", {})
        net_mode = host_cfg.get("NetworkMode", "")
        pid_mode = host_cfg.get("PidMode", "")
        reasons = []
        if net_mode == "host":
            reasons.append("net=host")
        if pid_mode == "host":
            reasons.append("pid=host")
        if reasons:
            offenders.append((name, reasons))
    if not offenders:
        return make_check(
            "DOC-004", "docker", "Containers using --net=host or --pid=host", STATUS_PASS,
            "Detects containers that share the host network or PID namespace, removing key isolation boundaries.",
            "Host network/PID sharing lets a container sniff all host traffic or see and signal host processes, weakening isolation.",
            "docker inspect --format '{{.HostConfig.NetworkMode}} {{.HostConfig.PidMode}}' <id>",
            current_value="No containers share host namespaces",
            recommended_value="Containers should use their own network and PID namespaces",
        )
    details = [f"{name}: {', '.join(reasons)}" for name, reasons in offenders]
    return make_check(
        "DOC-004", "docker", "Containers using --net=host or --pid=host", STATUS_WARNING,
        "Detects containers that share the host network or PID namespace, removing key isolation boundaries.",
        "Host network/PID sharing lets a container sniff all host traffic or see and signal host processes, weakening isolation.",
        "docker inspect --format '{{.HostConfig.NetworkMode}} {{.HostConfig.PidMode}}' <id>",
        current_value=f"{len(offenders)} container(s) share host namespaces",
        recommended_value="Containers should use their own network and PID namespaces",
        details=details,
        manual_command="docker run --rm --net=bridge --pid=private busybox true  # recreate without host namespaces",
    )


def _check_root_no_new_privs() -> dict:
    """DOC-005"""
    ids = _get_container_ids()
    containers = _inspect_containers(ids)
    offenders = []
    for c in containers:
        name = c.get("Name", "").lstrip("/")
        user = c.get("Config", {}).get("User", "")
        if user and user not in ("0", "root"):
            continue
        sec_opts = c.get("HostConfig", {}).get("SecurityOpt", []) or []
        if "no-new-privileges" not in sec_opts:
            offenders.append(name)
    if not offenders:
        return make_check(
            "DOC-005", "docker", "Containers running as root without no-new-privileges", STATUS_PASS,
            "Checks containers running as UID 0 that lack the no-new-privileges security option, which prevents privilege escalation.",
            "A root process without no-new-privileges can gain more privileges via setuid/setgid binaries or file capabilities, aiding escape.",
            "docker inspect --format '{{.Config.User}} {{.HostConfig.SecurityOpt}}' <id>",
            current_value="All root containers have no-new-privileges",
            recommended_value="Root containers should set --security-opt no-new-privileges",
        )
    return make_check(
        "DOC-005", "docker", "Containers running as root without no-new-privileges", STATUS_WARNING,
        "Checks containers running as UID 0 that lack the no-new-privileges security option, which prevents privilege escalation.",
        "A root process without no-new-privileges can gain more privileges via setuid/setgid binaries or file capabilities, aiding escape.",
        "docker inspect --format '{{.Config.User}} {{.HostConfig.SecurityOpt}}' <id>",
        current_value=f"{len(offenders)} root container(s) lack no-new-privileges",
        recommended_value="Root containers should set --security-opt no-new-privileges",
        details=[f"Root without no-new-privileges: {name}" for name in offenders],
        manual_command="docker update --security-opt no-new-privileges <container>",
    )


def run_checks() -> list[dict]:
    checks = []
    for func in (_check_docker_installed, _check_privileged, _check_docker_sock, _check_host_namespaces, _check_root_no_new_privs):
        try:
            checks.append(func())
        except Exception as exc:
            cid = func.__doc__.strip() if func.__doc__ else "DOC-ERR"
            checks.append(skipped_check(
                cid, "docker", func.__doc__ or "Docker check",
                "An internal check for Docker runtime security.",
                "An error prevented this Docker check from completing.",
                "internal", str(exc),
            ))
    return checks
