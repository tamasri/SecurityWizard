from checks_docker import _check_privileged, analyze_container
from common import STATUS_CRITICAL, STATUS_INFO, STATUS_WARNING


def _make_inspect(
    name, privileged=False, net_mode="", pid_mode="", user="", security_opt=None, cap_add=None, mounts=None
):
    return {
        "Name": "/" + name,
        "HostConfig": {
            "Privileged": privileged,
            "NetworkMode": net_mode,
            "PidMode": pid_mode,
            "SecurityOpt": security_opt or [],
            "CapAdd": cap_add or [],
        },
        "Config": {
            "User": user,
        },
        "Mounts": mounts or [],
    }


def test_privileged_container():
    inspect_dict = _make_inspect("proxy", privileged=True)
    findings = analyze_container(inspect_dict, allowlist_fn=lambda cid, name: None)
    assert any(f["id"] == "DOC-002" and f["status"] == STATUS_CRITICAL for f in findings)


def test_privileged_container_allowlisted():
    """Test that a privileged container becomes INFO when allowlisted by config."""
    inspect_dict = _make_inspect("proxy", privileged=True)
    findings = analyze_container(
        inspect_dict,
        allowlist_fn=lambda cid, name: {"reason": "allowed"} if cid == "DOC-002" and name == "proxy" else None,
    )
    doc002 = [f for f in findings if f["id"] == "DOC-002"]
    assert doc002 and doc002[0]["status"] == STATUS_INFO and doc002[0]["allowed"] is True


def test_docker_sock_mount():
    mounts = [{"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock", "RW": True}]
    inspect_dict = _make_inspect("coolify", mounts=mounts)
    findings = analyze_container(inspect_dict, allowlist_fn=lambda cid, name: None)
    assert any(f["id"] == "DOC-003" and f["status"] == STATUS_CRITICAL for f in findings)


def test_docker_sock_mount_allowlisted():
    mounts = [{"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock", "RW": True}]
    inspect_dict = _make_inspect("coolify", mounts=mounts)
    findings = analyze_container(
        inspect_dict, allowlist_fn=lambda cid, name: {"reason": "allowed"} if name == "coolify" else None
    )
    doc003 = [f for f in findings if f["id"] == "DOC-003"]
    assert doc003 and doc003[0]["status"] == STATUS_INFO and doc003[0]["allowed"] is True


def test_host_pid():
    inspect_dict = _make_inspect("monitor", pid_mode="host")
    findings = analyze_container(inspect_dict, allowlist_fn=lambda cid, name: None)
    assert any(f["id"] == "DOC-004" and "PID namespace" in f["detail"] for f in findings)


def test_root_without_no_new_privileges():
    inspect_dict = _make_inspect("app", user="root", security_opt=[])
    findings = analyze_container(inspect_dict, allowlist_fn=lambda cid, name: None)
    assert any(f["id"] == "DOC-005" and f["status"] == STATUS_WARNING for f in findings)


def test_clean_container():
    inspect_dict = _make_inspect("clean", user="1000", security_opt=["no-new-privileges"])
    findings = analyze_container(inspect_dict, allowlist_fn=lambda cid, name: None)
    assert findings == []


def test_dangerous_cap_add():
    inspect_dict = _make_inspect("netapp", cap_add=["NET_ADMIN", "SYS_PTRACE"])
    findings = analyze_container(inspect_dict, allowlist_fn=lambda cid, name: None)
    assert any(f["id"] == "DOC-006" and f["status"] == STATUS_WARNING for f in findings)


def test_sensitive_writable_mount():
    mounts = [{"Type": "bind", "Source": "/etc", "Destination": "/etc", "RW": True}]
    inspect_dict = _make_inspect("configurator", mounts=mounts)
    findings = analyze_container(inspect_dict, allowlist_fn=lambda cid, name: None)
    assert any(f["id"] == "DOC-007" and f["status"] == STATUS_WARNING for f in findings)


def test_check_privileged_allowlisted(monkeypatch):
    """Regression test: _check_privileged must return INFO when the container is allowlisted."""
    inspect_dict = _make_inspect("proxy", privileged=True)
    monkeypatch.setattr("checks_docker._get_container_ids", lambda: ["abc123"])
    monkeypatch.setattr("checks_docker._inspect_containers", lambda ids: [inspect_dict])

    class FakeConfig:
        def allowed_docker_privileged(self, name):
            if name == "proxy":
                return {"reason": "allowed"}
            return None

    monkeypatch.setattr("checks_docker.get_config", lambda: FakeConfig())

    result = _check_privileged()
    assert result["status"] == STATUS_INFO
    assert result["details"] == ["Container 'proxy' runs in privileged mode (accepted by configuration)"]
