"""checks_docker: every container finding and every DOC check, with `docker` fully mocked."""

import json

import pytest

import checks_docker
from common import STATUS_CRITICAL, STATUS_INFO, STATUS_PASS, STATUS_SKIPPED, STATUS_WARNING, CmdResult


def container(name="web", **overrides):
    """A minimal, clean `docker inspect` document."""
    data = {
        "Name": "/" + name,
        "HostConfig": {
            "Privileged": False,
            "NetworkMode": "bridge",
            "PidMode": "",
            "CapAdd": None,
            "SecurityOpt": ["no-new-privileges"],
        },
        "Config": {"User": "1000"},
        "Mounts": [],
    }
    for key, value in overrides.items():
        if key in data["HostConfig"]:
            data["HostConfig"][key] = value
        elif key == "User":
            data["Config"]["User"] = value
        else:
            data[key] = value
    return data


def _docker(monkeypatch, containers, available=True):
    monkeypatch.setattr(checks_docker, "_docker_available", lambda: available)
    monkeypatch.setattr(checks_docker, "_get_container_ids", lambda: [c["Name"] for c in containers])
    monkeypatch.setattr(checks_docker, "_inspect_containers", lambda ids: containers)


@pytest.fixture(autouse=True)
def no_allowlist(monkeypatch):
    """The default configuration allows nothing."""
    import config

    config.reset_config()
    monkeypatch.setenv("SECURITYWIZARD_CONFIG", "/nonexistent/securitywizard.toml")
    yield
    config.reset_config()


# ---- analyze_container -------------------------------------------------------------------------------------------------


def ids(findings):
    return sorted(f["id"] for f in findings)


def test_clean_container_has_no_findings():
    assert checks_docker.analyze_container(container()) == []


def test_each_risk_is_reported_by_container_name():
    risky = container(
        "proxy",
        Privileged=True,
        NetworkMode="host",
        PidMode="host",
        CapAdd=["SYS_ADMIN", "CHOWN", "NET_ADMIN"],
        SecurityOpt=[],
        User="",
        Mounts=[
            {"Type": "bind", "Source": "/var/run/docker.sock", "RW": True},
            {"Type": "bind", "Source": "/etc", "RW": True},
            {"Type": "bind", "Source": "/etc", "RW": False},  # read-only: harmless
            {"Type": "volume", "Source": "/etc", "RW": True},  # not a bind mount
            {"Type": "bind", "Source": "/srv/data", "RW": True},
        ],
    )
    findings = checks_docker.analyze_container(risky)
    assert ids(findings) == ["DOC-002", "DOC-003", "DOC-004", "DOC-004", "DOC-005", "DOC-006", "DOC-007"]
    assert all("proxy" in f["detail"] for f in findings)
    caps = next(f for f in findings if f["id"] == "DOC-006")
    assert "SYS_ADMIN" in caps["detail"] and "NET_ADMIN" in caps["detail"] and "CHOWN" not in caps["detail"]


def test_root_user_variants():
    for user, expected in (("", True), ("0", True), ("root", True), ("1000", False), ("app", False)):
        found = [
            f for f in checks_docker.analyze_container(container(User=user, SecurityOpt=[])) if f["id"] == "DOC-005"
        ]
        assert bool(found) is expected, user


def test_no_new_privileges_silences_the_root_finding():
    assert checks_docker.analyze_container(container(User="root", SecurityOpt=["no-new-privileges"])) == []


def test_allowlist_function_marks_findings_as_accepted():
    risky = container("coolify", Privileged=True, Mounts=[{"Type": "bind", "Source": "/var/run/docker.sock"}])
    findings = checks_docker.analyze_container(risky, allowlist_fn=lambda check_id, name: {"reason": "ok"})
    assert findings and all(
        f["allowed"] and f["status"] == STATUS_INFO for f in findings if f["id"] in ("DOC-002", "DOC-003")
    )


def test_default_allowlist_comes_from_the_configuration(tmp_path, monkeypatch):
    import config

    cfg = tmp_path / "securitywizard.toml"
    cfg.write_text(
        "[allow]\n"
        'docker_sock_containers = [{name = "coolify", reason = "orchestrator"}]\n'
        'docker_privileged = [{name = "coolify", reason = "host metrics"}]\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("SECURITYWIZARD_CONFIG", str(cfg))
    config.reset_config()
    risky = container("coolify", Privileged=True, Mounts=[{"Type": "bind", "Source": "/var/run/docker.sock"}])
    other = container("stranger", Privileged=True, Mounts=[{"Type": "bind", "Source": "/var/run/docker.sock"}])
    assert all(f["allowed"] for f in checks_docker.analyze_container(risky))
    assert not any(f["allowed"] for f in checks_docker.analyze_container(other))


# ---- docker CLI helpers ------------------------------------------------------------------------------------------------


def test_docker_available_follows_docker_info(monkeypatch):
    monkeypatch.setattr(checks_docker, "run_cmd", lambda args, timeout=None: CmdResult(0, "", ""))
    assert checks_docker._docker_available() is True
    monkeypatch.setattr(checks_docker, "run_cmd", lambda args, timeout=None: CmdResult(1, "", "no daemon"))
    assert checks_docker._docker_available() is False


def test_container_ids(monkeypatch):
    monkeypatch.setattr(checks_docker, "run_cmd", lambda args, timeout=None: CmdResult(0, "abc\n\n def \n", ""))
    assert checks_docker._get_container_ids() == ["abc", "def"]
    monkeypatch.setattr(checks_docker, "run_cmd", lambda args, timeout=None: CmdResult(1, "abc", ""))
    assert checks_docker._get_container_ids() == []


@pytest.mark.parametrize(
    "result, expected",
    [
        (CmdResult(0, json.dumps([{"Name": "/a"}]), ""), [{"Name": "/a"}]),
        (CmdResult(1, "[]", "error"), []),
        (CmdResult(0, "not json", ""), []),
        (CmdResult(0, json.dumps({"not": "a list"}), ""), []),
    ],
)
def test_inspect_containers(monkeypatch, result, expected):
    monkeypatch.setattr(checks_docker, "run_cmd", lambda args, timeout=None: result)
    assert checks_docker._inspect_containers(["abc"]) == expected


def test_inspect_with_no_ids_does_not_call_docker(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("docker must not be called")

    monkeypatch.setattr(checks_docker, "run_cmd", fail)
    assert checks_docker._inspect_containers([]) == []


# ---- DOC-001 ------------------------------------------------------------------------------------------------------------


def test_doc001_docker_missing(monkeypatch):
    _docker(monkeypatch, [], available=False)
    result = checks_docker._check_docker_installed()
    assert result["id"] == "DOC-001" and result["status"] == STATUS_INFO and "not installed" in result["current_value"]


def test_doc001_counts_containers(monkeypatch):
    _docker(monkeypatch, [])
    assert checks_docker._check_docker_installed()["current_value"] == "Docker running, 0 containers"
    _docker(monkeypatch, [container("a"), container("b")])
    result = checks_docker._check_docker_installed()
    assert result["status"] == STATUS_PASS and result["current_value"] == "Docker running, 2 container(s)"


# ---- DOC-002 .. DOC-007 ---------------------------------------------------------------------------------------------------

CHECKS = [
    ("_check_privileged", "DOC-002", dict(Privileged=True), STATUS_CRITICAL, "No privileged containers"),
    (
        "_check_docker_sock",
        "DOC-003",
        dict(Mounts=[{"Type": "bind", "Source": "/var/run/docker.sock"}]),
        STATUS_CRITICAL,
        "No containers mount",
    ),
    (
        "_check_host_namespaces",
        "DOC-004",
        dict(NetworkMode="host"),
        STATUS_WARNING,
        "No containers share host namespaces",
    ),
    ("_check_root_no_new_privs", "DOC-005", dict(User="", SecurityOpt=[]), STATUS_WARNING, "All root containers"),
    ("_check_added_capabilities", "DOC-006", dict(CapAdd=["SYS_PTRACE"]), STATUS_WARNING, "No containers add"),
    (
        "_check_sensitive_mounts",
        "DOC-007",
        dict(Mounts=[{"Type": "bind", "Source": "/root", "RW": True}]),
        STATUS_WARNING,
        "No writable mounts",
    ),
]


@pytest.mark.parametrize("function, check_id, risk, status, clean_text", CHECKS, ids=[c[1] for c in CHECKS])
def test_check_reports_clean_hosts_and_named_containers(monkeypatch, function, check_id, risk, status, clean_text):
    fn = getattr(checks_docker, function)
    _docker(monkeypatch, [container("good")])
    clean = fn()
    assert clean["id"] == check_id and clean["status"] == STATUS_PASS and clean_text in clean["current_value"]
    _docker(monkeypatch, [container("good"), container("bad-one", **risk)])
    risky = fn()
    assert (
        risky["status"] == status
        and "bad-one" in " ".join(risky["details"])
        and "good" not in " ".join(risky["details"])
    )
    assert risky["current_value"].startswith("1 ")


@pytest.mark.parametrize("function, check_id", [("_check_privileged", "DOC-002"), ("_check_docker_sock", "DOC-003")])
def test_accepted_findings_are_informational(monkeypatch, tmp_path, function, check_id):
    import config

    cfg = tmp_path / "securitywizard.toml"
    cfg.write_text(
        '[allow]\ndocker_sock_containers = [{name = "coolify", reason = "r"}]\ndocker_privileged = [{name = "coolify", reason = "r"}]\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("SECURITYWIZARD_CONFIG", str(cfg))
    config.reset_config()
    _docker(
        monkeypatch,
        [container("coolify", Privileged=True, Mounts=[{"Type": "bind", "Source": "/var/run/docker.sock"}])],
    )
    result = getattr(checks_docker, function)()
    assert result["status"] == STATUS_INFO and "(accepted by configuration)" in " ".join(result["details"])


def test_one_unaccepted_container_makes_it_critical(monkeypatch):
    _docker(monkeypatch, [container("a", Privileged=True), container("b", Privileged=True)])
    assert checks_docker._check_privileged()["status"] == STATUS_CRITICAL


# ---- run_checks -----------------------------------------------------------------------------------------------------------


def test_run_checks_returns_all_seven(monkeypatch):
    _docker(monkeypatch, [container()])
    assert [c["id"] for c in checks_docker.run_checks()] == [f"DOC-00{i}" for i in range(1, 8)]


def test_run_checks_turns_errors_into_skipped_results(monkeypatch):
    def boom():
        raise RuntimeError("docker exploded")

    monkeypatch.setattr(checks_docker, "_check_privileged", boom)
    _docker(monkeypatch, [container()])
    results = checks_docker.run_checks()
    broken = [r for r in results if r["status"] == STATUS_SKIPPED]
    assert len(results) == 7 and len(broken) == 1 and "docker exploded" in broken[0]["current_value"]


def test_the_docker_socket_is_reported_once_and_can_be_fully_accepted(tmp_path, monkeypatch):
    import config

    cfg = tmp_path / "securitywizard.toml"
    cfg.write_text('[allow]\ndocker_sock_containers = [{name = "coolify", reason = "r"}]\n', encoding="utf-8")
    monkeypatch.setenv("SECURITYWIZARD_CONFIG", str(cfg))
    config.reset_config()
    findings = checks_docker.analyze_container(
        container("coolify", Mounts=[{"Type": "bind", "Source": "/var/run/docker.sock", "RW": True}])
    )
    assert [(f["id"], f["allowed"]) for f in findings] == [("DOC-003", True)]
