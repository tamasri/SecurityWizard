"""remediator: snapshots, atomic writes, preview, apply (with validators, dead-man), backups and rollback.

Everything happens inside tmp_path with fake actions; no real system file is ever touched.
"""

import json
import os
import stat
import sys

import pytest

import remediator
import security

POSIX_MODES = pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
# Snapshots join the backup directory with an absolute path, which only works with POSIX paths; the target is Linux.
pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="remediator targets POSIX systems")


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Backups in tmp_path, applying allowed, and a registry that only holds the test's own actions."""
    monkeypatch.setenv("SECURITYWIZARD_BACKUP_DIR", str(tmp_path / "backups"))
    monkeypatch.setenv("SECURITYWIZARD_DRY_RUN_ONLY", "0")
    monkeypatch.setenv("SECURITYWIZARD_ALLOW_NONROOT", "1")
    monkeypatch.setattr(remediator, "_is_root", lambda: False)
    monkeypatch.setattr(remediator, "ACTIONS", {})
    return tmp_path


def _register(monkeypatch, rid, plan=None, **info):
    plan = plan if plan is not None else {}
    entry = {"title": "Title " + rid, "description": "Desc " + rid, "build_plan": lambda: dict(plan)}
    entry.update(info)
    monkeypatch.setitem(remediator.ACTIONS, rid, entry)
    return rid


class Runner:
    def __init__(self, results=None):
        self.calls = []
        self.results = results or {}

    def __call__(self, cmd):
        self.calls.append(list(cmd))
        return self.results.get(cmd[0], (0, "", ""))


# ---- small helpers ----------------------------------------------------------------------------------------


def test_ids_and_timestamps():
    snap = remediator._snap_id("ufw_baseline")
    assert security.validate_snapshot_id(snap)
    assert remediator._now_iso().endswith("Z")


def test_validate_remediation_id_uses_the_registry(env, monkeypatch):
    _register(monkeypatch, "known_fix")
    assert remediator._validate_remediation_id("known_fix") is True
    assert remediator._validate_remediation_id("other_fix") is False
    assert remediator._validate_remediation_id(None) is False


def test_real_registry_is_loaded():
    import importlib

    real = importlib.reload(remediator)
    assert "ssh_permit_root_login" in real.ACTIONS and "ufw_baseline" in real.ACTIONS


def test_environment_switches(monkeypatch):
    monkeypatch.setenv("SECURITYWIZARD_DRY_RUN_ONLY", "1")
    monkeypatch.setenv("SECURITYWIZARD_ALLOW_NONROOT", "1")
    monkeypatch.setenv("SECURITYWIZARD_BACKUP_DIR", "/somewhere")
    assert remediator._drun() is True and remediator._allow_nonroot() is True and remediator._bdir() == "/somewhere"
    monkeypatch.delenv("SECURITYWIZARD_DRY_RUN_ONLY")
    monkeypatch.delenv("SECURITYWIZARD_ALLOW_NONROOT")
    monkeypatch.delenv("SECURITYWIZARD_BACKUP_DIR")
    # dry-run is the default when the variable is not set
    assert remediator._drun() is True and remediator._allow_nonroot() is False
    assert remediator._bdir() == "/var/backups/securitywizard"


def test_is_root_without_geteuid(monkeypatch):
    monkeypatch.delattr(remediator.os, "geteuid", raising=False)
    assert remediator._is_root() is False


@POSIX_MODES
def test_is_root_with_geteuid(monkeypatch):
    monkeypatch.setattr(remediator.os, "geteuid", lambda: 0)
    assert remediator._is_root() is True


def test_run_cmd_success_failure_and_missing_binary():
    ok = remediator._run_cmd([sys.executable, "-c", "import sys; print('out'); sys.stderr.write('err'); sys.exit(2)"])
    assert ok == (2, "out\n", "err") or (ok[0] == 2 and ok[1].strip() == "out" and ok[2] == "err")
    assert remediator._run_cmd(["definitely-not-a-real-command-xyz"]) == (127, "", "not found")


def test_run_cmd_timeout_and_unexpected_error(monkeypatch):
    assert remediator._run_cmd([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.2) == (
        124,
        "",
        "timeout",
    )

    def boom(*args, **kwargs):
        raise RuntimeError("explosion")

    monkeypatch.setattr(remediator.subprocess, "run", boom)
    rc, out, err = remediator._run_cmd(["whatever"])
    assert rc == 1 and "explosion" in err


def test_run_validators_collects_failures():
    runner = Runner({"bad": (2, "", "nope"), "worse": (3, "", "")})
    assert remediator._run_validators([["good"], ["bad", "x"], ["worse"]], runner) == ["bad x rc=2 nope", "worse rc=3"]
    assert remediator._run_validators([], runner) == []


# ---- snapshots and atomic writes ----------------------------------------------------------------------------


def test_file_snapshot_missing_file_returns_none(env):
    assert remediator._file_snapshot(str(env / "missing.conf"), str(env / "snap")) is None


def test_file_snapshot_copies_the_file(env):
    source = env / "etc" / "app.conf"
    source.parent.mkdir()
    source.write_text("value=1\n", encoding="utf-8")
    entry = remediator._file_snapshot(str(source), str(env / "snap"))
    assert entry["existed"] is True and entry["path"] == str(source)
    assert open(entry["backup_file"], encoding="utf-8").read() == "value=1\n"
    assert entry["mode"] == stat.S_IMODE(source.stat().st_mode)


def test_file_snapshot_restores_ownership_as_root(env, monkeypatch):
    source = env / "owned.conf"
    source.write_text("x", encoding="utf-8")
    chowned = []
    monkeypatch.setattr(remediator, "_is_root", lambda: True)
    monkeypatch.setattr(remediator.os, "chown", lambda path, uid, gid: chowned.append((path, uid, gid)), raising=False)
    remediator._file_snapshot(str(source), str(env / "snap"))
    assert len(chowned) == 1


def test_file_snapshot_ignores_chown_errors(env, monkeypatch):
    source = env / "owned.conf"
    source.write_text("x", encoding="utf-8")

    def deny(path, uid, gid):
        raise PermissionError("no")

    monkeypatch.setattr(remediator, "_is_root", lambda: True)
    monkeypatch.setattr(remediator.os, "chown", deny, raising=False)
    assert remediator._file_snapshot(str(source), str(env / "snap"))["existed"] is True


def test_atomic_write_creates_directories_and_file(env):
    target = env / "new" / "dir" / "file.conf"
    remediator._atomic_write(str(target), "hello\n")
    assert target.read_text(encoding="utf-8") == "hello\n"
    assert [p.name for p in target.parent.iterdir()] == ["file.conf"]  # no temp file left behind


@POSIX_MODES
def test_atomic_write_keeps_the_original_mode(env):
    target = env / "secret.conf"
    target.write_text("old", encoding="utf-8")
    os.chmod(target, 0o600)
    remediator._atomic_write(str(target), "new", os.stat(target))
    assert target.read_text(encoding="utf-8") == "new" and stat.S_IMODE(target.stat().st_mode) == 0o600


def test_atomic_write_restores_owner_as_root(env, monkeypatch):
    target = env / "owned.conf"
    target.write_text("old", encoding="utf-8")
    calls = []
    monkeypatch.setattr(remediator, "_is_root", lambda: True)
    monkeypatch.setattr(remediator.os, "chown", lambda *a: calls.append(a), raising=False)
    remediator._atomic_write(str(target), "new", os.stat(target))
    assert calls and target.read_text(encoding="utf-8") == "new"


def test_atomic_write_ignores_chown_errors(env, monkeypatch):
    target = env / "owned.conf"
    target.write_text("old", encoding="utf-8")

    def deny(*args):
        raise OSError("no")

    monkeypatch.setattr(remediator, "_is_root", lambda: True)
    monkeypatch.setattr(remediator.os, "chown", deny, raising=False)
    remediator._atomic_write(str(target), "new", os.stat(target))
    assert target.read_text(encoding="utf-8") == "new"


def test_atomic_write_cleans_up_when_the_replace_fails(env, monkeypatch):
    target = env / "file.conf"

    def fail(src, dst):
        raise OSError("replace failed")

    monkeypatch.setattr(remediator.os, "replace", fail)
    with pytest.raises(OSError):
        remediator._atomic_write(str(target), "data")
    assert list(env.iterdir()) == []


# ---- plans, idempotency, preview ---------------------------------------------------------------------------------


def test_get_plan(env, monkeypatch):
    _register(monkeypatch, "fix_one", {"commands": [["true"]]})
    assert remediator._get_plan("fix_one") == {"commands": [["true"]]}
    assert remediator._get_plan("nothing") is None


def test_idempotency_detection(env):
    target = env / "a.conf"
    target.write_text("same", encoding="utf-8")
    assert remediator._check_idempotent({"file_changes": [{"path": str(target), "new_content": "same"}]}) is True
    assert remediator._check_idempotent({"file_changes": [{"path": str(target), "new_content": "different"}]}) is False
    assert remediator._check_idempotent({"file_changes": [{"path": str(env / "gone"), "new_content": "x"}]}) is False
    assert remediator._check_idempotent({}) is True
    assert remediator._check_idempotent({"perm_changes": [{"path": str(env / "gone"), "mode": 0o600}]}) is False


@POSIX_MODES
def test_idempotency_with_permissions(env):
    target = env / "p.conf"
    target.write_text("x", encoding="utf-8")
    os.chmod(target, 0o600)
    assert remediator._check_idempotent({"perm_changes": [{"path": str(target), "mode": 0o600}]}) is True
    assert remediator._check_idempotent({"perm_changes": [{"path": str(target), "mode": 0o644}]}) is False


def test_preview_unknown_remediation(env):
    result = remediator.preview("nope")
    assert result["blocked"] is True and result["blocked_reason"] == "Unknown remediation"


def test_preview_when_the_plan_cannot_be_built(env, monkeypatch):
    def broken():
        raise RuntimeError("bad plan")

    monkeypatch.setitem(remediator.ACTIONS, "broken", {"title": "t", "build_plan": broken})
    result = remediator.preview("broken")
    assert result["blocked"] is True and "exception" in result["blocked_reason"]


def test_preview_shows_diffs_commands_permissions_and_warnings(env, monkeypatch):
    existing = env / "existing.conf"
    existing.write_text("a=1\n", encoding="utf-8")
    plan = {
        "file_changes": [
            {"path": str(existing), "new_content": "a=2\n"},
            {"path": str(env / "brand-new.conf"), "new_content": "b=1\n"},
        ],
        "perm_changes": [{"path": str(existing), "mode": 0o600}, {"path": str(env / "missing"), "mode": 0o640}],
        "commands": [["systemctl", "reload", "my service"]],
        "warnings": ["careful"],
    }
    _register(monkeypatch, "fix_preview", plan)
    result = remediator.preview("fix_preview")
    assert result["blocked"] is False and result["requires_root"] is True
    assert result["title"] == "Title fix_preview" and result["description"] == "Desc fix_preview"
    assert "-a=1" in result["diffs"][0]["unified_diff"] and "+a=2" in result["diffs"][0]["unified_diff"]
    assert result["diffs"][1]["before"] == "" and result["diffs"][1]["after"] == "b=1\n"
    assert result["perm_changes"][1]["current_mode"] == "missing" and result["perm_changes"][1]["new_mode"] == "640"
    assert result["commands"] == ["systemctl reload 'my service'"] and result["warnings"] == ["careful"]


def test_preview_reports_blockers(env, monkeypatch):
    _register(monkeypatch, "fix_blocked", {"blockers": ["no ssh key", "second reason"]})
    result = remediator.preview("fix_blocked")
    assert result["blocked"] is True and result["blocked_reason"] == "no ssh key; second reason"


def test_preview_turns_a_malformed_plan_into_a_blocked_result(env, monkeypatch):
    _register(monkeypatch, "fix_malformed", {"file_changes": [{"new_content": "missing path"}]})
    result = remediator.preview("fix_malformed")
    assert result["blocked"] is True and "path" in result["blocked_reason"]


# ---- apply --------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "setup, expected",
    [
        ("no_confirm", "confirm must be True"),
        ("dry_run", "dry-run only"),
        ("not_root", "requires root"),
        ("unknown", "Unknown remediation"),
        ("plan_error", "build_plan failed"),
        ("blocked", "blocked: reason one"),
        ("precondition", "precondition: would lock you out"),
        ("idempotent", "already applied"),
    ],
)
def test_apply_refusals(env, monkeypatch, setup, expected):
    target = env / "same.conf"
    target.write_text("same", encoding="utf-8")
    plan = {}
    precondition = None
    if setup == "blocked":
        plan = {"blockers": ["reason one"]}
    if setup == "idempotent":
        plan = {"file_changes": [{"path": str(target), "new_content": "same"}]}
    if setup == "precondition":
        plan = {"commands": [["true"]]}
        precondition = lambda p: "would lock you out"  # noqa: E731
    if setup == "dry_run":
        monkeypatch.setenv("SECURITYWIZARD_DRY_RUN_ONLY", "1")
    if setup == "not_root":
        monkeypatch.delenv("SECURITYWIZARD_ALLOW_NONROOT")
    _register(monkeypatch, "fix_x", plan)
    if setup == "plan_error":

        def broken():
            raise RuntimeError("kaboom")

        monkeypatch.setitem(remediator.ACTIONS, "fix_x", {"title": "t", "build_plan": broken})
    rid = "other" if setup == "unknown" else "fix_x"
    result = remediator.apply(rid, confirm=setup != "no_confirm", precondition=precondition)
    assert expected in result["message"]
    assert result["ok"] is (setup == "idempotent")


def test_apply_writes_files_runs_commands_and_records_a_snapshot(env, monkeypatch):
    target = env / "etc" / "app.conf"
    target.parent.mkdir()
    target.write_text("old\n", encoding="utf-8")
    created = env / "etc" / "created.conf"
    plan = {
        "file_changes": [{"path": str(target), "new_content": "new\n"}, {"path": str(created), "new_content": "c\n"}],
        "perm_changes": [{"path": str(target), "mode": 0o640}, {"path": str(env / "etc" / "absent"), "mode": 0o600}],
        "validate_commands": [["validator", "--check"]],
        "commands": [["reload", "app"]],
        "inverse_commands": [["reload", "app"]],
    }
    plan["perm_changes"] = plan["perm_changes"][:1]
    _register(monkeypatch, "fix_apply", plan)
    runner = Runner({"reload": (0, "reloaded", "warn")})
    result = remediator.apply("fix_apply", confirm=True, runner=runner)
    assert result["ok"] is True and result["message"] == "applied"
    assert target.read_text(encoding="utf-8") == "new\n" and created.read_text(encoding="utf-8") == "c\n"
    assert runner.calls == [["validator", "--check"], ["reload", "app"]]
    assert (
        "validate validator --check rc=0" in result["output"]
        and "reloaded" in result["output"]
        and "warn" in result["output"]
    )
    manifest = json.loads((env / "backups" / result["snapshot_id"] / "manifest.json").read_text(encoding="utf-8"))
    assert [f["existed"] for f in manifest["files"]] == [True, False, True]
    assert manifest["remediation_id"] == "fix_apply" and manifest["inverse_commands"] == [["reload", "app"]]
    assert security.validate_snapshot_id(result["snapshot_id"])


def test_apply_handles_perm_change_of_a_missing_file_in_the_manifest(env, monkeypatch):
    plan = {"perm_changes": [{"path": str(env / "absent"), "mode": 0o600}], "commands": [["noop"]]}
    _register(monkeypatch, "fix_perm", plan)
    # chmod on the missing file fails, which must become a clean failure message and not an unhandled error
    result = remediator.apply("fix_perm", confirm=True, runner=Runner())
    assert result["ok"] is False and result["message"]


def test_apply_rolls_back_when_validation_fails(env, monkeypatch):
    target = env / "app.conf"
    target.write_text("old\n", encoding="utf-8")
    plan = {
        "file_changes": [{"path": str(target), "new_content": "broken\n"}],
        "validate_commands": [["validator"]],
        "commands": [["must-not-run"]],
    }
    _register(monkeypatch, "fix_validate", plan)
    runner = Runner({"validator": (1, "", "syntax error")})
    result = remediator.apply("fix_validate", confirm=True, runner=runner)
    assert result["ok"] is False and result["message"] == "validation failed, rolled back"
    assert target.read_text(encoding="utf-8") == "old\n"
    assert ["must-not-run"] not in runner.calls


def test_apply_arms_the_dead_man_switch_for_risky_changes(env, monkeypatch):
    armed = []
    monkeypatch.setattr(
        remediator.deadman,
        "arm",
        lambda token, revert, minutes, bdir, info=None: armed.append((token, minutes, revert, info)),
    )
    target = env / "sshd_config"
    target.write_text("Port 22\n", encoding="utf-8")
    plan = {"file_changes": [{"path": str(target), "new_content": "Port 2222\n"}]}
    _register(monkeypatch, "ssh_risky", plan, risky_remote=True, deadman_minutes=3)
    result = remediator.apply("ssh_risky", confirm=True, runner=Runner())
    assert result["deadman_token"] == "DM-ssh_risky" and result["deadline"] > 0
    assert armed[0][0] == "DM-ssh_risky" and armed[0][1] == 3
    assert armed[0][3] == {"snapshot_id": result["snapshot_id"], "remediation_id": "ssh_risky"}
    armed[0][2]()  # the revert callback restores the file
    assert target.read_text(encoding="utf-8") == "Port 22\n"


def test_apply_reports_unexpected_errors(env, monkeypatch):
    _register(monkeypatch, "fix_boom", {"file_changes": [{"path": str(env / "x.conf"), "new_content": "x"}]})
    monkeypatch.setattr(remediator.os, "makedirs", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
    result = remediator.apply("fix_boom", confirm=True, runner=Runner())
    assert result["ok"] is False and "disk full" in result["message"]


def test_apply_uses_the_default_runner(env, monkeypatch):
    seen = []
    monkeypatch.setattr(remediator, "_run_cmd", lambda cmd, timeout=120.0: seen.append(cmd) or (0, "", ""))
    _register(monkeypatch, "fix_default", {"commands": [["echo", "hi"]]})
    assert remediator.apply("fix_default", confirm=True)["ok"] is True
    assert seen == [["echo", "hi"]]


# ---- backups and rollback ----------------------------------------------------------------------------------------


def test_list_backups_empty_and_missing(env):
    assert remediator.list_backups() == []
    (env / "backups").mkdir()
    assert remediator.list_backups() == []


def test_list_backups_lists_valid_manifests_newest_first(env):
    root = env / "backups"
    for name in ("20260101T000000_a_fix", "20260301T000000_b_fix"):
        (root / name).mkdir(parents=True)
        (root / name / "manifest.json").write_text(
            json.dumps({"created": name, "remediation_id": name[-5:], "title": "T", "files": [{"path": "/etc/x"}]}),
            encoding="utf-8",
        )
    (root / "20260201T000000_broken").mkdir()
    (root / "20260201T000000_broken" / "manifest.json").write_text("not json", encoding="utf-8")
    (root / "stray-dir").mkdir()
    (root / "a-file.txt").write_text("x", encoding="utf-8")
    listed = remediator.list_backups()
    assert [b["snapshot_id"] for b in listed] == ["20260301T000000_b_fix", "20260101T000000_a_fix"]
    assert listed[0]["files"] == ["/etc/x"]


def test_list_backups_never_raises(env, monkeypatch):
    (env / "backups").mkdir()
    monkeypatch.setattr(remediator.os, "listdir", lambda path: (_ for _ in ()).throw(OSError("denied")))
    assert remediator.list_backups() == []


@pytest.mark.parametrize("snapshot", ["", None, "../escape", "has space", "a/b"])
def test_rollback_rejects_invalid_ids(env, snapshot):
    assert remediator.rollback(snapshot) == {"ok": False, "message": "invalid snapshot id", "restored": []}


def test_rollback_unknown_snapshot(env):
    assert remediator.rollback("20260101T000000_missing")["message"] == "snapshot not found"


def test_rollback_without_manifest_reports_the_error(env):
    (env / "backups" / "20260101T000000_empty").mkdir(parents=True)
    result = remediator.rollback("20260101T000000_empty")
    assert result["ok"] is False and result["message"]


def test_apply_then_rollback_restores_everything(env, monkeypatch):
    existing = env / "existing.conf"
    existing.write_text("original\n", encoding="utf-8")
    created = env / "created.conf"
    inverse = []
    monkeypatch.setattr(remediator, "_run_cmd", lambda cmd, timeout=120.0: inverse.append(cmd) or (0, "", ""))
    plan = {
        "file_changes": [
            {"path": str(existing), "new_content": "changed\n"},
            {"path": str(created), "new_content": "new\n"},
        ],
        "inverse_commands": [["undo", "it"]],
    }
    _register(monkeypatch, "fix_roundtrip", plan)
    applied = remediator.apply("fix_roundtrip", confirm=True, runner=Runner())
    assert existing.read_text(encoding="utf-8") == "changed\n" and created.exists()
    result = remediator.rollback(applied["snapshot_id"])
    assert result["ok"] is True and result["message"] == "rolled back"
    assert existing.read_text(encoding="utf-8") == "original\n" and not created.exists()
    assert set(result["restored"]) == {str(existing), str(created)} and inverse == [["undo", "it"]]


def test_rollback_restores_ownership_as_root(env, monkeypatch):
    target = env / "owned.conf"
    target.write_text("original\n", encoding="utf-8")
    _register(monkeypatch, "fix_owner", {"file_changes": [{"path": str(target), "new_content": "changed\n"}]})
    applied = remediator.apply("fix_owner", confirm=True, runner=Runner())
    chowned = []
    monkeypatch.setattr(remediator, "_is_root", lambda: True)
    monkeypatch.setattr(remediator.os, "chown", lambda *a: chowned.append(a), raising=False)
    assert remediator.rollback(applied["snapshot_id"])["ok"] is True
    assert chowned


def test_rollback_ignores_chown_errors(env, monkeypatch):
    target = env / "owned.conf"
    target.write_text("original\n", encoding="utf-8")
    _register(monkeypatch, "fix_owner2", {"file_changes": [{"path": str(target), "new_content": "changed\n"}]})
    applied = remediator.apply("fix_owner2", confirm=True, runner=Runner())

    def deny(*args):
        raise PermissionError("no")

    monkeypatch.setattr(remediator, "_is_root", lambda: True)
    monkeypatch.setattr(remediator.os, "chown", deny, raising=False)
    assert remediator.rollback(applied["snapshot_id"])["ok"] is True


def test_a_plan_that_only_runs_commands_is_never_considered_applied(env, monkeypatch):
    """Regression: the firewall baseline only runs commands; it must not be skipped as 'already applied'."""
    assert remediator._check_idempotent({"commands": [["ufw", "enable"]]}) is False
    assert remediator._check_idempotent({"commands": []}) is True
    runner = Runner()
    _register(monkeypatch, "fix_commands_only", {"commands": [["ufw", "default", "deny"], ["ufw", "enable"]]})
    result = remediator.apply("fix_commands_only", confirm=True, runner=runner)
    assert result["ok"] is True and result["message"] == "applied"
    assert runner.calls == [["ufw", "default", "deny"], ["ufw", "enable"]]
