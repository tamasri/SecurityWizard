import json
import os
import stat
import sys
import tempfile
from unittest import mock

import pytest

import remediator


def _make_action(rid, title, description, file_changes=None, perm_changes=None,
                 commands=None, validate_commands=None, inverse_commands=None,
                 blockers=None, risky_remote=False, deadman_minutes=5):
    plan = {
        "file_changes": file_changes or [],
        "perm_changes": perm_changes or [],
        "commands": commands or [],
        "validate_commands": validate_commands or [],
        "inverse_commands": inverse_commands or [],
        "blockers": blockers,
        "warnings": [],
    }
    remediator.ACTIONS[rid] = {
        "title": title,
        "description": description,
        "build_plan": lambda: plan,
        "risky_remote": risky_remote,
        "deadman_minutes": deadman_minutes,
    }


def _setup_file(tmp_path, rel, content, mode=0o644):
    path = os.path.join(str(tmp_path), rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)
    os.chmod(path, mode)
    return path


def _runner_factory(fail_cmds=None):
    """Return a runner that fails on the given command prefixes."""
    fail_cmds = fail_cmds or set()

    def runner(args):
        cmd_str = " ".join(args)
        for prefix in fail_cmds:
            if cmd_str.startswith(prefix):
                return 1, "", "failed: " + cmd_str
        return 0, "ok", ""

    return runner


def test_id_validation_rejects_bad_id():
    result = remediator.preview("bad-id")
    assert result["blocked"] is True
    assert result["blocked_reason"] == "Unknown remediation"


def test_id_validation_accepts_known_id(tmp_path):
    _make_action("SSH-001", "t", "d")
    result = remediator.preview("SSH-001")
    assert result["blocked"] is False


def test_validator_failure_leaves_files_untouched(tmp_path):
    path = _setup_file(tmp_path, "etc/ssh/sshd_config", "Port 22\n")
    original = "Port 22\n"
    _make_action(
        "SSH-001", "t", "d",
        file_changes=[{"path": path, "new_content": "Port 2222\n"}],
        validate_commands=[["sshd", "-t"]],
    )
    runner = _runner_factory(fail_cmds={"sshd"})
    with mock.patch.dict(os.environ, {"SECURITYWIZARD_BACKUP_DIR": str(tmp_path / "backups"),
                                       "SECURITYWIZARD_DRY_RUN_ONLY": "0",
                                       "SECURITYWIZARD_ALLOW_NONROOT": "1"}):
        with mock.patch.object(remediator, "_is_root", return_value=True):
            result = remediator.apply("SSH-001", confirm=True, runner=runner)
    assert result["ok"] is False
    assert "validation failed" in result["message"]
    with open(path) as f:
        assert f.read() == original


def test_idempotency(tmp_path):
    path = _setup_file(tmp_path, "etc/ssh/sshd_config", "Port 2222\n")
    _make_action(
        "SSH-001", "t", "d",
        file_changes=[{"path": path, "new_content": "Port 2222\n"}],
    )
    runner = _runner_factory()
    with mock.patch.dict(os.environ, {"SECURITYWIZARD_BACKUP_DIR": str(tmp_path / "backups"),
                                       "SECURITYWIZARD_DRY_RUN_ONLY": "0",
                                       "SECURITYWIZARD_ALLOW_NONROOT": "1"}):
        with mock.patch.object(remediator, "_is_root", return_value=True):
            result = remediator.apply("SSH-001", confirm=True, runner=runner)
    assert result["ok"] is True
    assert result["message"] == "already applied"


def test_dry_run_only_blocks_apply(tmp_path):
    path = _setup_file(tmp_path, "etc/ssh/sshd_config", "Port 22\n")
    _make_action("SSH-001", "t", "d",
                 file_changes=[{"path": path, "new_content": "Port 2222\n"}])
    runner = _runner_factory()
    with mock.patch.dict(os.environ, {"SECURITYWIZARD_BACKUP_DIR": str(tmp_path / "backups"),
                                       "SECURITYWIZARD_DRY_RUN_ONLY": "1",
                                       "SECURITYWIZARD_ALLOW_NONROOT": "1"}):
        with mock.patch.object(remediator, "_is_root", return_value=True):
            result = remediator.apply("SSH-001", confirm=True, runner=runner)
    assert result["ok"] is False
    assert result["message"] == "dry-run only"
    with open(path) as f:
        assert f.read() == "Port 22\n"


def test_risky_remote_arms_deadman(tmp_path):
    path = _setup_file(tmp_path, "etc/ssh/sshd_config", "Port 22\n")
    _make_action(
        "SSH-001", "t", "d",
        file_changes=[{"path": path, "new_content": "Port 2222\n"}],
        risky_remote=True,
        deadman_minutes=5,
    )
    runner = _runner_factory()
    with mock.patch.dict(os.environ, {"SECURITYWIZARD_BACKUP_DIR": str(tmp_path / "backups"),
                                       "SECURITYWIZARD_DRY_RUN_ONLY": "0",
                                       "SECURITYWIZARD_ALLOW_NONROOT": "1"}):
        with mock.patch.object(remediator, "_is_root", return_value=True):
            result = remediator.apply("SSH-001", confirm=True, runner=runner)
    assert result["ok"] is True
    assert "deadman_token" in result
    assert "deadline" in result
    assert result["deadman_token"].startswith("DM-")


def test_precondition_refuses(tmp_path):
    path = _setup_file(tmp_path, "etc/ssh/sshd_config", "Port 22\n")
    _make_action("SSH-001", "t", "d",
                 file_changes=[{"path": path, "new_content": "Port 2222\n"}])
    runner = _runner_factory()
    precondition = lambda plan: "would cut current connection"
    with mock.patch.dict(os.environ, {"SECURITYWIZARD_BACKUP_DIR": str(tmp_path / "backups"),
                                       "SECURITYWIZARD_DRY_RUN_ONLY": "0",
                                       "SECURITYWIZARD_ALLOW_NONROOT": "1"}):
        with mock.patch.object(remediator, "_is_root", return_value=True):
            result = remediator.apply("SSH-001", confirm=True, runner=runner,
                                      precondition=precondition)
    assert result["ok"] is False
    assert "precondition" in result["message"]
    with open(path) as f:
        assert f.read() == "Port 22\n"
