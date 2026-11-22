"""Dry-run is the default: nothing is changed on the server unless SECURITYWIZARD_DRY_RUN_ONLY is explicitly 0."""

import json

import pytest
from fastapi.testclient import TestClient

import auth
import main
import remediator
import scanner
import security
from common import make_check

CSRF = {"X-Requested-With": "SecurityWizard"}


@pytest.fixture
def unset(monkeypatch, tmp_path):
    monkeypatch.delenv("SECURITYWIZARD_DRY_RUN_ONLY", raising=False)
    monkeypatch.setenv("SECURITYWIZARD_BACKUP_DIR", str(tmp_path / "backups"))
    monkeypatch.setenv("SECURITYWIZARD_ALLOW_NONROOT", "1")
    monkeypatch.setattr(remediator, "_is_root", lambda: False)
    monkeypatch.setattr(
        remediator, "ACTIONS", {"fix_it": {"title": "t", "build_plan": lambda: {"commands": [["true"]]}}}
    )
    return tmp_path


@pytest.mark.parametrize(
    "value, dry",
    [
        (None, True),
        ("", True),
        ("1", True),
        ("true", True),
        ("yes", True),
        ("garbage", True),
        ("0", False),
        ("false", False),
        ("No", False),
        (" off ", False),
    ],
)
def test_only_an_explicit_zero_allows_changes(monkeypatch, value, dry):
    if value is None:
        monkeypatch.delenv("SECURITYWIZARD_DRY_RUN_ONLY", raising=False)
    else:
        monkeypatch.setenv("SECURITYWIZARD_DRY_RUN_ONLY", value)
    assert security.is_dry_run_only() is dry
    assert remediator._drun() is dry


def test_apply_is_refused_by_default(unset):
    result = remediator.apply("fix_it", confirm=True, runner=lambda cmd: (0, "", ""))
    assert result == {"ok": False, "message": "dry-run only", "snapshot_id": None, "output": []}
    assert not (unset / "backups").exists()


def test_apply_works_only_after_an_explicit_opt_in(unset, monkeypatch):
    monkeypatch.setenv("SECURITYWIZARD_DRY_RUN_ONLY", "0")
    result = remediator.apply("fix_it", confirm=True, runner=lambda cmd: (0, "", ""))
    assert result["ok"] is True and result["message"] == "applied"


def _snapshot(tmp_path):
    snap = tmp_path / "backups" / "20260101T000000_fix_it"
    snap.mkdir(parents=True)
    (snap / "manifest.json").write_text(
        json.dumps({"snapshot_id": snap.name, "files": [], "inverse_commands": []}), encoding="utf-8"
    )
    return snap.name


def test_rollback_is_refused_by_default_but_safety_reverts_are_not(unset):
    snapshot = _snapshot(unset)
    assert remediator.rollback(snapshot) == {"ok": False, "message": "dry-run only", "restored": []}
    assert remediator.rollback(snapshot, force=True)["ok"] is True


def test_rollback_works_after_an_explicit_opt_in(unset, monkeypatch):
    snapshot = _snapshot(unset)
    monkeypatch.setenv("SECURITYWIZARD_DRY_RUN_ONLY", "0")
    assert remediator.rollback(snapshot)["ok"] is True


@pytest.mark.parametrize("value, state", [(None, "dry_run_only"), ("1", "dry_run_only"), ("0", "available")])
def test_scan_results_tell_the_dashboard_whether_a_fix_can_be_applied(monkeypatch, value, state):
    if value is None:
        monkeypatch.delenv("SECURITYWIZARD_DRY_RUN_ONLY", raising=False)
    else:
        monkeypatch.setenv("SECURITYWIZARD_DRY_RUN_ONLY", value)
    check = make_check("SSH-001", "ssh", "t", "WARNING", "w", "r", "c", remediation_id="ssh_x11_forwarding")
    assert scanner._build_result("now", [check])["checks"][0]["fix_state"] == state


@pytest.mark.parametrize("value, expected", [(None, True), ("0", False)])
def test_status_endpoint_reports_the_mode(monkeypatch, value, expected):
    monkeypatch.setenv("SECURITYWIZARD_AUTH", "0")
    if value is None:
        monkeypatch.delenv("SECURITYWIZARD_DRY_RUN_ONLY", raising=False)
    else:
        monkeypatch.setenv("SECURITYWIZARD_DRY_RUN_ONLY", value)
    auth.reset_for_tests()
    with TestClient(main.app, base_url="http://127.0.0.1:8443") as client:
        assert client.get("/api/status").json()["dry_run_only"] is expected
    auth.reset_for_tests()


def test_the_dashboard_disables_rollback_in_dry_run_mode():
    import pathlib

    script = (pathlib.Path(__file__).resolve().parents[1] / "static" / "app.js").read_text(encoding="utf-8")
    assert "disabled: !!(s.readonly || s.dry_run_only)" in script
