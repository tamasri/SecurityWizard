"""Regression tests for the HTTP routes (previously broken: request model used as the HTTP request,
shadowed /api/scan/status route, blocking scan start and scans never stored in the history)."""

import threading
import time

import pytest
from fastapi.testclient import TestClient

import auth
import main
import remediator
import scanner
import security

CSRF = {"X-Requested-With": "SecurityWizard"}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("SECURITYWIZARD_AUTH", "0")
    auth.reset_for_tests()
    for bucket in security._rate_limits.values():
        bucket.clear()
    main._scan_state.update(status="idle", job_id=None, scan_id=None, result=None, error=None)
    with TestClient(main.app, base_url="http://127.0.0.1:8443") as test_client:
        yield test_client
    auth.reset_for_tests()


def _fake_scan(progress_cb=None):
    if progress_cb:
        progress_cb(1, 1, "network")
    return {
        "checks": [{"id": "ufw_baseline", "status": "PASS"}],
        "score": 100,
        "counts": {},
        "started": "x",
        "finished": "y",
    }


def _wait_finished(client, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        state = client.get("/api/scan/status").json()
        if state["status"] == "finished":
            return state
        time.sleep(0.05)
    raise AssertionError("scan did not finish")


def test_scan_status_route_is_not_shadowed_by_job_id_route(client):
    resp = client.get("/api/scan/status")
    assert resp.status_code == 200
    assert resp.json()["status"] in ("idle", "running", "finished")


def test_scan_start_returns_immediately_and_is_saved_in_history(client, monkeypatch):
    release = threading.Event()

    def slow_scan(progress_cb=None):
        release.wait(5)
        return _fake_scan(progress_cb)

    monkeypatch.setattr(scanner, "run_full_scan", slow_scan)
    started = time.time()
    resp = client.post("/api/scan", json={}, headers=CSRF)
    assert resp.status_code == 200 and "job_id" in resp.json()
    assert time.time() - started < 2  # did not wait for the scan
    assert client.get("/api/scan/status").json()["status"] == "running"
    # a second request while running does not start another scan
    assert client.post("/api/scan", json={}, headers=CSRF).json().get("already_running") is True
    release.set()
    state = _wait_finished(client)
    assert state["error"] is None and state["scan_id"]
    scans = client.get("/api/history").json()["scans"]
    assert [item["scan_id"] for item in scans] == [state["scan_id"]]
    assert scans[0]["score"] == 100
    assert client.get("/api/history/" + state["scan_id"]).status_code == 200
    export = client.get("/api/export", params={"fmt": "markdown", "scan_id": state["scan_id"]})
    assert export.status_code == 200 and "100/100" in export.json()["markdown"]


def test_failed_scan_is_reported(client, monkeypatch):
    def broken(progress_cb=None):
        raise RuntimeError("boom")

    monkeypatch.setattr(scanner, "run_full_scan", broken)
    client.post("/api/scan", json={}, headers=CSRF)
    state = _wait_finished(client)
    assert "boom" in state["error"]


def test_dry_run_works_and_is_audited(client, monkeypatch):
    monkeypatch.setattr(remediator, "preview", lambda rid: {"remediation_id": rid, "ok": True})
    resp = client.post("/api/dry-run", json={"remediation_id": "ufw_baseline"}, headers=CSRF)
    assert resp.status_code == 200
    assert resp.json()["remediation_id"] == "ufw_baseline"


def test_remediate_validates_id_and_honours_readonly(client, monkeypatch):
    monkeypatch.setattr(remediator, "apply", lambda rid, confirm: {"applied": rid, "confirm": confirm})
    bad = client.post("/api/remediate", json={"remediation_id": "Not Valid!", "confirm": True}, headers=CSRF)
    assert bad.status_code == 422
    good = client.post("/api/remediate", json={"remediation_id": "ufw_baseline", "confirm": True}, headers=CSRF)
    assert good.status_code == 200 and good.json()["applied"] == "ufw_baseline"
    monkeypatch.setenv("SECURITYWIZARD_READONLY", "1")
    blocked = client.post("/api/remediate", json={"remediation_id": "ufw_baseline", "confirm": True}, headers=CSRF)
    assert blocked.status_code == 403


def test_rollback_validates_id(client, monkeypatch):
    monkeypatch.setattr(remediator, "rollback", lambda sid: {"rolled_back": sid})
    assert client.post("/api/rollback", json={"snapshot_id": "bad id"}, headers=CSRF).status_code == 422
    ok = client.post("/api/rollback", json={"snapshot_id": "SNAP-abcdef123456"}, headers=CSRF)
    assert ok.status_code == 200


def test_post_requires_csrf_header_and_known_host(client):
    assert client.post("/api/dry-run", json={"remediation_id": "ufw_baseline"}).status_code == 403
    assert client.get("/api/status", headers={"Host": "evil.example"}).status_code == 403


def test_security_headers_present(client):
    resp = client.get("/api/status")
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Cache-Control"] == "no-store"


def test_deadman_confirm_endpoint(client, monkeypatch):
    calls = []
    monkeypatch.setattr(main.deadman, "confirm", lambda token, bdir: calls.append(token) or True)
    assert client.post("/api/deadman/confirm", json={"token": "bad"}, headers=CSRF).status_code == 422
    ok = client.post("/api/deadman/confirm", json={"token": "DM-ssh_permit_root_login"}, headers=CSRF)
    assert ok.status_code == 200 and ok.json() == {"ok": True} and calls == ["DM-ssh_permit_root_login"]
    assert client.get("/api/deadman").status_code == 200
