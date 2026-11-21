"""Remediation ids emitted by the checks must work end to end through the API (format, registry, preview, dead-man)."""

import pathlib
import re

import pytest
from fastapi.testclient import TestClient

import auth
import main
import remediator
import security

ROOT = pathlib.Path(__file__).resolve().parents[1]
CSRF = {"X-Requested-With": "SecurityWizard"}


def _emitted_ids():
    found = set()
    for path in ROOT.glob("checks_*.py"):
        found |= set(re.findall(r'remediation_id\s*=\s*"([^"]+)"', path.read_text(encoding="utf-8")))
    return sorted(found)


def test_some_remediation_ids_are_emitted():
    assert len(_emitted_ids()) >= 10


@pytest.mark.parametrize("rid", _emitted_ids())
def test_every_emitted_id_is_valid_registered_and_previewable(rid):
    assert security.validate_remediation_id(rid), "the API would reject %s with HTTP 422" % rid
    assert rid in remediator.ACTIONS, "%s is not registered, the fix button would do nothing" % rid
    preview = remediator.preview(rid)
    assert preview.get("blocked_reason") != "Unknown remediation"
    assert main.DEADMAN_TOKEN_RE.match("DM-" + rid), "the dead-man token for %s could not be confirmed" % rid


def test_preview_through_the_api_accepts_a_real_id(monkeypatch):
    monkeypatch.setenv("SECURITYWIZARD_AUTH", "0")
    auth.reset_for_tests()
    with TestClient(main.app, base_url="http://127.0.0.1:8443") as client:
        response = client.post("/api/dry-run", json={"remediation_id": "ssh_permit_root_login"}, headers=CSRF)
    auth.reset_for_tests()
    assert response.status_code == 200
    assert response.json().get("blocked_reason") != "Unknown remediation"


def test_unknown_but_well_formed_ids_are_not_applied(monkeypatch):
    monkeypatch.setenv("SECURITYWIZARD_AUTH", "0")
    monkeypatch.setenv("SECURITYWIZARD_DRY_RUN_ONLY", "0")
    auth.reset_for_tests()
    with TestClient(main.app, base_url="http://127.0.0.1:8443") as client:
        response = client.post(
            "/api/remediate", json={"remediation_id": "does_not_exist", "confirm": True}, headers=CSRF
        )
    auth.reset_for_tests()
    assert response.status_code == 200
    assert response.json()["ok"] is False
