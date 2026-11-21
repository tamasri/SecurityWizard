import os
import sys
import json
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
import main
import scanner
import common


def _mock_check(id, category, title, status, remediation_id=None):
    return {
        "id": id,
        "category": category,
        "title": title,
        "status": status,
        "what_it_checks": "test",
        "risk": "test",
        "command": "test",
        "current_value": "x",
        "recommended_value": "y",
        "details": [],
        "remediation_id": remediation_id,
        "manual_command": ""
    }


def test_scan_result_fix_state_no_remediation(monkeypatch):
    monkeypatch.setenv("SECURITYWIZARD_DRY_RUN_ONLY", "0")
    checks = [
        _mock_check("CHK-1", "network", "No fix", "PASS", None),
        _mock_check("CHK-2", "ssh", "Has fix", "WARNING", "FIX-SSH-1"),
    ]
    result = scanner._build_result("2024-01-01T00:00:00Z", checks)
    assert result["checks"][0]["fix_state"] == "none"
    assert result["checks"][0]["remediation_id"] is None
    assert result["checks"][1]["fix_state"] == "available"
    assert result["checks"][1]["remediation_id"] == "FIX-SSH-1"


def test_scan_result_fix_state_dry_run_only(monkeypatch):
    monkeypatch.setenv("SECURITYWIZARD_DRY_RUN_ONLY", "1")
    checks = [
        _mock_check("CHK-1", "network", "Has fix", "PASS", "FIX-NET-1"),
    ]
    result = scanner._build_result("2024-01-01T00:00:00Z", checks)
    assert result["checks"][0]["fix_state"] == "dry_run_only"
    assert result["checks"][0]["remediation_id"] == "FIX-NET-1"


def test_api_status_dry_run_only(monkeypatch):
    monkeypatch.setenv("SECURITYWIZARD_DRY_RUN_ONLY", "1")
    client = TestClient(main.app)
    resp = client.get("/api/status", headers={"Host": "127.0.0.1"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["dry_run_only"] is True


def test_api_status_not_dry_run_only(monkeypatch):
    monkeypatch.setenv("SECURITYWIZARD_DRY_RUN_ONLY", "0")
    client = TestClient(main.app)
    resp = client.get("/api/status", headers={"Host": "127.0.0.1"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["dry_run_only"] is False


def test_ui_explains_why_fix_buttons_are_missing_or_disabled():
    """The explanations live in the dashboard script (English and Arabic dictionaries)."""
    js_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "static", "app.js")
    with open(js_path, "r", encoding="utf-8") as f:
        js = f.read()
    assert "No automatic fix" in js
    assert "Apply is disabled: the server runs in dry-run-only mode" in js
    assert "Apply is disabled: the server runs in read-only mode" in js
    assert "Preview fix" in js
    assert "'fix.dryRunOnly'" in js and "'fix.readOnly'" in js and "'noFix'" in js


def test_scan_result_fix_state_no_remediation_old_code_fails(monkeypatch):
    """Regression test: old code set fix_state='available' even when remediation_id was None.
    This test asserts that a check with remediation_id=None has fix_state='none'."""
    monkeypatch.setenv("SECURITYWIZARD_DRY_RUN_ONLY", "0")
    checks = [
        _mock_check("CHK-1", "network", "No fix", "PASS", None),
    ]
    result = scanner._build_result("2024-01-01T00:00:00Z", checks)
    # Old code: fix_state would be 'available' (wrong)
    # New code: fix_state must be 'none'
    assert result["checks"][0]["fix_state"] == "none", \
        "fix_state should be 'none' when remediation_id is None, got %r" % result["checks"][0]["fix_state"]


def test_scan_result_fix_state_dry_run_only_old_code_fails(monkeypatch):
    """Regression test: old code set fix_state='available' even when DRY_RUN_ONLY=1.
    This test asserts that a check with remediation_id set has fix_state='dry_run_only'
    when DRY_RUN_ONLY=1."""
    monkeypatch.setenv("SECURITYWIZARD_DRY_RUN_ONLY", "1")
    checks = [
        _mock_check("CHK-1", "network", "Has fix", "PASS", "FIX-NET-1"),
    ]
    result = scanner._build_result("2024-01-01T00:00:00Z", checks)
    # Old code: fix_state would be 'available' (wrong)
    # New code: fix_state must be 'dry_run_only'
    assert result["checks"][0]["fix_state"] == "dry_run_only", \
        "fix_state should be 'dry_run_only' when DRY_RUN_ONLY=1, got %r" % result["checks"][0]["fix_state"]
