import json
import os
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import history


def _make_result(scan_id: str, timestamp: str, checks: list, score_total: int = 80) -> Dict[str, Any]:
    return {
        "scan_id": scan_id,
        "timestamp": timestamp,
        "score": {"total": score_total, "pass": 5, "warning": 2, "critical": 1},
        "status_counts": {"PASS": 5, "WARNING": 2, "CRITICAL": 1},
        "checks": checks,
    }


def _check(cid: str, status: str, category: str = "network", title: str = "Check") -> Dict[str, Any]:
    return {
        "id": cid,
        "category": category,
        "title": title,
        "status": status,
        "what_it_checks": "test",
        "risk": "low",
        "command": "test",
        "current_value": "current",
        "recommended_value": "recommended",
        "details": [],
        "remediation_id": None,
        "manual_command": "",
    }


@pytest.fixture
def hist_dir(tmp_path, monkeypatch):
    backup = tmp_path / "backups"
    backup.mkdir()
    monkeypatch.setenv("SECURITYWIZARD_BACKUP_DIR", str(backup))
    return backup / "history"


def test_save_scan_creates_file(hist_dir):
    sid = str(uuid.uuid4())
    result = _make_result(sid, "2024-01-01T00:00:00+00:00", [_check("c1", "PASS")])
    returned = history.save_scan(result)
    assert returned == sid
    path = hist_dir / f"{sid}.json"
    assert path.is_file()
    with open(path, "r", encoding="utf-8") as f:
        loaded = json.load(f)
    assert loaded["scan_id"] == sid


def test_save_scan_invalid_id_raises(hist_dir):
    with pytest.raises(ValueError):
        history.save_scan(_make_result("not-a-uuid", "2024-01-01T00:00:00+00:00", []))


def test_list_scans_sorted_newest_first(hist_dir):
    ids = [str(uuid.uuid4()) for _ in range(3)]
    timestamps = ["2024-01-01T00:00:00+00:00", "2024-01-02T00:00:00+00:00", "2024-01-03T00:00:00+00:00"]
    for sid, ts in zip(ids, timestamps):
        history.save_scan(_make_result(sid, ts, []))
    scans = history.list_scans()
    assert len(scans) == 3
    assert scans[0]["scan_id"] == ids[2]
    assert scans[1]["scan_id"] == ids[1]
    assert scans[2]["scan_id"] == ids[0]


def test_load_scan_found(hist_dir):
    sid = str(uuid.uuid4())
    result = _make_result(sid, "2024-01-01T00:00:00+00:00", [_check("c1", "PASS")])
    history.save_scan(result)
    loaded = history.load_scan(sid)
    assert loaded is not None
    assert loaded["scan_id"] == sid
    assert loaded["checks"][0]["id"] == "c1"


def test_load_scan_not_found(hist_dir):
    assert history.load_scan(str(uuid.uuid4())) is None


def test_load_scan_invalid_id(hist_dir):
    assert history.load_scan("bad-id") is None


def test_diff_scans_new_findings():
    old = _make_result("old", "2024-01-01T00:00:00+00:00", [_check("c1", "PASS")], score_total=80)
    new = _make_result("new", "2024-01-02T00:00:00+00:00", [_check("c1", "PASS"), _check("c2", "WARNING")], score_total=70)
    diff = history.diff_scans(old, new)
    assert diff["new_findings"] == ["c2"]
    assert diff["resolved"] == []
    assert diff["score_delta"] == -10


def test_diff_scans_resolved():
    old = _make_result("old", "2024-01-01T00:00:00+00:00", [_check("c1", "PASS"), _check("c2", "CRITICAL")], score_total=70)
    new = _make_result("new", "2024-01-02T00:00:00+00:00", [_check("c1", "PASS")], score_total=85)
    diff = history.diff_scans(old, new)
    assert diff["new_findings"] == []
    assert diff["resolved"] == ["c2"]
    assert diff["score_delta"] == 15


def test_diff_scans_changed_status():
    old = _make_result("old", "2024-01-01T00:00:00+00:00", [_check("c1", "PASS")], score_total=90)
    new = _make_result("new", "2024-01-02T00:00:00+00:00", [_check("c1", "WARNING")], score_total=80)
    diff = history.diff_scans(old, new)
    assert diff["new_findings"] == []
    assert diff["resolved"] == []
    assert diff["changed"] == [{"check_id": "c1", "old_status": "PASS", "new_status": "WARNING"}]
    assert diff["score_delta"] == -10


def test_diff_scans_skipped_to_active():
    old = _make_result("old", "2024-01-01T00:00:00+00:00", [_check("c1", "SKIPPED")], score_total=50)
    new = _make_result("new", "2024-01-02T00:00:00+00:00", [_check("c1", "CRITICAL")], score_total=40)
    diff = history.diff_scans(old, new)
    assert diff["new_findings"] == ["c1"]
    assert diff["resolved"] == []
    assert diff["changed"] == [{"check_id": "c1", "old_status": "SKIPPED", "new_status": "CRITICAL"}]


def test_diff_scans_active_to_skipped():
    old = _make_result("old", "2024-01-01T00:00:00+00:00", [_check("c1", "CRITICAL")], score_total=40)
    new = _make_result("new", "2024-01-02T00:00:00+00:00", [_check("c1", "SKIPPED")], score_total=50)
    diff = history.diff_scans(old, new)
    assert diff["new_findings"] == []
    assert diff["resolved"] == ["c1"]
    assert diff["changed"] == [{"check_id": "c1", "old_status": "CRITICAL", "new_status": "SKIPPED"}]


def test_retention_keeps_last_50(hist_dir):
    for i in range(55):
        sid = str(uuid.uuid4())
        ts = f"2024-01-{(i % 28) + 1:02d}T{i % 24:02d}:00:00+00:00"
        history.save_scan(_make_result(sid, ts, []))
    files = list(hist_dir.glob("*.json"))
    assert len(files) == 50
