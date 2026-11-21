"""deadman: daemon timers, merged state, and recovery after a restart (reverting overdue changes)."""

import json
import threading
import time

import deadman
import remediator


class FakeTimer:
    def __init__(self, seconds, callback):
        self.seconds, self.callback, self.started, self.cancelled = seconds, callback, False, False

    def start(self):
        self.started = True

    def cancel(self):
        self.cancelled = True


def _state(tmp_path):
    return json.loads((tmp_path / "deadman.json").read_text(encoding="utf-8"))


def test_default_timer_is_a_daemon_thread():
    timer = deadman._default_timer_factory(60, lambda: None)
    assert isinstance(timer, threading.Timer) and timer.daemon is True  # never blocks the server's shutdown


def test_state_is_merged_not_overwritten(tmp_path):
    deadman.arm("DM-first", lambda: None, 5, str(tmp_path), timer_factory=FakeTimer, info={"snapshot_id": "s1"})
    deadman.arm("DM-second", lambda: None, 5, str(tmp_path), timer_factory=FakeTimer, info={"snapshot_id": "s2"})
    state = _state(tmp_path)
    assert set(state) == {"DM-first", "DM-second"}
    assert state["DM-first"]["snapshot_id"] == "s1" and state["DM-second"]["armed"] is True
    assert deadman.get_state(str(tmp_path)) == state
    deadman.confirm("DM-first", str(tmp_path))
    deadman.confirm("DM-second", str(tmp_path))


def test_get_state_handles_missing_and_corrupt_files(tmp_path):
    assert deadman.get_state(str(tmp_path)) == {}
    (tmp_path / "deadman.json").write_text("not json", encoding="utf-8")
    assert deadman.get_state(str(tmp_path)) == {}
    (tmp_path / "deadman.json").write_text("[1, 2]", encoding="utf-8")
    assert deadman.get_state(str(tmp_path)) == {}


def test_recovery_reverts_overdue_changes_and_rearms_the_others(tmp_path):
    (tmp_path / "deadman.json").write_text(
        json.dumps({"DM-overdue": {"deadline": time.time() - 30}, "DM-later": {"deadline": time.time() + 120}}),
        encoding="utf-8",
    )
    reverted = []
    armed = deadman.recover_pending(
        str(tmp_path), lambda token: lambda: reverted.append(token), timer_factory=FakeTimer
    )
    assert reverted == ["DM-overdue"] and armed == ["DM-later"]
    assert set(_state(tmp_path)) == {"DM-later"}  # the reverted one is forgotten
    deadman.confirm("DM-later", str(tmp_path))


def test_recovery_survives_a_failing_revert(tmp_path):
    (tmp_path / "deadman.json").write_text(json.dumps({"DM-bad": {"deadline": time.time() - 5}}), encoding="utf-8")

    def factory(token):
        def revert():
            raise RuntimeError("cannot revert")

        return revert

    assert deadman.recover_pending(str(tmp_path), factory, timer_factory=FakeTimer) == []
    assert _state(tmp_path) == {}


def test_recovery_without_a_state_file(tmp_path):
    assert deadman.recover_pending(str(tmp_path), lambda token: lambda: None) == []


def test_remediator_recovers_through_the_snapshot_id(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITYWIZARD_BACKUP_DIR", str(tmp_path))
    (tmp_path / "deadman.json").write_text(
        json.dumps(
            {
                "DM-ssh_x": {"deadline": time.time() - 1, "snapshot_id": "20260101T000000_ssh_x"},
                "DM-no_snapshot": {"deadline": time.time() - 1},
            }
        ),
        encoding="utf-8",
    )
    rolled_back = []
    monkeypatch.setattr(remediator, "rollback", lambda snapshot: rolled_back.append(snapshot))
    assert remediator.recover_deadman() == []
    assert rolled_back == ["20260101T000000_ssh_x"]
