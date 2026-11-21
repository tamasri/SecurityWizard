import json
import os
import threading
import time

import pytest

import deadman


class FakeTimer:
    """A fake threading.Timer that records callbacks without real waiting."""

    def __init__(self, seconds, callback):
        self.seconds = seconds
        self.callback = callback
        self.cancelled = False
        self.started = False

    def start(self):
        self.started = True

    def cancel(self):
        self.cancelled = True

    def fire(self):
        if not self.cancelled:
            self.callback()


def _make_fake_timer_factory():
    timers = []

    def factory(seconds, callback):
        t = FakeTimer(seconds, callback)
        timers.append(t)
        return t

    return factory, timers


def test_arm_and_confirm(tmp_path):
    factory, timers = _make_fake_timer_factory()
    reverted = []

    deadman.arm("tok1", lambda: reverted.append(1), 5, str(tmp_path), timer_factory=factory)
    assert len(timers) == 1
    assert timers[0].started
    assert deadman.confirm("tok1", str(tmp_path)) is True
    assert timers[0].cancelled
    timers[0].fire()
    assert reverted == []


def test_arm_and_timeout_revert(tmp_path):
    factory, timers = _make_fake_timer_factory()
    reverted = []

    deadman.arm("tok2", lambda: reverted.append(1), 1, str(tmp_path), timer_factory=factory)
    timers[0].fire()
    assert reverted == [1]
    assert deadman.pending(str(tmp_path)) == []


def test_cancel_prevents_revert(tmp_path):
    factory, timers = _make_fake_timer_factory()
    reverted = []

    deadman.arm("tok3", lambda: reverted.append(1), 2, str(tmp_path), timer_factory=factory)
    deadman.cancel("tok3", str(tmp_path))
    timers[0].fire()
    assert reverted == []


def test_pending_lists_armed_tokens(tmp_path):
    factory, _ = _make_fake_timer_factory()
    deadman.arm("a", lambda: None, 1, str(tmp_path), timer_factory=factory)
    deadman.arm("b", lambda: None, 1, str(tmp_path), timer_factory=factory)
    assert sorted(deadman.pending(str(tmp_path))) == ["a", "b"]


def test_persisted_state(tmp_path):
    factory, _ = _make_fake_timer_factory()
    deadman.arm("p1", lambda: None, 10, str(tmp_path), timer_factory=factory)
    path = os.path.join(str(tmp_path), "deadman.json")
    assert os.path.isfile(path)
    with open(path) as f:
        data = json.load(f)
    assert "p1" in data
    deadman.confirm("p1", str(tmp_path))
    with open(path) as f:
        data = json.load(f)
    assert "p1" not in data


def test_recover_pending(tmp_path):
    factory, timers = _make_fake_timer_factory()
    reverted = []

    deadman.arm("r1", lambda: reverted.append("r1"), 100, str(tmp_path), timer_factory=factory)
    # Simulate restart: clear in-memory timers
    deadman._timers.clear()

    re_armed = deadman.recover_pending(
        str(tmp_path),
        lambda token: lambda: reverted.append(token),
        timer_factory=factory,
    )
    assert re_armed == ["r1"]
    assert len(timers) == 2  # original + recovered
    timers[1].fire()
    assert reverted == ["r1"]
