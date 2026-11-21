"""Dead-man switch for risky remote remediation actions.

``arm(token, revert_callable, minutes)`` schedules ``revert_callable`` to run
after *minutes* unless ``confirm(token)`` is called first.  The armed state is
persisted to a small JSON file in the backup directory so that a process
restart can still revert an unconfirmed change via ``recover_pending()``.

The timer is injectable (``timer_factory``) so tests can use a fake clock.
"""

import json
import os
import threading
import time
from typing import Callable, Dict, List, Optional

_lock = threading.Lock()
_timers: Dict[str, threading.Timer] = {}


def _default_timer_factory(seconds: float, callback: Callable[[], None]) -> threading.Timer:
    return threading.Timer(seconds, callback)


def _state_path(backup_dir: str) -> str:
    return os.path.join(backup_dir, "deadman.json")


def arm(token: str, revert_callable: Callable[[], None], minutes: float,
        backup_dir: str,
        timer_factory: Optional[Callable[[float, Callable[[], None]], threading.Timer]] = None) -> str:
    """Arm the dead-man switch for *token*.

    *revert_callable* is invoked after *minutes* unless ``confirm(token)`` is
    called first.  The armed state is written to *backup_dir*/deadman.json.

    Returns the token.
    """
    factory = timer_factory or _default_timer_factory
    timer = factory(minutes * 60.0, lambda: _revert(token, revert_callable, backup_dir))
    with _lock:
        _timers[token] = timer
    _persist({token: {"armed": True, "deadline": time.time() + minutes * 60.0}}, backup_dir)
    timer.start()
    return token


def confirm(token: str, backup_dir: str) -> bool:
    """Cancel the pending revert for *token*.  Returns True if the token was
    armed, False otherwise."""
    with _lock:
        timer = _timers.pop(token, None)
    if timer is not None:
        timer.cancel()
    _remove_persisted(token, backup_dir)
    return timer is not None


def cancel(token: str, backup_dir: str) -> bool:
    """Same as ``confirm`` – provided for API symmetry."""
    return confirm(token, backup_dir)


def pending(backup_dir: str) -> List[str]:
    """Return the list of currently armed tokens."""
    with _lock:
        return list(_timers.keys())


def _revert(token: str, revert_callable: Callable[[], None], backup_dir: str) -> None:
    with _lock:
        _timers.pop(token, None)
    revert_callable()
    _remove_persisted(token, backup_dir)


def _persist(states: Dict[str, dict], backup_dir: str) -> None:
    path = _state_path(backup_dir)
    os.makedirs(backup_dir, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(states, f, indent=2)


def _remove_persisted(token: str, backup_dir: str) -> None:
    path = _state_path(backup_dir)
    try:
        with open(path, "r", encoding="utf-8") as f:
            states = json.load(f)
    except (OSError, json.JSONDecodeError):
        return
    if token in states:
        del states[token]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(states, f, indent=2)


def recover_pending(backup_dir: str,
                    revert_factory: Callable[[str], Callable[[], None]],
                    timer_factory: Optional[Callable[[float, Callable[[], None]], threading.Timer]] = None) -> List[str]:
    """Re-arm any tokens that were persisted but not confirmed before a restart.

    *revert_factory* maps a token to the revert callable to invoke.  Only tokens
    whose deadline has not yet passed are re-armed.  Returns the list of
    re-armed tokens.
    """
    path = _state_path(backup_dir)
    try:
        with open(path, "r", encoding="utf-8") as f:
            states = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []
    factory = timer_factory or _default_timer_factory
    re_armed: List[str] = []
    now = time.time()
    for token, info in states.items():
        deadline = info.get("deadline", 0)
        if deadline <= now:
            continue
        revert_cb = revert_factory(token)
        timer = factory(deadline - now, lambda t=token: _revert(t, revert_cb, backup_dir))
        with _lock:
            _timers[token] = timer
        timer.start()
        re_armed.append(token)
    return re_armed
