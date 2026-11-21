"""Dead-man switch for risky remote remediation actions.

``arm(token, revert_callable, minutes)`` schedules ``revert_callable`` to run
after *minutes* unless ``confirm(token)`` is called first.  The armed state is
persisted to a small JSON file in the backup directory so that a process
restart can still revert an unconfirmed change via ``recover_pending()``.

The timer is injectable (``timer_factory``) so tests can use a fake clock.
"""

import json
import logging
import os
import threading
import time
from typing import Callable, Dict, List, Optional

logger = logging.getLogger("securitywizard")

_lock = threading.Lock()
_timers: Dict[str, threading.Timer] = {}


def _default_timer_factory(seconds: float, callback: Callable[[], None]) -> threading.Timer:
    # Daemon thread: a pending timer must never keep the server from shutting down. The state file lets
    # recover_pending() deal with an unconfirmed change after a restart.
    timer = threading.Timer(seconds, callback)
    timer.daemon = True
    return timer


def _state_path(backup_dir: str) -> str:
    return os.path.join(backup_dir, "deadman.json")


def arm(
    token: str,
    revert_callable: Callable[[], None],
    minutes: float,
    backup_dir: str,
    timer_factory: Optional[Callable[[float, Callable[[], None]], threading.Timer]] = None,
    info: Optional[dict] = None,
) -> str:
    """Arm the dead-man switch for *token*.

    *revert_callable* is invoked after *minutes* unless ``confirm(token)`` is
    called first.  The armed state is merged into *backup_dir*/deadman.json
    together with *info* (for example the snapshot id needed to revert after a restart).

    Returns the token.
    """
    factory = timer_factory or _default_timer_factory
    timer = factory(minutes * 60.0, lambda: _revert(token, revert_callable, backup_dir))
    with _lock:
        _timers[token] = timer
    states = get_state(backup_dir)
    states[token] = dict(info or {}, armed=True, deadline=time.time() + minutes * 60.0)
    _persist(states, backup_dir)
    timer.start()
    return token


def get_state(backup_dir: str) -> Dict[str, dict]:
    """The persisted state of every armed token (empty when there is none or the file is unreadable)."""
    try:
        with open(_state_path(backup_dir), "r", encoding="utf-8") as f:
            states = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    return states if isinstance(states, dict) else {}


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


def recover_pending(
    backup_dir: str,
    revert_factory: Callable[[str], Callable[[], None]],
    timer_factory: Optional[Callable[[float, Callable[[], None]], threading.Timer]] = None,
) -> List[str]:
    """Re-arm any tokens that were persisted but not confirmed before a restart.

    *revert_factory* maps a token to the revert callable to invoke.  Tokens
    whose deadline has not yet passed are re-armed; tokens whose deadline
    passed during the downtime are reverted immediately.  Returns the list of
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
            # The timer ran out while the service was down and nobody confirmed the change: undo it now.
            try:
                revert_factory(token)()
            except Exception:
                logger.exception("Could not revert the unconfirmed change %s", token)
            _remove_persisted(token, backup_dir)
            continue
        revert_cb = revert_factory(token)

        def expire(t: str = token, cb: Callable[[], None] = revert_cb) -> None:
            _revert(t, cb, backup_dir)

        timer = factory(deadline - now, expire)
        with _lock:
            _timers[token] = timer
        timer.start()
        re_armed.append(token)
    return re_armed
