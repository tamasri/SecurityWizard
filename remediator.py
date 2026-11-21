import difflib
import json
import logging
import os
import shlex
import shutil
import stat
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import deadman

logger = logging.getLogger("securitywizard")


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _snap_id(rid):
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "_" + rid


ACTIONS = {}
for _mod in ("actions_network", "actions_ssh", "actions_system"):
    try:
        m = __import__(_mod)
        ACTIONS.update(m.ACTIONS)
    except ImportError:
        pass


def _validate_remediation_id(rid: str) -> bool:
    """The registry of actions is the allowlist: only a registered id can ever be previewed or applied."""
    return isinstance(rid, str) and rid in ACTIONS


_lock = threading.Lock()


def _is_root():
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def _drun():
    return os.environ.get("SECURITYWIZARD_DRY_RUN_ONLY", "") == "1"


def _allow_nonroot():
    return os.environ.get("SECURITYWIZARD_ALLOW_NONROOT", "") == "1"


def _bdir():
    return os.environ.get("SECURITYWIZARD_BACKUP_DIR", "/var/backups/securitywizard")


def _run_cmd(args: List[str], timeout: float = 120.0) -> Tuple[int, str, str]:
    try:
        r = subprocess.run(list(args), capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return 127, "", "not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        logger.exception("Unexpected error running command %s", " ".join(args))
        return 1, "", str(e)


def _file_snapshot(path, snap_dir):
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return None
    rel = path.lstrip("/")
    dest = os.path.join(snap_dir, rel)
    d = os.path.dirname(dest)
    if d:
        os.makedirs(d, exist_ok=True)
    shutil.copy2(path, dest)
    if _is_root():
        try:
            os.chown(dest, st.st_uid, st.st_gid)
        except (OSError, PermissionError):
            pass
    return {
        "path": path,
        "existed": True,
        "backup_file": dest,
        "mode": stat.S_IMODE(st.st_mode),
        "uid": st.st_uid,
        "gid": st.st_gid,
    }


def _atomic_write(path: str, content: str, orig_stat=None) -> None:
    d = os.path.dirname(path) or "."
    if d:
        os.makedirs(d, exist_ok=True)
    fd, tmp = None, None
    try:
        fd, tmp = tempfile.mkstemp(dir=d)
        with os.fdopen(fd, "w") as f:
            f.write(content)
        if orig_stat is not None:
            os.chmod(tmp, stat.S_IMODE(orig_stat.st_mode))
            if _is_root():
                try:
                    os.chown(tmp, orig_stat.st_uid, orig_stat.st_gid)
                except (OSError, PermissionError):
                    pass
        else:
            os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except Exception:
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _run_validators(validators: List[List[str]], runner) -> List[str]:
    """Run each validator command list.  Returns a list of failure messages
    (empty if all passed)."""
    failures = []
    for cmd in validators:
        rc, so, se = runner(cmd)
        if rc != 0:
            failures.append(" ".join(cmd) + " rc=" + str(rc) + (" " + se if se else ""))
    return failures


def _get_plan(rid: str) -> Optional[dict]:
    if rid not in ACTIONS:
        return None
    return ACTIONS[rid]["build_plan"]()


def _check_idempotent(plan: dict) -> bool:
    """Return True if the plan would change nothing (all file contents already
    match and all permissions already match)."""
    if not plan.get("file_changes") and not plan.get("perm_changes"):
        # Nothing to compare: a plan that only runs commands (for example the firewall baseline) can never be
        # recognised as already applied, so its commands must run. They are written to be repeatable.
        return not plan.get("commands")
    for fc in plan.get("file_changes", []):
        p = fc["path"]
        try:
            with open(p, "r") as f:
                current = f.read()
        except (OSError, IOError):
            return False
        if current != fc["new_content"]:
            return False
    for pc in plan.get("perm_changes", []):
        p = pc["path"]
        try:
            st = os.stat(p)
        except (OSError, FileNotFoundError):
            return False
        if stat.S_IMODE(st.st_mode) != pc["mode"]:
            return False
    return True


def preview(remediation_id: str) -> dict:
    out = {
        "remediation_id": remediation_id,
        "title": "",
        "description": "",
        "commands": [],
        "diffs": [],
        "perm_changes": [],
        "warnings": [],
        "blocked": False,
        "blocked_reason": None,
        "requires_root": False,
    }
    try:
        if not _validate_remediation_id(remediation_id):
            out["blocked"] = True
            out["blocked_reason"] = "Unknown remediation"
            return out
        info = ACTIONS[remediation_id]
        out["title"] = info.get("title", "")
        out["description"] = info.get("description", "")
        try:
            plan = info["build_plan"]()
        except Exception:
            out["blocked"] = True
            out["blocked_reason"] = "build_plan raised an exception"
            return out
        for fc in plan.get("file_changes", []):
            p = fc["path"]
            new = fc["new_content"]
            try:
                with open(p, "r") as f:
                    old = f.read()
            except (OSError, IOError):
                old = ""
            diff = list(
                difflib.unified_diff(old.splitlines(True), new.splitlines(True), fromfile="current", tofile="proposed")
            )
            out["diffs"].append({"path": p, "before": old, "after": new, "unified_diff": "".join(diff)})
        for pc in plan.get("perm_changes", []):
            p = pc["path"]
            try:
                st = os.stat(p)
                cur = oct(stat.S_IMODE(st.st_mode))[2:].zfill(4)
            except (OSError, FileNotFoundError):
                cur = "missing"
            out["perm_changes"].append({"path": p, "current_mode": cur, "new_mode": oct(pc["mode"])[2:]})
        out["commands"] = [shlex.join(c) for c in plan.get("commands", [])]
        out["warnings"] = list(plan.get("warnings", []))
        if plan.get("blockers"):
            out["blocked"] = True
            out["blocked_reason"] = "; ".join(plan["blockers"])
        out["requires_root"] = True
    except Exception as e:
        out["blocked"] = True
        out["blocked_reason"] = str(e)
    return out


def apply(remediation_id: str, confirm: bool = False, runner=None, precondition=None) -> dict:
    """Apply a remediation.

    *runner* is an optional callable ``(args: List[str]) -> (rc, stdout, stderr)``
    used instead of ``_run_cmd`` (for tests).  *precondition* is an optional
    callable ``(plan) -> Optional[str]`` that may refuse the change.

    Returns a dict with keys ``ok``, ``message``, ``snapshot_id``, ``output``,
    and optionally ``deadman_token`` / ``deadline`` for risky_remote actions.
    """
    out: Dict[str, Any] = {"ok": False, "message": "", "snapshot_id": None, "output": []}
    try:
        if not confirm:
            out["message"] = "confirm must be True"
            return out
        if _drun():
            out["message"] = "dry-run only"
            return out
        if not _is_root() and not _allow_nonroot():
            out["message"] = "requires root"
            return out
        if not _validate_remediation_id(remediation_id):
            out["message"] = "Unknown remediation"
            return out
        info = ACTIONS[remediation_id]
        try:
            plan = info["build_plan"]()
        except Exception as e:
            out["message"] = "build_plan failed: " + str(e)
            return out
        if plan.get("blockers"):
            out["message"] = "blocked: " + "; ".join(plan["blockers"])
            return out
        if precondition is not None:
            reason = precondition(plan)
            if reason is not None:
                out["message"] = "precondition: " + reason
                return out
        if _check_idempotent(plan):
            out["message"] = "already applied"
            out["ok"] = True
            return out
        run = runner or _run_cmd
        with _lock:
            snap_dir = os.path.join(_bdir(), _snap_id(remediation_id))
            os.makedirs(snap_dir, exist_ok=True)
            manifest = {
                "snapshot_id": os.path.basename(snap_dir),
                "created": _now_iso(),
                "remediation_id": remediation_id,
                "title": info.get("title", ""),
                "files": [],
                "inverse_commands": plan.get("inverse_commands", []),
            }
            for fc in plan.get("file_changes", []):
                p = fc["path"]
                entry = _file_snapshot(p, snap_dir)
                if entry is None:
                    entry = {"path": p, "existed": False, "backup_file": None, "mode": None, "uid": None, "gid": None}
                manifest["files"].append(entry)
            for pc in plan.get("perm_changes", []):
                p = pc["path"]
                entry = _file_snapshot(p, snap_dir)
                if entry is None:
                    entry = {"path": p, "existed": False, "backup_file": None, "mode": None, "uid": None, "gid": None}
                manifest["files"].append(entry)
            with open(os.path.join(snap_dir, "manifest.json"), "w") as f:
                json.dump(manifest, f, indent=2)
            out["snapshot_id"] = os.path.basename(snap_dir)
            for fc in plan.get("file_changes", []):
                p = fc["path"]
                try:
                    st = os.stat(p)
                except (OSError, FileNotFoundError):
                    st = None
                _atomic_write(p, fc["new_content"], st)
            for pc in plan.get("perm_changes", []):
                os.chmod(pc["path"], pc["mode"])
            for cmd in plan.get("validate_commands", []):
                rc, so, se = run(cmd)
                out["output"].append("validate " + shlex.join(cmd) + " rc=" + str(rc))
                if rc != 0:
                    rollback(out["snapshot_id"])
                    out["message"] = "validation failed, rolled back"
                    return out
            for cmd in plan.get("commands", []):
                rc, so, se = run(cmd)
                out["output"].append(shlex.join(cmd) + " rc=" + str(rc))
                if so:
                    out["output"].append(so)
                if se:
                    out["output"].append(se)
            out["ok"] = True
            out["message"] = "applied"
            if info.get("risky_remote"):
                token = "DM-" + remediation_id
                minutes = info.get("deadman_minutes", 5)
                deadline = time.time() + minutes * 60.0

                def _revert():
                    rollback(out["snapshot_id"])

                deadman.arm(
                    token,
                    _revert,
                    minutes,
                    _bdir(),
                    info={"snapshot_id": out["snapshot_id"], "remediation_id": remediation_id},
                )
                out["deadman_token"] = token
                out["deadline"] = deadline
    except Exception as e:
        logger.exception("apply(%s) failed", remediation_id)
        out["message"] = str(e)
    return out


def recover_deadman() -> List[str]:
    """After a restart: undo unconfirmed risky changes whose safety timer ran out, re-arm the others."""
    bdir = _bdir()
    states = deadman.get_state(bdir)

    def revert_factory(token):
        snapshot_id = states.get(token, {}).get("snapshot_id")

        def revert():
            if snapshot_id:
                rollback(snapshot_id)

        return revert

    return deadman.recover_pending(bdir, revert_factory)


def list_backups():
    out = []
    try:
        b = _bdir()
        if not os.path.isdir(b):
            return out
        for name in sorted(os.listdir(b), reverse=True):
            mpath = os.path.join(b, name, "manifest.json")
            if not os.path.isfile(mpath):
                continue
            try:
                with open(mpath) as f:
                    m = json.load(f)
                out.append(
                    {
                        "snapshot_id": name,
                        "created": m.get("created", ""),
                        "remediation_id": m.get("remediation_id", ""),
                        "title": m.get("title", ""),
                        "files": [e["path"] for e in m.get("files", [])],
                    }
                )
            except (json.JSONDecodeError, OSError):
                pass
    except Exception:
        pass
    return out


def rollback(snapshot_id):
    out = {"ok": False, "message": "", "restored": []}
    try:
        if not snapshot_id or not all(c.isalnum() or c in "_.-" for c in snapshot_id):
            out["message"] = "invalid snapshot id"
            return out
        snap_dir = os.path.join(_bdir(), snapshot_id)
        if not os.path.isdir(snap_dir):
            out["message"] = "snapshot not found"
            return out
        with open(os.path.join(snap_dir, "manifest.json")) as f:
            m = json.load(f)
        for entry in m.get("files", []):
            p = entry["path"]
            if entry["existed"]:
                shutil.copy2(entry["backup_file"], p)
                os.chmod(p, entry["mode"])
                if _is_root():
                    try:
                        os.chown(p, entry["uid"], entry["gid"])
                    except (OSError, PermissionError):
                        pass
            else:
                if os.path.exists(p):
                    os.unlink(p)
            out["restored"].append(p)
        for cmd in m.get("inverse_commands", []):
            _run_cmd(cmd)
        out["ok"] = True
        out["message"] = "rolled back"
    except Exception as e:
        out["message"] = str(e)
    return out
