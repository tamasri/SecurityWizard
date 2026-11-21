"""Scan history storage and diff utilities for SecurityWizard."""

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger("securitywizard")

SCAN_ID_RE = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")
HISTORY_KEEP = 50


def _history_dir() -> str:
    backup_dir = os.environ.get("SECURITYWIZARD_BACKUP_DIR", "/var/backups/securitywizard")
    return os.path.join(backup_dir, "history")


def scan_score(scan: Dict[str, Any]) -> Optional[float]:
    """Score of a scan result: the scanner stores a number (or None when nothing was scored); older files used {"total": n}."""
    value = scan.get("score")
    if isinstance(value, dict):
        value = value.get("total")
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def scan_counts(scan: Dict[str, Any]) -> Dict[str, Any]:
    return scan.get("status_counts") or scan.get("counts") or {}


def scan_timestamp(scan: Dict[str, Any]) -> str:
    return str(scan.get("timestamp") or scan.get("finished") or scan.get("started") or "")


def save_scan(result: Dict[str, Any]) -> str:
    """Persist a scan result dict to disk and return the scan id."""
    scan_id = result.get("scan_id", "")
    if not SCAN_ID_RE.match(scan_id):
        raise ValueError(f"Invalid scan_id: {scan_id!r}")
    d = _history_dir()
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, f"{scan_id}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    _prune(d)
    return scan_id


def list_scans() -> List[Dict[str, Any]]:
    """Return a list of scan summaries sorted newest first."""
    d = _history_dir()
    if not os.path.isdir(d):
        return []
    out: List[Dict[str, Any]] = []
    for fname in os.listdir(d):
        if not fname.endswith(".json"):
            continue
        sid = fname[:-5]
        if not SCAN_ID_RE.match(sid):
            continue
        path = os.path.join(d, fname)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as exc:
            logger.warning("Failed to read history file %s: %s", path, exc)
            continue
        out.append(
            {
                "scan_id": sid,
                "timestamp": scan_timestamp(data),
                "score": scan_score(data),
                "status_counts": scan_counts(data),
            }
        )
    out.sort(key=lambda x: x["timestamp"], reverse=True)
    return out


def load_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    """Load a single scan by id. Returns None if not found or unreadable."""
    if not SCAN_ID_RE.match(scan_id):
        return None
    path = os.path.join(_history_dir(), f"{scan_id}.json")
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        logger.warning("Failed to load scan %s: %s", scan_id, exc)
        return None


def diff_scans(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    """Compute the difference between two scan results.

    Returns a dict with keys:
      - new_findings: list of check ids present in new but not old (or old was SKIPPED)
      - resolved: list of check ids present in old but not new (or new is SKIPPED)
      - changed: list of dicts with check_id, old_status, new_status
      - score_delta: new score total minus old score total
    """
    old_checks = {c["id"]: c for c in old.get("checks", [])}
    new_checks = {c["id"]: c for c in new.get("checks", [])}

    new_findings: List[str] = []
    resolved: List[str] = []
    changed: List[Dict[str, str]] = []

    for cid, nc in new_checks.items():
        oc = old_checks.get(cid)
        if oc is None:
            new_findings.append(cid)
        else:
            if oc["status"] != nc["status"]:
                changed.append({"check_id": cid, "old_status": oc["status"], "new_status": nc["status"]})
                if oc["status"] == "SKIPPED" and nc["status"] != "SKIPPED":
                    new_findings.append(cid)
                elif nc["status"] == "SKIPPED" and oc["status"] != "SKIPPED":
                    resolved.append(cid)

    for cid, oc in old_checks.items():
        if cid not in new_checks:
            if oc["status"] != "SKIPPED":
                resolved.append(cid)

    old_score = scan_score(old) or 0
    new_score = scan_score(new) or 0

    return {
        "new_findings": sorted(new_findings),
        "resolved": sorted(resolved),
        "changed": sorted(changed, key=lambda x: x["check_id"]),
        "score_delta": new_score - old_score,
    }


def _prune(d: str) -> None:
    """Keep only the newest HISTORY_KEEP scan files, removing older ones."""
    if not os.path.isdir(d):
        return
    files = [f for f in os.listdir(d) if f.endswith(".json") and SCAN_ID_RE.match(f[:-5])]
    if len(files) <= HISTORY_KEEP:
        return
    try:
        entries = []
        for fname in files:
            path = os.path.join(d, fname)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                entries.append((data.get("timestamp", ""), path))
            except Exception:
                entries.append(("", path))
        entries.sort(key=lambda x: x[0], reverse=True)
        for _, path in entries[HISTORY_KEEP:]:
            try:
                os.remove(path)
            except OSError as exc:
                logger.warning("Failed to remove old history file %s: %s", path, exc)
    except Exception as exc:
        logger.warning("Error during history pruning: %s", exc)
