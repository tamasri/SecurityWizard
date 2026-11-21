import importlib
import logging
from datetime import datetime, timezone
from typing import List, Optional

from common import STATUS_PASS, STATUS_WARNING, STATUS_CRITICAL, STATUS_INFO, STATUS_SKIPPED, make_check, skipped_check

logger = logging.getLogger(__name__)

MODULES = [
    ("network", "checks_network"),
    ("ssh", "checks_ssh"),
    ("kernel", "checks_kernel"),
    ("privilege", "checks_privilege"),
    ("docker", "checks_docker"),
    ("logs", "checks_logs"),
]


def _run_module(category, module_name):
    try:
        mod = importlib.import_module(module_name)
        return mod.run_checks()
    except Exception as e:
        return [skipped_check(
            id="SCN-" + category,
            category=category,
            title="Module error",
            what_it_checks="Failed to load the " + category + " checks module.",
            risk="The " + category + " checks could not be evaluated.",
            command=module_name,
            reason=str(e),
        )]


def compute_score(checks: List[dict]) -> dict:
    """Compute the security score from a list of check result dicts.
    
    Returns a dict with 'score' (int or None), 'counts', 'excluded', 'formula', 'weights'.
    """
    counts = {STATUS_PASS: 0, STATUS_WARNING: 0, STATUS_CRITICAL: 0, STATUS_INFO: 0, STATUS_SKIPPED: 0}
    for c in checks:
        st = c.get("status", STATUS_SKIPPED)
        if st in counts:
            counts[st] += 1
    
    excluded = counts[STATUS_SKIPPED] + counts[STATUS_INFO]
    denom = counts[STATUS_PASS] + counts[STATUS_WARNING] + counts[STATUS_CRITICAL]
    
    not_scanned = denom == 0
    if not_scanned:
        score = None
        formula = "No scored checks (all SKIPPED or INFO)"
    else:
        score = round(100 * (counts[STATUS_PASS] + 0.5 * counts[STATUS_WARNING]) / denom)
        formula = f"100 * ({counts[STATUS_PASS]} PASS + 0.5 * {counts[STATUS_WARNING]} WARNING) / {denom} = {score}%"
    
    result = {
        "score": score,
        "counts": counts,
        "excluded": excluded,
        "formula": formula,
        "weights": {
            "PASS": 1.0,
            "WARNING": 0.5,
            "CRITICAL": 0.0,
            "INFO": "excluded",
            "SKIPPED": "excluded"
        }
    }
    if not_scanned:
        result["not_scanned"] = True
    return result


def _build_result(start_iso, checks):
    import os
    dry_run_only = os.environ.get("SECURITYWIZARD_DRY_RUN_ONLY", "0") == "1"
    for c in checks:
        rid = c.get("remediation_id")
        if rid:
            c["fix_state"] = "dry_run_only" if dry_run_only else "available"
        else:
            c["fix_state"] = "none"
    score_info = compute_score(checks)
    return {
        "started": start_iso,
        "finished": datetime.now(timezone.utc).isoformat(),
        "score": score_info["score"],
        "counts": score_info["counts"],
        "excluded": score_info["excluded"],
        "formula": score_info["formula"],
        "weights": score_info["weights"],
        "checks": checks,
    }


def run_full_scan(progress_cb=None):
    start_iso = datetime.now(timezone.utc).isoformat()
    checks = []
    total = len(MODULES)
    for i, (category, module_name) in enumerate(MODULES):
        checks.extend(_run_module(category, module_name))
        if progress_cb is not None:
            progress_cb(i + 1, total, category)
    return _build_result(start_iso, checks)


def run_category_scan(category):
    start_iso = datetime.now(timezone.utc).isoformat()
    checks = []
    for cat, module_name in MODULES:
        if cat == category:
            checks.extend(_run_module(cat, module_name))
            break
    else:
        checks.append(skipped_check(
            id="SCN-" + category,
            category=category,
            title="Unknown category",
            what_it_checks="The requested category was not found.",
            risk="No checks were run for this category.",
            command=category,
            reason="Unknown category: " + str(category),
        ))
    return _build_result(start_iso, checks)
