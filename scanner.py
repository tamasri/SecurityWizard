import importlib
import logging
import os
import traceback
import concurrent.futures
from datetime import datetime, timezone
from typing import List, Optional

from common import (
    STATUS_PASS, STATUS_WARNING, STATUS_CRITICAL, STATUS_INFO, STATUS_SKIPPED,
    make_check, skipped_check,
)

logger = logging.getLogger(__name__)

MODULES = [
    ("network", "checks_network"),
    ("ssh", "checks_ssh"),
    ("kernel", "checks_kernel"),
    ("privilege", "checks_privilege"),
    ("docker", "checks_docker"),
    ("logs", "checks_logs"),
    ("misc", "checks_misc"),
    ("access", "checks_access"),
    ("system", "checks_system"),
]


def _get_worker_count() -> int:
    try:
        return max(1, int(os.environ.get("SECURITYWIZARD_WORKERS", "8")))
    except (ValueError, TypeError):
        return 8


def _get_check_timeout() -> float:
    try:
        return max(0.1, float(os.environ.get("SECURITYWIZARD_CHECK_TIMEOUT", "60")))
    except (ValueError, TypeError):
        return 60.0


def _run_module(category: str, module_name: str) -> List[dict]:
    try:
        mod = importlib.import_module(module_name)
        return mod.run_checks()
    except Exception as exc:
        logger.exception("Unexpected error in %s module", module_name)
        reason = "{}: {}".format(type(exc).__name__, exc)
        return [skipped_check(
            id="SCN-" + category,
            category=category,
            title="Module error",
            what_it_checks="Failed to load the " + category + " checks module.",
            risk="The " + category + " checks could not be evaluated.",
            command=module_name,
            reason=reason,
        )]


def _run_module_with_timeout(category: str, module_name: str, timeout: float) -> List[dict]:
    """Run a module's checks in a thread with a timeout.

    Returns the list of check dicts, or a single SKIPPED check if the timeout
    is exceeded or an unexpected error occurs.
    """
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_run_module, category, module_name)
            return future.result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        logger.warning("Module %s timed out after %.1fs", module_name, timeout)
        return [skipped_check(
            id="SCN-" + category,
            category=category,
            title="Timed out",
            what_it_checks="The " + category + " checks did not finish in time.",
            risk="The " + category + " checks could not be evaluated within the time limit.",
            command=module_name,
            reason="timed out after {:.1f} s".format(timeout),
        )]
    except Exception as exc:
        logger.exception("Unexpected error in %s module", module_name)
        reason = "{}: {}".format(type(exc).__name__, exc)
        return [skipped_check(
            id="SCN-" + category,
            category=category,
            title="Module error",
            what_it_checks="Failed to load the " + category + " checks module.",
            risk="The " + category + " checks could not be evaluated.",
            command=module_name,
            reason=reason,
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
    workers = _get_worker_count()
    timeout = _get_check_timeout()
    total = len(MODULES)
    module_results: List[Optional[List[dict]]] = [None] * total

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_index = {}
        for i, (category, module_name) in enumerate(MODULES):
            future = executor.submit(_run_module_with_timeout, category, module_name, timeout)
            future_to_index[future] = i

        for future in concurrent.futures.as_completed(future_to_index):
            idx = future_to_index[future]
            try:
                module_results[idx] = future.result()
            except Exception as exc:
                logger.exception("Unexpected error collecting result for module at index %d", idx)
                category, module_name = MODULES[idx]
                reason = "{}: {}".format(type(exc).__name__, exc)
                module_results[idx] = [skipped_check(
                    id="SCN-" + category,
                    category=category,
                    title="Module error",
                    what_it_checks="Failed to load the " + category + " checks module.",
                    risk="The " + category + " checks could not be evaluated.",
                    command=module_name,
                    reason=reason,
                )]
            if progress_cb is not None:
                # Report progress in module order, not completion order
                done_count = sum(1 for r in module_results if r is not None)
                progress_cb(done_count, total, MODULES[idx][0])

    checks = []
    for res in module_results:
        if res is not None:
            checks.extend(res)
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
