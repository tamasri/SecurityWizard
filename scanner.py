import importlib
from datetime import datetime, timezone

from common import STATUS_PASS, STATUS_WARNING, STATUS_CRITICAL, STATUS_INFO, STATUS_SKIPPED, make_check, skipped_check

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


def _build_result(start_iso, checks):
    counts = {STATUS_PASS: 0, STATUS_WARNING: 0, STATUS_CRITICAL: 0, STATUS_INFO: 0, STATUS_SKIPPED: 0}
    for c in checks:
        st = c.get("status", STATUS_SKIPPED)
        if st in counts:
            counts[st] += 1
    denom = counts[STATUS_PASS] + counts[STATUS_WARNING] + counts[STATUS_CRITICAL]
    if denom > 0:
        score = round(100 * (counts[STATUS_PASS] + 0.5 * counts[STATUS_WARNING]) / denom)
    else:
        score = 100
    return {
        "started": start_iso,
        "finished": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "counts": counts,
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
