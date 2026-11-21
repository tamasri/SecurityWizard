import sys
import time
import threading
import pytest
import scanner
from common import STATUS_SKIPPED, STATUS_PASS


def _make_fake_module(monkeypatch, name, results, delay=0.0, crash=False):
    """Create a fake module that returns predefined results."""
    def run_checks():
        if delay > 0:
            time.sleep(delay)
        if crash:
            raise RuntimeError("Simulated crash")
        return results
    mod = type(sys)('fake_' + name)
    mod.run_checks = run_checks
    monkeypatch.setitem(sys.modules, name, mod)


def _isolate_scanner(monkeypatch, modules):
    """Replace scanner.MODULES with only the given modules to isolate the scan."""
    monkeypatch.setattr(scanner, "MODULES", modules)
    # Also patch importlib.import_module to only return fake modules for the ones we registered
    original_import = __import__("importlib").import_module
    def fake_import_module(name):
        if name in [m[1] for m in modules]:
            return original_import(name)
        raise ImportError("Module not registered: " + name)
    monkeypatch.setattr(scanner, "importlib", type("FakeImportlib", (), {"import_module": fake_import_module}))


def test_concurrent_execution_is_faster_than_sequential(monkeypatch):
    """Two slow checks should run in parallel, not sequentially."""
    # Each check takes 0.3s; sequential would be 0.6s, parallel should be < 0.5s
    results_a = [
        {"id": "NET-001", "category": "network", "title": "T1", "status": STATUS_PASS,
         "what_it_checks": "", "risk": "", "command": "", "current_value": "",
         "recommended_value": "", "details": [], "remediation_id": None, "manual_command": ""}
    ]
    results_b = [
        {"id": "SSH-001", "category": "ssh", "title": "T2", "status": STATUS_PASS,
         "what_it_checks": "", "risk": "", "command": "", "current_value": "",
         "recommended_value": "", "details": [], "remediation_id": None, "manual_command": ""}
    ]
    _make_fake_module(monkeypatch, "checks_network", results_a, delay=0.3)
    _make_fake_module(monkeypatch, "checks_ssh", results_b, delay=0.3)

    _isolate_scanner(monkeypatch, [
        ("network", "checks_network"),
        ("ssh", "checks_ssh"),
    ])

    start = time.monotonic()
    result = scanner.run_full_scan()
    elapsed = time.monotonic() - start

    # Sequential would be >= 0.6s; parallel should be well under that
    assert elapsed < 0.55, f"Expected parallel execution, got {elapsed:.3f}s"
    assert len(result["checks"]) == 2


def test_timeout_produces_skipped(monkeypatch):
    """A check that exceeds the timeout yields SKIPPED with the reason."""
    def slow_run_checks():
        time.sleep(2.0)  # longer than the 0.2s timeout
        return []

    mod = type(sys)('fake_network')
    mod.run_checks = slow_run_checks
    monkeypatch.setitem(sys.modules, "checks_network", mod)

    _isolate_scanner(monkeypatch, [
        ("network", "checks_network"),
    ])

    monkeypatch.setenv("SECURITYWIZARD_CHECK_TIMEOUT", "0.2")
    monkeypatch.setenv("SECURITYWIZARD_WORKERS", "4")

    result = scanner.run_full_scan()
    skipped = [c for c in result["checks"] if c["status"] == STATUS_SKIPPED]
    assert len(skipped) == 1
    assert "timed out after 0.2 s" in skipped[0]["current_value"]


def test_stable_order(monkeypatch):
    """Results must preserve module order, then check id order."""
    results_network = [
        {"id": "NET-002", "category": "network", "title": "B", "status": STATUS_PASS,
         "what_it_checks": "", "risk": "", "command": "", "current_value": "",
         "recommended_value": "", "details": [], "remediation_id": None, "manual_command": ""},
        {"id": "NET-001", "category": "network", "title": "A", "status": STATUS_PASS,
         "what_it_checks": "", "risk": "", "command": "", "current_value": "",
         "recommended_value": "", "details": [], "remediation_id": None, "manual_command": ""},
    ]
    results_ssh = [
        {"id": "SSH-001", "category": "ssh", "title": "C", "status": STATUS_PASS,
         "what_it_checks": "", "risk": "", "command": "", "current_value": "",
         "recommended_value": "", "details": [], "remediation_id": None, "manual_command": ""},
    ]
    _make_fake_module(monkeypatch, "checks_network", results_network, delay=0.1)
    _make_fake_module(monkeypatch, "checks_ssh", results_ssh, delay=0.0)

    _isolate_scanner(monkeypatch, [
        ("network", "checks_network"),
        ("ssh", "checks_ssh"),
    ])

    result = scanner.run_full_scan()
    ids = [c["id"] for c in result["checks"]]
    # network module comes first in MODULES, so NET-002 and NET-001 appear before SSH-001
    assert ids == ["NET-002", "NET-001", "SSH-001"]


def test_crashing_check_does_not_abort_scan(monkeypatch):
    """A module that raises should yield a SKIPPED result, not crash the scan."""
    def crashing_run_checks():
        raise RuntimeError("Simulated crash")

    mod = type(sys)('fake_kernel')
    mod.run_checks = crashing_run_checks
    monkeypatch.setitem(sys.modules, "checks_kernel", mod)

    results_network = [
        {"id": "NET-001", "category": "network", "title": "OK", "status": STATUS_PASS,
         "what_it_checks": "", "risk": "", "command": "", "current_value": "",
         "recommended_value": "", "details": [], "remediation_id": None, "manual_command": ""}
    ]
    _make_fake_module(monkeypatch, "checks_network", results_network)

    _isolate_scanner(monkeypatch, [
        ("network", "checks_network"),
        ("kernel", "checks_kernel"),
    ])

    result = scanner.run_full_scan()
    # The crashing kernel module should produce a SKIPPED check
    skipped = [c for c in result["checks"] if c["status"] == STATUS_SKIPPED and c["category"] == "kernel"]
    assert len(skipped) == 1
    assert "RuntimeError" in skipped[0]["current_value"]
    # The network check should still be present
    net_checks = [c for c in result["checks"] if c["category"] == "network"]
    assert len(net_checks) == 1
    assert net_checks[0]["status"] == STATUS_PASS
