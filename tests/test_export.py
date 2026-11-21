import json
import os
import sys
from typing import Any, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import export


def _sample_result() -> Dict[str, Any]:
    return {
        "scan_id": "abc-123",
        "timestamp": "2024-01-01T00:00:00+00:00",
        "score": {"total": 85, "pass": 10, "warning": 3, "critical": 1},
        "status_counts": {"PASS": 10, "WARNING": 3, "CRITICAL": 1, "SKIPPED": 2},
        "checks": [
            {
                "id": "net-01",
                "category": "network",
                "title": "SSH port",
                "status": "WARNING",
                "what_it_checks": "SSH port exposure",
                "risk": "medium",
                "command": "ss -tlnp",
                "current_value": "0.0.0.0:22",
                "recommended_value": "127.0.0.1:22",
                "details": ["<script>alert('xss')</script>"],
                "remediation_id": "fix-ssh-port",
                "manual_command": "",
            },
            {
                "id": "net-02",
                "category": "network",
                "title": "Firewall",
                "status": "PASS",
                "what_it_checks": "Firewall active",
                "risk": "high",
                "command": "iptables -L",
                "current_value": "active",
                "recommended_value": "",
                "details": [],
                "remediation_id": None,
                "manual_command": "",
            },
        ],
    }


def test_to_json_roundtrip():
    result = _sample_result()
    out = export.to_json(result)
    parsed = json.loads(out)
    assert parsed == result


def test_to_markdown_contains_sections():
    result = _sample_result()
    md = export.to_markdown(result)
    assert "# SecurityWizard Scan Report" in md
    assert "net-01" in md
    assert "WARNING" in md
    assert "**Score:** 85/100" in md
    assert "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;" in md


def test_to_sarif_structure():
    result = _sample_result()
    sarif_str = export.to_sarif(result)
    sarif = json.loads(sarif_str)
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "SecurityWizard"
    rule_ids = [r["id"] for r in driver["rules"]]
    assert "net-01" in rule_ids
    assert "net-02" in rule_ids
    assert len(run["results"]) == 2
    r0 = run["results"][0]
    assert r0["ruleId"] == "net-01"
    assert r0["level"] == "warning"
    assert "<script>alert('xss')</script>" in r0["message"]["text"]
    r1 = run["results"][1]
    assert r1["ruleId"] == "net-02"
    assert r1["level"] == "pass"


def test_to_sarif_level_mapping():
    result = _sample_result()
    result["checks"][0]["status"] = "CRITICAL"
    sarif = json.loads(export.to_sarif(result))
    assert sarif["runs"][0]["results"][0]["level"] == "error"
    result["checks"][0]["status"] = "SKIPPED"
    sarif = json.loads(export.to_sarif(result))
    assert sarif["runs"][0]["results"][0]["level"] == "note"
    result["checks"][0]["status"] = "INFO"
    sarif = json.loads(export.to_sarif(result))
    assert sarif["runs"][0]["results"][0]["level"] == "note"


def test_to_html_escapes_xss():
    result = _sample_result()
    html = export.to_html(result)
    assert "<script>alert('xss')</script>" not in html
    assert "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;" in html
    assert "<!DOCTYPE html>" in html
    assert "SecurityWizard Scan Report" in html


def test_to_html_contains_all_checks():
    result = _sample_result()
    html = export.to_html(result)
    assert "net-01" in html
    assert "net-02" in html
    assert "WARNING" in html
    assert "PASS" in html
