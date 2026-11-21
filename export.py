"""Export scan results to JSON, Markdown, SARIF, and HTML formats."""

import json
import logging
from html import escape
from typing import Any, Dict, List

from history import scan_counts, scan_score, scan_timestamp

logger = logging.getLogger("securitywizard")

STATUS_TO_SARIF = {
    "PASS": "pass",
    "INFO": "note",
    "WARNING": "warning",
    "CRITICAL": "error",
    "SKIPPED": "note",
}


def to_json(result: Dict[str, Any]) -> str:
    """Return the scan result as a JSON string."""
    return json.dumps(result, indent=2, ensure_ascii=False)


def to_markdown(result: Dict[str, Any]) -> str:
    """Return a Markdown report of the scan result."""
    lines: List[str] = []
    lines.append("# SecurityWizard Scan Report")
    lines.append("")
    lines.append(f"**Scan ID:** {result.get('scan_id', 'N/A')}")
    lines.append(f"**Timestamp:** {scan_timestamp(result) or 'N/A'}")
    lines.append("")
    total = scan_score(result)
    lines.append(f"**Score:** {'not scored' if total is None else str(total) + '/100'}")
    lines.append("")
    counts = scan_counts(result)
    if counts:
        lines.append("**Status counts:** " + ", ".join(f"{k}: {v}" for k, v in sorted(counts.items())))
        lines.append("")
    lines.append("| Check | Category | Status | Title |")
    lines.append("|-------|----------|--------|-------|")
    for check in result.get("checks", []):
        cid = escape(check.get("id", ""))
        cat = escape(check.get("category", ""))
        status = escape(check.get("status", ""))
        title = escape(check.get("title", ""))
        lines.append(f"| {cid} | {cat} | {status} | {title} |")
    lines.append("")
    for check in result.get("checks", []):
        if check.get("status") not in ("PASS", "SKIPPED"):
            lines.append(f"### {escape(check.get('title', ''))}")
            lines.append("")
            lines.append(f"- **Check ID:** {escape(check.get('id', ''))}")
            lines.append(f"- **Status:** {escape(check.get('status', ''))}")
            lines.append(f"- **What it checks:** {escape(check.get('what_it_checks', ''))}")
            lines.append(f"- **Risk:** {escape(check.get('risk', ''))}")
            if check.get("current_value"):
                lines.append(f"- **Current value:** {escape(check.get('current_value', ''))}")
            if check.get("recommended_value"):
                lines.append(f"- **Recommended value:** {escape(check.get('recommended_value', ''))}")
            details = check.get("details") or []
            if details:
                lines.append("- **Details:**")
                for d in details:
                    lines.append(f"  - {escape(str(d))}")
            lines.append("")
    return "\n".join(lines)


def to_sarif(result: Dict[str, Any]) -> str:
    """Return a valid SARIF 2.1.0 JSON string for the scan result."""
    rules: Dict[str, Dict[str, Any]] = {}
    sarif_results: List[Dict[str, Any]] = []

    for check in result.get("checks", []):
        cid = check.get("id", "")
        rule_id = cid
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": check.get("title", cid),
                "description": check.get("what_it_checks", ""),
                "helpUri": "",
                "properties": {
                    "category": check.get("category", ""),
                    "risk": check.get("risk", ""),
                },
            }
        level = STATUS_TO_SARIF.get(check.get("status", "INFO"), "note")
        evidence_parts = []
        if check.get("current_value"):
            evidence_parts.append(f"Current: {check['current_value']}")
        if check.get("recommended_value"):
            evidence_parts.append(f"Recommended: {check['recommended_value']}")
        for d in check.get("details") or []:
            evidence_parts.append(str(d))
        message_text = "; ".join(evidence_parts) if evidence_parts else check.get("what_it_checks", "")
        sarif_results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": message_text,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": "server",
                            },
                        },
                    }
                ],
            }
        )

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecurityWizard",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/securitywizard/securitywizard",
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": [],
                    }
                ],
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def to_html(result: Dict[str, Any]) -> str:
    """Return a self-contained single-page HTML report with all text escaped."""
    checks = result.get("checks", [])
    total = scan_score(result)
    counts = scan_counts(result)

    def esc(s: Any) -> str:
        return escape(str(s), quote=True)

    rows: List[str] = []
    for check in checks:
        status = check.get("status", "")
        status_class = {
            "PASS": "pass",
            "WARNING": "warning",
            "CRITICAL": "critical",
            "INFO": "info",
            "SKIPPED": "skipped",
        }.get(status, "info")
        details_html = ""
        details = check.get("details") or []
        if details:
            items = "".join(f"<li>{esc(d)}</li>" for d in details)
            details_html = f"<ul>{items}</ul>"
        rows.append(
            f'<tr class="{status_class}">'
            f"<td>{esc(check.get('id', ''))}</td>"
            f"<td>{esc(check.get('category', ''))}</td>"
            f"<td>{esc(status)}</td>"
            f"<td>{esc(check.get('title', ''))}</td>"
            f"<td>{esc(check.get('current_value', ''))}</td>"
            f"<td>{esc(check.get('recommended_value', ''))}</td>"
            f"<td>{details_html}</td>"
            f"</tr>"
        )

    counts_html = ", ".join(f"{esc(k)}: {esc(v)}" for k, v in sorted(counts.items()))
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecurityWizard Report</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 2rem; color: #222; }}
h1 {{ font-size: 1.5rem; }}
.meta {{ margin-bottom: 1rem; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
th, td {{ border: 1px solid #ccc; padding: 0.5rem; text-align: left; vertical-align: top; }}
th {{ background: #f4f4f4; }}
tr.pass td:nth-child(3) {{ color: #2e7d32; font-weight: bold; }}
tr.warning td:nth-child(3) {{ color: #f57f17; font-weight: bold; }}
tr.critical td:nth-child(3) {{ color: #c62828; font-weight: bold; }}
tr.info td:nth-child(3) {{ color: #1565c0; font-weight: bold; }}
tr.skipped td:nth-child(3) {{ color: #757575; font-weight: bold; }}
ul {{ margin: 0; padding-left: 1.2rem; }}
</style>
</head>
<body>
<h1>SecurityWizard Scan Report</h1>
<div class="meta">
<p><strong>Scan ID:</strong> {esc(result.get("scan_id", "N/A"))}</p>
<p><strong>Timestamp:</strong> {esc(scan_timestamp(result) or "N/A")}</p>
<p><strong>Score:</strong> {esc("not scored" if total is None else str(total) + "/100")}</p>
<p><strong>Status counts:</strong> {counts_html}</p>
</div>
<table>
<thead>
<tr><th>ID</th><th>Category</th><th>Status</th><th>Title</th><th>Current</th><th>Recommended</th><th>Details</th></tr>
</thead>
<tbody>
{"".join(rows)}
</tbody>
</table>
</body>
</html>"""
    return html
