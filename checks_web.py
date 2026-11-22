"""HTTP(S) security response header audit for the operator's own reverse-proxied sites.

Every host checked here must be listed under [pentest].targets (see pentest_common.py); anything else is
refused. The only network action is a single HTTPS GET of "/" to read the response headers - detection
only, never exploitation: no other path is requested, no form is submitted, and the response body is
discarded unread.
"""

import logging
import ssl
from http.client import HTTPSConnection
from typing import Callable, Dict, List, Optional

from common import STATUS_CRITICAL, STATUS_PASS, STATUS_WARNING, make_check, skipped_check
from config import get_config
from pentest_common import audit_scan, check_target_allowed

logger = logging.getLogger("securitywizard")

CATEGORY = "web"

#: header (lowercase) -> (display label, whether its absence alone is only informational)
REQUIRED_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "strict-transport-security": "Strict-Transport-Security",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
}
#: headers whose absence alone never raises the status past INFO.
INFO_ONLY_HEADERS = {"referrer-policy"}

#: recommended minimum Strict-Transport-Security max-age, in seconds (180 days).
MIN_HSTS_MAX_AGE = 15552000

FetchFn = Callable[[str, int, float], Dict[str, str]]


def configured_domains() -> List[str]:
    """Domains from the [pentest] allowlist (host entries only)."""
    return sorted({t.host for t in get_config().pentest_targets if t.host})


def _fetch_headers(host: str, port: int = 443, timeout: float = 5.0) -> Dict[str, str]:
    """Real network call: one HTTPS GET of '/'. The body is never read into memory beyond draining the
    socket so the connection can close cleanly; it is never inspected."""
    ctx = ssl.create_default_context()
    conn = HTTPSConnection(host, port, timeout=timeout, context=ctx)
    try:
        conn.request("GET", "/", headers={"User-Agent": "SecurityWizard-header-check", "Accept": "*/*"})
        resp = conn.getresponse()
        resp.read()
        return {key.lower(): value for key, value in resp.getheaders()}
    finally:
        conn.close()


def _parse_hsts_max_age(value: str) -> Optional[int]:
    for part in value.split(";"):
        part = part.strip()
        if part.lower().startswith("max-age="):
            try:
                return int(part.split("=", 1)[1])
            except ValueError:
                return None
    return None


def check_security_headers(host: str, fetch: Optional[FetchFn] = None) -> List[dict]:
    """WEB-001 (presence of standard protective headers) and WEB-002 (HSTS max-age, if HSTS is present)."""
    title = f"{host}: security response headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)"
    what = "Fetches the response headers for the site's home page and checks for standard protective headers."
    risk = (
        "Missing security headers make the site more exploitable via clickjacking, MIME-type sniffing, "
        "protocol downgrade and script injection, even when the application code itself is otherwise sound."
    )
    cmd = f"curl -sI https://{host}/"

    reason = check_target_allowed(host)
    if reason:
        audit_scan("WEB-001", host, "SKIPPED", reason)
        return [skipped_check("WEB-001", CATEGORY, title, what, risk, cmd, reason)]

    try:
        raw_headers = (fetch or _fetch_headers)(host, 443, 5.0)
    except Exception as exc:
        audit_scan("WEB-001", host, "SKIPPED", str(exc))
        return [skipped_check("WEB-001", CATEGORY, title, what, risk, cmd, f"Request failed: {exc}")]
    # Normalise here too, not only inside _fetch_headers: a caller-supplied `fetch` (as in tests, or any
    # future caller) may return headers in whatever case the server sent them.
    headers = {key.lower(): value for key, value in raw_headers.items()}

    present: List[str] = []
    missing: List[str] = []
    for key, label in REQUIRED_HEADERS.items():
        (present if key in headers else missing).append(label)
    core_missing = [
        label for key, label in REQUIRED_HEADERS.items() if key not in headers and key not in INFO_ONLY_HEADERS
    ]

    if not core_missing:
        status = STATUS_PASS
    elif len(core_missing) >= 3:
        status = STATUS_CRITICAL
    else:
        status = STATUS_WARNING
    current = "Present: {}. Missing: {}.".format(", ".join(present) or "none", ", ".join(missing) or "none")
    audit_scan("WEB-001", host, status, current)

    results = [
        make_check(
            "WEB-001",
            CATEGORY,
            title,
            status,
            what,
            risk,
            cmd,
            current_value=current,
            recommended_value="Set Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, "
            "X-Content-Type-Options and Referrer-Policy",
            details=[
                f"{label}: {'present' if key in headers else 'MISSING'}" for key, label in REQUIRED_HEADERS.items()
            ],
        )
    ]

    if "strict-transport-security" in headers:
        hsts_value = headers["strict-transport-security"]
        max_age = _parse_hsts_max_age(hsts_value)
        hsts_title = f"{host}: Strict-Transport-Security max-age"
        hsts_what = "Checks the max-age directive of the Strict-Transport-Security header."
        hsts_risk = (
            "A short (or missing) max-age gives only brief protection against protocol-downgrade attacks "
            "after the first visit."
        )
        if max_age is None:
            hsts_status, hsts_current = STATUS_WARNING, f"Could not parse max-age from: {hsts_value}"
        elif max_age < MIN_HSTS_MAX_AGE:
            hsts_status = STATUS_WARNING
            hsts_current = f"max-age={max_age}s (~{max_age // 86400} day(s)), below the recommended {MIN_HSTS_MAX_AGE // 86400} days"
        else:
            hsts_status, hsts_current = STATUS_PASS, f"max-age={max_age}s (~{max_age // 86400} day(s))"
        audit_scan("WEB-002", host, hsts_status, hsts_current)
        results.append(
            make_check(
                "WEB-002",
                CATEGORY,
                hsts_title,
                hsts_status,
                hsts_what,
                hsts_risk,
                cmd,
                current_value=hsts_current,
                recommended_value=f">= {MIN_HSTS_MAX_AGE} seconds, with includeSubDomains",
                details=[hsts_value],
            )
        )
    return results


def run_checks() -> List[dict]:
    """Run the security-header audit for every domain in the [pentest] allowlist."""
    results: List[dict] = []
    domains = configured_domains()
    if not domains:
        results.append(
            skipped_check(
                "WEB-001",
                CATEGORY,
                "Security response headers",
                "Fetches response headers for every domain in the [pentest] target allowlist.",
                "No domains configured means this area is not audited.",
                "curl -sI https://<domain>/",
                "No domains configured under [pentest].targets; add hosts to securitywizard.toml to enable this check.",
            )
        )
        return results
    for host in domains:
        try:
            results.extend(check_security_headers(host))
        except Exception as exc:
            logger.exception("WEB-001 failed for %s", host)
            audit_scan("WEB-001", host, "SKIPPED", str(exc))
            results.append(
                skipped_check(
                    "WEB-001",
                    CATEGORY,
                    f"{host}: security response headers",
                    "Fetches response headers and checks for standard protective headers.",
                    "Could not evaluate this domain.",
                    f"curl -sI https://{host}/",
                    f"Unexpected error: {exc}",
                )
            )
    return results
