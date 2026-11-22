"""Resilience / availability configuration review.

This module never sends traffic to anything: it only parses local configuration files that the operator
already deployed (Traefik, Nginx, Stalwart, fail2ban/CrowdSec) and reports whether rate limiting,
connection/request-size limits and timeouts are configured, with what is missing. It is deliberately NOT a
load or denial-of-service test: SecurityWizard does not send high-volume traffic to a live service, flood
connections, or otherwise try to degrade one. (A separate, explicitly opt-in, hard-time-and-request-capped
bounded load check for a designated staging/test instance may be added later; this module is config-review
only.)
"""

import configparser
import glob
import logging
import os
import re
from typing import Dict, List, Optional, Tuple

from common import STATUS_CRITICAL, STATUS_INFO, STATUS_PASS, STATUS_WARNING, make_check, skipped_check
from envdetect import detect_environment

logger = logging.getLogger("securitywizard")

CATEGORY = "resilience"

TRAEFIK_PATTERNS = [
    "/etc/traefik/dynamic.yml",
    "/etc/traefik/dynamic.yaml",
    "/etc/traefik/dynamic/*.yml",
    "/etc/traefik/dynamic/*.yaml",
    "/data/coolify/proxy/dynamic/*.yaml",
    "/data/coolify/proxy/dynamic/*.yml",
]
NGINX_PATTERNS = [
    "/etc/nginx/nginx.conf",
    "/etc/nginx/conf.d/*.conf",
    "/etc/nginx/sites-enabled/*",
]
STALWART_PATTERNS = [
    "/opt/stalwart-mail/etc/config.toml",
    "/etc/stalwart-mail/config.toml",
    "/etc/stalwart/config.toml",
]
FAIL2BAN_PATTERNS = [
    "/etc/fail2ban/jail.local",
    "/etc/fail2ban/jail.d/*.conf",
    "/etc/fail2ban/jail.d/*.local",
]
EXPECTED_JAILS: Dict[str, List[str]] = {
    "ssh": ["sshd", "ssh"],
    "mail (SMTP/submission)": ["postfix", "postfix-sasl", "stalwart", "sasl", "exim"],
    "web auth": ["nginx-http-auth", "traefik-auth", "apache-auth", "haproxy-http-auth"],
}


def _glob_read(patterns: List[str]) -> Dict[str, str]:
    """Read every file matching any of `patterns`. A literal, already-existing path matches itself."""
    out: Dict[str, str] = {}
    for pattern in patterns:
        for path in sorted(glob.glob(pattern)):
            if path in out or not os.path.isfile(path):
                continue
            try:
                with open(path, encoding="utf-8", errors="replace") as handle:
                    out[path] = handle.read()
            except OSError as exc:
                logger.warning("Could not read %s: %s", path, exc)
    return out


def check_traefik_limits(patterns: Optional[List[str]] = None) -> dict:
    """RES-001: Traefik rate limiting, request-size and timeout configuration."""
    title = "Traefik rate limiting, request-size and timeout configuration"
    what = (
        "Parses Traefik's dynamic configuration for a rateLimit middleware, a request body size limit "
        "(buffering/maxRequestBodyBytes), and explicit responding/forwarding timeouts."
    )
    risk = (
        "Without per-client rate limiting, a request-size cap and explicit timeouts, a burst of traffic "
        "(even an accidental one, a misbehaving client, or a retry storm) can exhaust connections, memory "
        "or worker slots faster than it otherwise would, degrading the service for everyone."
    )
    cmd = "grep -rniE 'rateLimit|maxRequestBodyBytes|buffering|respondingTimeouts|idleTimeout' /etc/traefik 2>/dev/null"
    files = _glob_read(patterns or TRAEFIK_PATTERNS)
    if not files:
        return skipped_check(
            "RES-001",
            CATEGORY,
            title,
            what,
            risk,
            cmd,
            "No Traefik dynamic configuration file found at any of: " + ", ".join(patterns or TRAEFIK_PATTERNS),
        )
    text = "\n".join(files.values())
    missing = []
    if not re.search(r"ratelimit\s*:", text, re.I):
        missing.append("rateLimit middleware")
    if not re.search(r"(maxrequestbodybytes|buffering)\s*:", text, re.I):
        missing.append("maxRequestBodyBytes / buffering limit")
    if not re.search(r"(respondingtimeouts|forwardingtimeouts|idletimeout|readtimeout|writetimeout)\s*:", text, re.I):
        missing.append("explicit responding/forwarding timeouts")

    if not missing:
        status, current = STATUS_PASS, f"Configured in {len(files)} file(s): {', '.join(sorted(files))}"
    elif len(missing) == 1:
        status, current = STATUS_WARNING, "Missing: " + ", ".join(missing)
    else:
        status, current = STATUS_CRITICAL, "Missing: " + ", ".join(missing)
    return make_check(
        "RES-001",
        CATEGORY,
        title,
        status,
        what,
        risk,
        cmd,
        current_value=current,
        recommended_value="A rateLimit middleware with a sane average/burst, maxRequestBodyBytes set, and "
        "explicit idle/read/write timeouts",
        details=[f"Scanned: {path}" for path in sorted(files)],
    )


def check_nginx_limits(patterns: Optional[List[str]] = None) -> dict:
    """RES-002: Nginx rate limiting, connection limiting, request-size and timeout configuration."""
    title = "Nginx rate limiting, request-size and timeout configuration"
    what = (
        "Parses Nginx configuration files for limit_req_zone/limit_conn_zone, client_max_body_size, and "
        "explicit client/keepalive timeouts."
    )
    risk = (
        "Without rate/connection limiting, a request-size cap and sane timeouts, a burst of traffic can "
        "exhaust worker connections or memory faster than it otherwise would."
    )
    cmd = (
        "grep -rniE 'limit_req_zone|limit_conn_zone|client_max_body_size|keepalive_timeout|"
        "client_(body|header)_timeout' /etc/nginx 2>/dev/null"
    )
    files = _glob_read(patterns or NGINX_PATTERNS)
    if not files:
        return skipped_check(
            "RES-002",
            CATEGORY,
            title,
            what,
            risk,
            cmd,
            "No Nginx configuration file found at any of: " + ", ".join(patterns or NGINX_PATTERNS),
        )
    text = "\n".join(files.values())
    missing = []
    if not re.search(r"\blimit_req_zone\b", text):
        missing.append("limit_req_zone (request rate limiting)")
    if not re.search(r"\blimit_conn_zone\b", text):
        missing.append("limit_conn_zone (connection limiting)")
    if not re.search(r"\bclient_max_body_size\b", text):
        missing.append("client_max_body_size (request-size cap)")
    if not re.search(r"\b(keepalive_timeout|client_body_timeout|client_header_timeout)\b", text):
        missing.append("explicit client/keepalive timeouts")

    if not missing:
        status, current = STATUS_PASS, f"Configured in {len(files)} file(s): {', '.join(sorted(files))}"
    elif len(missing) <= 2:
        status, current = STATUS_WARNING, "Missing: " + ", ".join(missing)
    else:
        status, current = STATUS_CRITICAL, "Missing: " + ", ".join(missing)
    return make_check(
        "RES-002",
        CATEGORY,
        title,
        status,
        what,
        risk,
        cmd,
        current_value=current,
        recommended_value="limit_req_zone and limit_conn_zone defined and applied, client_max_body_size set, "
        "explicit client/keepalive timeouts",
        details=[f"Scanned: {path}" for path in sorted(files)],
    )


#: key fragments that suggest a connection/request limit or timeout is configured somewhere in the file.
_STALWART_LIMIT_HINTS = ("timeout", "max-connections", "concurrency", "rate-limit", "ratelimit", "max-size")


def check_stalwart_limits(patterns: Optional[List[str]] = None) -> dict:
    """RES-003: Stalwart connection/request limit and timeout configuration (best effort)."""
    title = "Stalwart connection, request-size and timeout configuration (best effort)"
    what = (
        "Looks for timeout, connection-limit and rate-limit related keys in the Stalwart mail server "
        "configuration. Stalwart's exact schema can differ between versions, so this is a heuristic: a "
        "PASS here means related keys exist, not that every value has been checked - verify against "
        "Stalwart's own documentation for the deployed version."
    )
    risk = (
        "Without connection/request limits and timeouts on the mail server, a burst of connections (even "
        "an accidental one) can exhaust worker slots or memory faster than it otherwise would."
    )
    cmd = "grep -niE 'timeout|max-connections|concurrency|rate-limit' /opt/stalwart-mail/etc/config.toml 2>/dev/null"
    files = _glob_read(patterns or STALWART_PATTERNS)
    if not files:
        return skipped_check(
            "RES-003",
            CATEGORY,
            title,
            what,
            risk,
            cmd,
            "No Stalwart configuration file found at any of: " + ", ".join(patterns or STALWART_PATTERNS),
        )
    text = "\n".join(files.values()).lower()
    found = sorted({hint for hint in _STALWART_LIMIT_HINTS if hint in text})
    if not found:
        status = STATUS_WARNING
        current = "No timeout/connection-limit/rate-limit keys found; verify manually against Stalwart's docs"
    else:
        status = STATUS_INFO
        current = "Found related keys: " + ", ".join(found) + " (verify the actual values manually)"
    return make_check(
        "RES-003",
        CATEGORY,
        title,
        status,
        what,
        risk,
        cmd,
        current_value=current,
        recommended_value="Explicit timeouts and connection/request limits set and verified against documented defaults",
        details=[f"Scanned: {path}" for path in sorted(files)],
    )


def _parse_jail_files(patterns: List[str]) -> Tuple[configparser.ConfigParser, List[str]]:
    cp = configparser.ConfigParser(strict=False, allow_no_value=True, interpolation=None)
    read_files: List[str] = []
    for pattern in patterns:
        for path in sorted(glob.glob(pattern)):
            if not os.path.isfile(path) or path in read_files:
                continue
            try:
                cp.read(path, encoding="utf-8")
                read_files.append(path)
            except configparser.Error as exc:
                logger.warning("Could not parse fail2ban file %s: %s", path, exc)
    return cp, read_files


def check_fail2ban_scoping(patterns: Optional[List[str]] = None) -> dict:
    """RES-004: fail2ban/CrowdSec jails are active, cover the exposed services, and have sane thresholds."""
    title = "fail2ban/CrowdSec jail scoping and ban thresholds"
    what = (
        "Checks that fail2ban jails (or the equivalent CrowdSec bouncers) exist and are enabled for SSH, "
        "mail/SMTP and web authentication, and that maxretry is not absurdly high."
    )
    risk = (
        "An intrusion-prevention tool that is installed but not scoped to the services actually exposed "
        "(or with a ban threshold so high it never triggers) gives a false sense of protection."
    )
    cmd = "fail2ban-client status; grep -A5 '^\\[sshd\\]' /etc/fail2ban/jail.local"
    env = detect_environment()
    cp, read_files = _parse_jail_files(patterns or (FAIL2BAN_PATTERNS))
    if not read_files:
        reason = (
            "fail2ban/CrowdSec is active but no jail configuration file was found at the usual paths"
            if (env.fail2ban or env.crowdsec)
            else "fail2ban/CrowdSec does not appear to be active, and no jail configuration file was found"
        )
        return skipped_check("RES-004", CATEGORY, title, what, risk, cmd, reason)

    sections = {name.lower(): dict(cp.items(name)) for name in cp.sections()}

    def _enabled(data: Dict[str, str]) -> bool:
        return data.get("enabled", "true").strip().lower() not in ("false", "0", "no")

    covered: List[str] = []
    uncovered: List[str] = []
    notes: List[str] = []
    for area, candidates in EXPECTED_JAILS.items():
        match = next((c for c in candidates if c in sections and _enabled(sections[c])), None)
        if not match:
            uncovered.append(area)
            continue
        covered.append(f"{area} ({match})")
        data = sections[match]
        try:
            maxretry = int(data.get("maxretry", "5"))
        except ValueError:
            maxretry = None
        if maxretry is not None and maxretry > 20:
            notes.append(f"{area} ({match}): maxretry={maxretry} is unusually high; bans will rarely trigger")
        bantime = data.get("bantime", "").strip()
        if bantime not in ("", "-1") and bantime.lstrip("-").isdigit() and int(bantime) < 60:
            notes.append(f"{area} ({match}): bantime={bantime}s is very short")

    if uncovered:
        status = STATUS_CRITICAL if not covered else STATUS_WARNING
        current = "Not scoped for: " + ", ".join(uncovered)
        if covered:
            current += ". Covered: " + ", ".join(covered)
    elif notes:
        status, current = STATUS_WARNING, "; ".join(notes)
    else:
        status, current = STATUS_PASS, "Scoped and enabled for: " + ", ".join(covered)

    return make_check(
        "RES-004",
        CATEGORY,
        title,
        status,
        what,
        risk,
        cmd,
        current_value=current,
        recommended_value="An enabled, correctly-named jail per exposed service, with maxretry in a sane "
        "range (roughly 3-10) and a non-trivial bantime",
        details=(notes or []) + [f"Scanned: {path}" for path in sorted(read_files)],
    )


def run_checks() -> List[dict]:
    """Run every resilience/availability configuration review."""
    checks: List[dict] = []
    # (check_id, function) pairs - the id is explicit here rather than derived from the function's own name,
    # so a test (or anything else) that swaps in a differently-named callable still gets a correct id.
    for check_id, func in (
        ("RES-001", check_traefik_limits),
        ("RES-002", check_nginx_limits),
        ("RES-003", check_stalwart_limits),
        ("RES-004", check_fail2ban_scoping),
    ):
        try:
            checks.append(func())
        except Exception as exc:
            logger.exception("%s failed", check_id)
            checks.append(
                skipped_check(
                    check_id,
                    CATEGORY,
                    func.__doc__.strip() if func.__doc__ else check_id,
                    "An internal error occurred while evaluating this check.",
                    "The check could not be completed due to an unexpected error.",
                    check_id,
                    f"Unexpected error: {exc}",
                )
            )
    return checks
