import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("securitywizard")

# Regex for remediation IDs (e.g., NET-001)
REMEDIATION_ID_RE = re.compile(r"^[A-Z]{3}-\d{3}$")

# Regex for snapshot IDs (e.g., SNAP-abc12345)
SNAPSHOT_ID_RE = re.compile(r"^SNAP-[a-zA-Z0-9]{8,32}$")

# Allowed hosts for Origin/Referer validation
ALLOWED_HOSTS: List[str] = []

# Rate limiting configuration
RATE_LIMITS: Dict[str, Tuple[int, int]] = {
    "login": (5, 60),  # 5 attempts per 60 seconds
    "apply": (10, 60),  # 10 applies per 60 seconds
    "rollback": (10, 60),  # 10 rollbacks per 60 seconds
}

# In-memory rate limit storage: {endpoint: {client_ip: [timestamps]}}
_rate_limits: Dict[str, Dict[str, List[float]]] = {
    "login": {},
    "apply": {},
    "rollback": {},
}
_rate_limit_lock = threading.Lock()

# Audit log path
_audit_log_path: Optional[str] = None
_audit_log_lock = threading.Lock()


def init() -> None:
    """Initialize security settings from environment."""
    global ALLOWED_HOSTS, _audit_log_path

    # Parse allowed hosts from environment
    hosts_env = os.environ.get("SECURITYWIZARD_ALLOWED_HOSTS", "")
    if hosts_env:
        ALLOWED_HOSTS = [h.strip() for h in hosts_env.split(",") if h.strip()]
    else:
        ALLOWED_HOSTS = []

    # Set audit log path
    _audit_log_path = os.environ.get(
        "SECURITYWIZARD_AUDIT_LOG",
        os.path.join(os.environ.get("SECURITYWIZARD_BACKUP_DIR", "/var/backups/securitywizard"), "audit.log"),
    )

    logger.info("Security module initialized. Allowed hosts: %s", ALLOWED_HOSTS)


def is_readonly() -> bool:
    """Check if read-only mode is enabled."""
    return os.environ.get("SECURITYWIZARD_READONLY", "0") == "1"


def validate_remediation_id(rid: str) -> bool:
    """Validate remediation ID format."""
    return bool(REMEDIATION_ID_RE.match(rid))


def validate_snapshot_id(sid: str) -> bool:
    """Validate snapshot ID format."""
    return bool(SNAPSHOT_ID_RE.match(sid))


def check_origin_allowed(request) -> bool:
    """Check if the Origin or Referer header matches an allowed host.

    Returns True if no Origin/Referer header is present (non-browser request)
    or if the host matches an allowed host.
    """
    origin = request.headers.get("origin", "")
    referer = request.headers.get("referer", "")

    # If no Origin/Referer, allow (non-browser request)
    if not origin and not referer:
        return True

    # Extract host from Origin or Referer
    if origin:
        try:
            host = origin.split("://", 1)[1].split("/", 1)[0]
        except (IndexError, ValueError):
            logger.warning("Invalid Origin header: %s", origin)
            return False
    elif referer:
        try:
            host = referer.split("://", 1)[1].split("/", 1)[0]
        except (IndexError, ValueError):
            logger.warning("Invalid Referer header: %s", referer)
            return False
    else:
        return True

    # Check if host is in allowed list
    if not ALLOWED_HOSTS:
        # No allowed hosts configured, allow all
        return True

    return host in ALLOWED_HOSTS


def check_rate_limit(endpoint: str, client_ip: str) -> bool:
    """Check if the client is rate limited.

    Returns True if the client can proceed, False if rate limited.
    """
    if endpoint not in RATE_LIMITS:
        return True

    max_requests, window = RATE_LIMITS[endpoint]
    now = time.time()

    with _rate_limit_lock:
        if client_ip not in _rate_limits[endpoint]:
            _rate_limits[endpoint][client_ip] = []

        # Remove old timestamps outside the window
        cutoff = now - window
        _rate_limits[endpoint][client_ip] = [t for t in _rate_limits[endpoint][client_ip] if t > cutoff]

        # Check if limit exceeded
        if len(_rate_limits[endpoint][client_ip]) >= max_requests:
            return False

        # Add current timestamp
        _rate_limits[endpoint][client_ip].append(now)
        return True


def audit_log(
    action: str, client_ip: str, remediation_id: Optional[str] = None, result: str = "success", **extra
) -> None:
    """Write an audit log entry as JSON lines.

    Never logs secrets (passwords, tokens).
    """
    if not _audit_log_path:
        return

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "client": client_ip,
        "action": action,
        "remediation_id": remediation_id,
        "result": result,
    }

    # Add extra fields but filter out secrets
    for key, value in extra.items():
        if key.lower() not in ("password", "token", "secret"):
            entry[key] = value

    try:
        with _audit_log_lock:
            with open(_audit_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
    except Exception as exc:
        logger.error("Failed to write audit log: %s", exc)


def get_security_headers() -> Dict[str, str]:
    """Return security headers to add to every response."""
    return {
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
    }


def get_cache_headers() -> Dict[str, str]:
    """Return cache headers for API responses."""
    return {
        "Cache-Control": "no-store",
    }
