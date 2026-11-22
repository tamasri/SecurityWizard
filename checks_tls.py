"""TLS and certificate auditing for the operator's own domains.

Every domain checked here must be listed under [pentest].targets in the configuration file (see
pentest_common.py); anything else is refused with a clear reason. Every probe is a single, read-only TLS
handshake (optionally pinned to one protocol version to see whether it is still accepted) - there is no
exploitation, no credential use, and no data beyond the certificate and the negotiated cipher is read.
"""

import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Callable, List, Optional, Tuple

from common import STATUS_CRITICAL, STATUS_PASS, STATUS_WARNING, make_check, skipped_check
from config import get_config
from pentest_common import audit_scan, check_target_allowed

logger = logging.getLogger("securitywizard")

CATEGORY = "tls"

#: (port, human label) pairs audited for every allowlisted domain.
DEFAULT_PORTS: List[Tuple[int, str]] = [(443, "HTTPS"), (465, "SMTPS/submission"), (993, "IMAPS")]

#: TLS versions that must no longer be accepted.
WEAK_VERSIONS: List[str] = ["TLSv1", "TLSv1.1"]
_VERSION_MAP = {"TLSv1": ssl.TLSVersion.TLSv1, "TLSv1.1": ssl.TLSVersion.TLSv1_1}

#: Substrings that mark a negotiated cipher suite as weak/export-grade/anonymous.
WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES-CBC", "EXPORT", "_NULL_", "MD5", "ADH", "AECDH", "PSK")

#: Recommended minimum HSTS max-age (not evaluated here; see checks_web.py, which owns header checks).

ConnectFn = Callable[[str, int, ssl.SSLContext, float], Tuple[Optional[dict], Optional[tuple], Optional[str]]]


def configured_domains() -> List[str]:
    """Domains from the [pentest] allowlist (host entries only; bare CIDR entries are for IP-based checks)."""
    return sorted({t.host for t in get_config().pentest_targets if t.host})


def _connect(host: str, port: int, ctx: ssl.SSLContext, timeout: float):
    """Real network probe: one TLS handshake, returning (peer certificate dict, cipher tuple, negotiated
    protocol version string). Kept separate from the probing functions so tests can inject a fake."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            return ssock.getpeercert(), ssock.cipher(), ssock.version()


def _probe_verified(host: str, port: int, timeout: float = 5.0, connect: Optional[ConnectFn] = None):
    """A normal handshake that validates the chain against the system trust store (for certificate checks)."""
    ctx = ssl.create_default_context()
    return (connect or _connect)(host, port, ctx, timeout)


def _probe_insecure(host: str, port: int, timeout: float = 5.0, connect: Optional[ConnectFn] = None):
    """A handshake that never fails on certificate problems, used only to read the negotiated cipher/version
    even when the chain itself is broken (that is reported separately by the certificate check)."""
    # Deliberate for this diagnostic probe, not a connection that sends or trusts anything: chain/hostname
    # validity is reported separately by check_certificate() (TLS-001). Disabling verification here is what
    # lets the cipher check still report something useful on a host whose certificate is already broken,
    # instead of failing with an unrelated SSL error.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False  # NOSONAR
    ctx.verify_mode = ssl.CERT_NONE  # NOSONAR
    return (connect or _connect)(host, port, ctx, timeout)


def probe_weak_version(
    host: str, port: int, label: str, timeout: float = 5.0, connect: Optional[ConnectFn] = None
) -> Optional[bool]:
    """True if the server completed a handshake pinned to exactly this (weak) version, False if it refused,
    None if this machine's OpenSSL build cannot even attempt the version (so nothing is proven either way)."""
    # Deliberate: this probe exists to isolate ONE variable (does the server still accept this legacy
    # protocol version at all), so a hostname/chain mismatch on the same certificate must not be allowed to
    # produce a false "refused" result for a reason that has nothing to do with the protocol version.
    # Nothing sent here is sensitive and no data from the connection is trusted.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False  # NOSONAR
    ctx.verify_mode = ssl.CERT_NONE  # NOSONAR
    try:
        ctx.minimum_version = _VERSION_MAP[label]
        ctx.maximum_version = _VERSION_MAP[label]
    except (ValueError, OSError):
        return None
    try:
        _cert, _cipher, negotiated = (connect or _connect)(host, port, ctx, timeout)
    except (ssl.SSLError, OSError, socket.timeout):
        return False
    return negotiated == label


def _parse_not_after(not_after: str) -> datetime:
    return datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def check_certificate(host: str, port: int, label: str, connect: Optional[ConnectFn] = None) -> dict:
    """TLS-001: certificate chain validity and days until expiry."""
    title = f"{host}:{port} ({label}) certificate expiry and chain validity"
    what = "Validates the certificate chain against the system trust store and reports days until expiry."
    risk = (
        "An expired certificate breaks TLS for every client; an invalid or self-signed chain lets an "
        "attacker intercept traffic without most clients noticing."
    )
    cmd = f"openssl s_client -connect {host}:{port} -servername {host} </dev/null 2>&1 | openssl x509 -noout -dates"
    target = f"{host}:{port}"

    try:
        cert, _cipher, _version = _probe_verified(host, port, connect=connect)
    except ssl.SSLCertVerificationError as exc:
        audit_scan("TLS-001", target, STATUS_CRITICAL, str(exc))
        return make_check(
            "TLS-001",
            CATEGORY,
            title,
            STATUS_CRITICAL,
            what,
            risk,
            cmd,
            current_value=f"Chain validation failed: {exc}",
            recommended_value="A certificate chain that validates against a public CA for this hostname",
            details=[str(exc)],
        )
    except (OSError, socket.timeout) as exc:
        audit_scan("TLS-001", target, "SKIPPED", str(exc))
        return skipped_check("TLS-001", CATEGORY, title, what, risk, cmd, f"Could not connect: {exc}")

    not_after = cert.get("notAfter") if cert else None
    if not not_after:
        audit_scan("TLS-001", target, STATUS_WARNING, "handshake succeeded but no certificate was returned")
        return make_check(
            "TLS-001",
            CATEGORY,
            title,
            STATUS_WARNING,
            what,
            risk,
            cmd,
            current_value="Handshake succeeded but no certificate details were returned",
            recommended_value="A certificate chain that validates against a public CA for this hostname",
        )

    expires_at = _parse_not_after(not_after)
    days = (expires_at - datetime.now(timezone.utc)).total_seconds() / 86400
    if days < 0:
        status = STATUS_CRITICAL
    elif days < 14:
        status = STATUS_CRITICAL
    elif days < 30:
        status = STATUS_WARNING
    else:
        status = STATUS_PASS
    current = f"Valid, expires in {days:.1f} day(s) ({expires_at.date().isoformat()})"
    audit_scan("TLS-001", target, status, current)
    return make_check(
        "TLS-001",
        CATEGORY,
        title,
        status,
        what,
        risk,
        cmd,
        current_value=current,
        recommended_value="Renew at least 30 days before expiry; chain validates against a public CA",
        details=[f"notAfter: {not_after}"],
    )


def check_weak_protocols(host: str, port: int, label: str, connect: Optional[ConnectFn] = None) -> dict:
    """TLS-002: whether TLSv1 or TLSv1.1 are still accepted."""
    title = f"{host}:{port} ({label}) weak TLS protocol versions (TLSv1, TLSv1.1)"
    what = "Attempts a handshake pinned to exactly TLSv1 and exactly TLSv1.1 and reports whether either is accepted."
    risk = (
        "TLSv1 and TLSv1.1 have known weaknesses and are deprecated by every major browser and by PCI-DSS; "
        "a client forced down to them is easier to intercept or downgrade further."
    )
    cmd = f"openssl s_client -connect {host}:{port} -servername {host} -tls1_1"
    target = f"{host}:{port}"

    offered = {}
    inconclusive = []
    for version in WEAK_VERSIONS:
        result = probe_weak_version(host, port, version, connect=connect)
        if result is None:
            inconclusive.append(version)
        else:
            offered[version] = result

    accepted = [v for v, ok in offered.items() if ok]
    if accepted:
        status = STATUS_CRITICAL
        current = "Still accepts: " + ", ".join(accepted)
    elif not offered:
        audit_scan("TLS-002", target, "SKIPPED", "local OpenSSL cannot attempt: " + ", ".join(inconclusive))
        return skipped_check(
            "TLS-002",
            CATEGORY,
            title,
            what,
            risk,
            cmd,
            "This machine's OpenSSL build cannot even attempt: " + ", ".join(inconclusive),
        )
    else:
        status = STATUS_PASS
        current = "Refused: " + ", ".join(sorted(offered))
        if inconclusive:
            current += "; could not test: " + ", ".join(inconclusive)

    audit_scan("TLS-002", target, status, current)
    return make_check(
        "TLS-002",
        CATEGORY,
        title,
        status,
        what,
        risk,
        cmd,
        current_value=current,
        recommended_value="TLSv1 and TLSv1.1 both refused; only TLSv1.2 and TLSv1.3 negotiated",
        details=[f"{v}: {'accepted' if ok else 'refused'}" for v, ok in offered.items()],
    )


def check_cipher(host: str, port: int, label: str, connect: Optional[ConnectFn] = None) -> dict:
    """TLS-003: strength of the cipher suite negotiated in a normal handshake."""
    title = f"{host}:{port} ({label}) negotiated cipher suite"
    what = "Reads the cipher suite negotiated in a normal TLS handshake and flags known-weak ciphers."
    risk = (
        "A weak or export-grade cipher (RC4, 3DES, anonymous/NULL ciphers, ...) can be broken or gives no "
        "real confidentiality even though the handshake succeeds."
    )
    cmd = f"openssl s_client -connect {host}:{port} -servername {host} </dev/null 2>&1 | grep Cipher"
    target = f"{host}:{port}"

    try:
        _cert, cipher, _version = _probe_insecure(host, port, connect=connect)
    except (OSError, socket.timeout) as exc:
        audit_scan("TLS-003", target, "SKIPPED", str(exc))
        return skipped_check("TLS-003", CATEGORY, title, what, risk, cmd, f"Could not connect: {exc}")

    cipher_name = cipher[0] if cipher else ""
    if not cipher_name:
        audit_scan("TLS-003", target, "SKIPPED", "no cipher reported")
        return skipped_check(
            "TLS-003", CATEGORY, title, what, risk, cmd, "Handshake succeeded but no cipher was reported"
        )

    weak = any(marker in cipher_name.upper() for marker in WEAK_CIPHER_MARKERS)
    status = STATUS_CRITICAL if weak else STATUS_PASS
    current = f"Negotiated: {cipher_name}"
    audit_scan("TLS-003", target, status, current)
    return make_check(
        "TLS-003",
        CATEGORY,
        title,
        status,
        what,
        risk,
        cmd,
        current_value=current,
        recommended_value="A modern AEAD cipher suite (AES-GCM, ChaCha20-Poly1305); no RC4/3DES/export/anonymous ciphers",
        details=[current],
    )


def run_checks() -> List[dict]:
    """Run the TLS audit for every domain in the [pentest] allowlist."""
    results: List[dict] = []
    domains = configured_domains()
    if not domains:
        results.append(
            skipped_check(
                "TLS-001",
                CATEGORY,
                "TLS/certificate audit",
                "Audits certificate validity, weak protocol support and cipher strength for configured domains.",
                "No domains configured means this server's TLS posture is not audited.",
                "openssl s_client -connect <domain>:443",
                "No domains configured under [pentest].targets; add hosts to securitywizard.toml to enable this check.",
            )
        )
        return results

    for host in domains:
        reason = check_target_allowed(host)
        if reason:
            for check_id in ("TLS-001", "TLS-002", "TLS-003"):
                audit_scan(check_id, host, "SKIPPED", reason)
            results.append(
                skipped_check(
                    "TLS-001",
                    CATEGORY,
                    f"{host}: TLS/certificate audit",
                    "Audits certificate validity, weak protocol support and cipher strength.",
                    "Could not evaluate this domain.",
                    f"openssl s_client -connect {host}:443",
                    reason,
                )
            )
            continue
        for port, label in DEFAULT_PORTS:
            for check_fn, check_id in (
                (check_certificate, "TLS-001"),
                (check_weak_protocols, "TLS-002"),
                (check_cipher, "TLS-003"),
            ):
                try:
                    results.append(check_fn(host, port, label))
                except Exception as exc:
                    logger.exception("%s failed for %s:%s", check_id, host, port)
                    audit_scan(check_id, f"{host}:{port}", "SKIPPED", str(exc))
                    results.append(
                        skipped_check(
                            check_id,
                            CATEGORY,
                            f"{host}:{port} ({label})",
                            "TLS audit.",
                            "Could not evaluate.",
                            f"openssl s_client -connect {host}:{port}",
                            f"Unexpected error: {exc}",
                        )
                    )
    return results
