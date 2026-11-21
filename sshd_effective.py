"""Effective SSH configuration via sshd -T with Match evaluation."""

import logging
from typing import Any, Dict, List, Optional

from common import read_text, run_cmd

logger = logging.getLogger("securitywizard")

SSHD_CONFIG = "/etc/ssh/sshd_config"
SSHD_DROPIN_DIR = "/etc/ssh/sshd_config.d"

# Deprecated algorithms to check for
DEPRECATED_CIPHERS = {"3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "arcfour", "arcfour128", "arcfour256"}
DEPRECATED_MACS = {"hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96"}
DEPRECATED_KEX = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"}


def listening_ssh_ports() -> List[int]:
    """Get SSH ports from ss output and sshd -T."""
    ports = set()
    # From ss
    res = run_cmd(["ss", "-tlnpH"])
    if res.returncode == 0:
        for line in res.stdout.splitlines():
            if "sshd" in line:
                # Format: tcp LISTEN 0 128 0.0.0.0:22 users:(("sshd",pid=1234,fd=3))
                parts = line.split()
                if len(parts) >= 4:
                    addr_port = parts[3]
                    if ":" in addr_port:
                        try:
                            port = int(addr_port.rsplit(":", 1)[1])
                            ports.add(port)
                        except ValueError:
                            pass
    # From sshd -T
    res = run_cmd(["sshd", "-T"])
    if res.returncode == 0:
        for line in res.stdout.splitlines():
            line = line.strip()
            if line.lower().startswith("port "):
                try:
                    port = int(line.split(None, 1)[1])
                    ports.add(port)
                except (ValueError, IndexError):
                    pass
    return sorted(ports)


def effective_config(
    port: Optional[int] = None, user: Optional[str] = None, addr: Optional[str] = None, host: Optional[str] = None
) -> Dict[str, Any]:
    """Get effective sshd config via sshd -T with Match evaluation."""
    args = ["sshd", "-T"]
    if port is not None:
        args.extend(["-C", f"lport={port}"])
    if user is not None:
        args.extend(["-C", f"user={user}"])
    if addr is not None:
        args.extend(["-C", f"addr={addr}"])
    if host is not None:
        args.extend(["-C", f"host={host}"])

    res = run_cmd(args)
    if res.returncode != 0:
        return {"error": res.stderr.strip() or "sshd -T failed", "config": {}}

    config = {}
    for line in res.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            key = parts[0].lower()
            val = parts[1].strip()
            # Multi-value keys: ciphers, macs, kexalgorithms, etc.
            if key in ("ciphers", "macs", "kexalgorithms", "hostkeyalgorithms"):
                config[key] = [v.strip() for v in val.split(",")]
            else:
                config[key] = val
    return {"error": None, "config": config}


def parse_match_blocks() -> List[Dict[str, str]]:
    """Parse Match blocks from on-disk config."""
    matches = []
    current = None

    def _process_file(path: str):
        nonlocal current
        content = read_text(path)
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower().startswith("match "):
                current = {"conditions": line[6:].strip()}
                matches.append(current)
            elif current is not None:
                # End of match block when we hit a non-Match directive at top level
                # For simplicity, assume Match blocks are contiguous
                pass

    _process_file(SSHD_CONFIG)
    return matches


def _is_deprecated(algo: str, deprecated_set: set) -> bool:
    """Check if algorithm is in deprecated set."""
    return algo.lower() in deprecated_set


def evaluate_ssh_security(port: Optional[int] = None, user: Optional[str] = None) -> Dict[str, Any]:
    """Evaluate SSH security for given port/user."""
    result = effective_config(port=port, user=user)
    if result["error"]:
        return {"status": "SKIPPED", "reason": result["error"], "config": {}}

    config = result["config"]
    findings = []

    # PermitRootLogin
    root_login = config.get("permitrootlogin", "prohibit-password")
    if root_login == "yes":
        findings.append(
            {
                "check": "PermitRootLogin",
                "value": root_login,
                "status": "CRITICAL",
                "detail": f"Root login allowed on port {port}",
            }
        )
    elif root_login == "prohibit-password":
        findings.append(
            {
                "check": "PermitRootLogin",
                "value": root_login,
                "status": "PASS",
                "detail": f"Root login key-only on port {port}",
            }
        )
    else:
        findings.append(
            {
                "check": "PermitRootLogin",
                "value": root_login,
                "status": "PASS",
                "detail": f"Root login disabled on port {port}",
            }
        )

    # PasswordAuthentication
    passwd_auth = config.get("passwordauthentication", "yes")
    if passwd_auth == "yes":
        findings.append(
            {
                "check": "PasswordAuthentication",
                "value": passwd_auth,
                "status": "WARNING",
                "detail": f"Password auth enabled on port {port}",
            }
        )
    else:
        findings.append(
            {
                "check": "PasswordAuthentication",
                "value": passwd_auth,
                "status": "PASS",
                "detail": f"Password auth disabled on port {port}",
            }
        )

    # KbdInteractiveAuthentication
    kbd_interactive = config.get("kbdinteractiveauthentication", "yes")
    if kbd_interactive == "yes":
        findings.append(
            {
                "check": "KbdInteractiveAuthentication",
                "value": kbd_interactive,
                "status": "INFO",
                "detail": f"Keyboard-interactive auth enabled on port {port}",
            }
        )
    else:
        findings.append(
            {
                "check": "KbdInteractiveAuthentication",
                "value": kbd_interactive,
                "status": "PASS",
                "detail": f"Keyboard-interactive auth disabled on port {port}",
            }
        )

    # PubkeyAuthentication
    pubkey_auth = config.get("pubkeyauthentication", "yes")
    if pubkey_auth == "no":
        findings.append(
            {
                "check": "PubkeyAuthentication",
                "value": pubkey_auth,
                "status": "CRITICAL",
                "detail": f"Pubkey auth disabled on port {port}",
            }
        )
    else:
        findings.append(
            {
                "check": "PubkeyAuthentication",
                "value": pubkey_auth,
                "status": "PASS",
                "detail": f"Pubkey auth enabled on port {port}",
            }
        )

    # PermitEmptyPasswords
    empty_passwd = config.get("permitemptypasswords", "no")
    if empty_passwd == "yes":
        findings.append(
            {
                "check": "PermitEmptyPasswords",
                "value": empty_passwd,
                "status": "CRITICAL",
                "detail": f"Empty passwords allowed on port {port}",
            }
        )
    else:
        findings.append(
            {
                "check": "PermitEmptyPasswords",
                "value": empty_passwd,
                "status": "PASS",
                "detail": f"Empty passwords disabled on port {port}",
            }
        )

    # X11Forwarding
    x11 = config.get("x11forwarding", "yes")
    if x11 == "yes":
        findings.append(
            {
                "check": "X11Forwarding",
                "value": x11,
                "status": "WARNING",
                "detail": f"X11 forwarding enabled on port {port}",
            }
        )
    else:
        findings.append(
            {
                "check": "X11Forwarding",
                "value": x11,
                "status": "PASS",
                "detail": f"X11 forwarding disabled on port {port}",
            }
        )

    # MaxAuthTries
    max_tries = config.get("maxauthtries", "6")
    try:
        max_tries_int = int(max_tries)
        if max_tries_int > 3:
            findings.append(
                {
                    "check": "MaxAuthTries",
                    "value": max_tries,
                    "status": "WARNING",
                    "detail": f"MaxAuthTries={max_tries_int} on port {port}",
                }
            )
        else:
            findings.append(
                {
                    "check": "MaxAuthTries",
                    "value": max_tries,
                    "status": "PASS",
                    "detail": f"MaxAuthTries={max_tries_int} on port {port}",
                }
            )
    except ValueError:
        findings.append(
            {
                "check": "MaxAuthTries",
                "value": max_tries,
                "status": "INFO",
                "detail": f"MaxAuthTries={max_tries} on port {port}",
            }
        )

    # AllowUsers/AllowGroups
    allow_users = config.get("allowusers", "")
    allow_groups = config.get("allowgroups", "")
    if allow_users:
        findings.append(
            {
                "check": "AllowUsers",
                "value": allow_users,
                "status": "PASS",
                "detail": f"AllowUsers configured on port {port}",
            }
        )
    if allow_groups:
        findings.append(
            {
                "check": "AllowGroups",
                "value": allow_groups,
                "status": "PASS",
                "detail": f"AllowGroups configured on port {port}",
            }
        )
    if not allow_users and not allow_groups:
        findings.append(
            {
                "check": "AllowUsers/AllowGroups",
                "value": "",
                "status": "INFO",
                "detail": "No AllowUsers or AllowGroups configured",
            }
        )

    # Weak ciphers/MACs/KEX
    ciphers = config.get("ciphers", [])
    macs = config.get("macs", [])
    kex = config.get("kexalgorithms", [])

    weak_ciphers = [c for c in ciphers if _is_deprecated(c, DEPRECATED_CIPHERS)]
    weak_macs = [m for m in macs if _is_deprecated(m, DEPRECATED_MACS)]
    weak_kex = [k for k in kex if _is_deprecated(k, DEPRECATED_KEX)]

    if weak_ciphers:
        findings.append(
            {
                "check": "WeakCiphers",
                "value": ", ".join(weak_ciphers),
                "status": "WARNING",
                "detail": f"Weak ciphers on port {port}: {', '.join(weak_ciphers)}",
            }
        )
    if weak_macs:
        findings.append(
            {
                "check": "WeakMACs",
                "value": ", ".join(weak_macs),
                "status": "WARNING",
                "detail": f"Weak MACs on port {port}: {', '.join(weak_macs)}",
            }
        )
    if weak_kex:
        findings.append(
            {
                "check": "WeakKEX",
                "value": ", ".join(weak_kex),
                "status": "WARNING",
                "detail": f"Weak KEX on port {port}: {', '.join(weak_kex)}",
            }
        )

    return {"status": "OK", "config": config, "findings": findings, "port": port, "user": user}
