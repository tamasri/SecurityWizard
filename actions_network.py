"""
actions_network.py - SecurityWizard network hardening actions.

Provides the ACTIONS dict for the remediator engine:
  * ufw_baseline         - enable UFW with sensible defaults, always keeping SSH reachable.
  * docker_user_isolation - insert a DOCKER-USER chain into /etc/ufw/after.rules so that
                           published container ports are not exposed to the internet by default.

build_plan() only READS the system.  It never raises; on any unexpected error it returns a
plan with a non-empty "blockers" list so the anti-lockout guard can refuse the apply.
"""

from __future__ import annotations

import os
import re
from common import read_text, run_cmd

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _detect_ssh_ports() -> list[int]:
    """Return a list of TCP ports that sshd listens on.  Falls back to [22]."""
    ports: set[int] = set()
    # 1) /etc/ssh/sshd_config  (Port directive)
    cfg = read_text("/etc/ssh/sshd_config")
    for line in cfg.splitlines():
        line = line.strip()
        if line.startswith("Port "):
            try:
                ports.add(int(line.split(None, 1)[1].strip()))
            except (ValueError, IndexError):
                pass
    # 2) live listeners via ss -tlnp
    rc, out, _ = run_cmd(["ss", "-tlnp"])
    if rc == 0:
        for line in out.splitlines():
            if ":22 " in line or ":22\t" in line or line.strip().startswith("LISTEN") and ":22" in line:
                m = re.search(r":(\d+)\s", line)
                if m:
                    try:
                        ports.add(int(m.group(1)))
                    except ValueError:
                        pass
                break  # first match is enough for the common case
    if not ports:
        ports.add(22)
    return sorted(ports)


def _ufw_installed() -> bool:
    rc, _, _ = run_cmd(["which", "ufw"])
    return rc == 0


def _docker_installed() -> bool:
    rc, _, _ = run_cmd(["which", "docker"])
    return rc == 0


def _current_after_rules() -> str:
    return read_text("/etc/ufw/after.rules")


def _current_default_ufw() -> str:
    return read_text("/etc/default/ufw")


def _current_user_rules() -> str:
    return read_text("/etc/ufw/user.rules")


def _current_user6_rules() -> str:
    return read_text("/etc/ufw/user6.rules")


# ---------------------------------------------------------------------------
# ufw_baseline
# ---------------------------------------------------------------------------

def _build_ufw_baseline() -> dict:
    blockers: list[str] = []
    warnings: list[str] = []
    file_changes: list[dict] = []

    if not _ufw_installed():
        blockers.append("ufw is not installed on this system.")
        return {
            "file_changes": [],
            "perm_changes": [],
            "validate_commands": [],
            "commands": [],
            "inverse_commands": [["ufw", "reload"]],
            "warnings": warnings,
            "blockers": blockers,
        }

    ssh_ports = _detect_ssh_ports()
    if not ssh_ports:
        blockers.append("Could not determine the SSH port; refusing to enable UFW.")
        return {
            "file_changes": [],
            "perm_changes": [],
            "validate_commands": [],
            "commands": [],
            "inverse_commands": [["ufw", "reload"]],
            "warnings": warnings,
            "blockers": blockers,
        }

    # Snapshot the three UFW state files with their CURRENT (unchanged) content.
    # The remediator engine will back them up, and the inverse_commands will reload UFW.
    for path, reader in (
        ("/etc/default/ufw", _current_default_ufw),
        ("/etc/ufw/user.rules", _current_user_rules),
        ("/etc/ufw/user6.rules", _current_user6_rules),
    ):
        if os.path.exists(path):
            file_changes.append({"path": path, "new_content": reader()})

    commands: list[list[str]] = [
        ["ufw", "default", "deny", "incoming"],
        ["ufw", "default", "allow", "outgoing"],
    ]
    for port in ssh_ports:
        commands.append(["ufw", "allow", f"{port}/tcp"])
    commands.append(["ufw", "--force", "enable"])

    warnings.append(
        "Existing connections on ports other than SSH will be blocked once UFW is enabled. "
        "If you run other services (web, database, etc.), add allow rules for them afterwards."
    )

    return {
        "file_changes": file_changes,
        "perm_changes": [],
        "validate_commands": [["ufw", "status"]],
        "commands": commands,
        "inverse_commands": [["ufw", "reload"]],
        "warnings": warnings,
        "blockers": blockers,
    }


# ---------------------------------------------------------------------------
# docker_user_isolation
# ---------------------------------------------------------------------------

_BEGIN_MARKER = "# BEGIN SECURITYWIZARD DOCKER-USER"
_END_MARKER = "# END SECURITYWIZARD DOCKER-USER"

_DOCKER_USER_CHAIN = """\
*filter
# BEGIN SECURITYWIZARD DOCKER-USER
:DOCKER-USER - [0 0]
-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
-A DOCKER-USER -s 10.0.0.0/8 -j RETURN
-A DOCKER-USER -s 172.16.0.0/12 -j RETURN
-A DOCKER-USER -s 192.168.0.0/16 -j RETURN
-A DOCKER-USER -j ufw-user-forward
-A DOCKER-USER -m conntrack --ctstate NEW -j DROP
# END SECURITYWIZARD DOCKER-USER
COMMIT
"""


def _build_docker_user_isolation() -> dict:
    blockers: list[str] = []
    warnings: list[str] = []
    file_changes: list[dict] = []

    if not _docker_installed():
        blockers.append("docker is not installed on this system.")
    if not _ufw_installed():
        blockers.append("ufw is not installed on this system.")
    if blockers:
        return {
            "file_changes": [],
            "perm_changes": [],
            "validate_commands": [],
            "commands": [],
            "inverse_commands": [["ufw", "reload"]],
            "warnings": warnings,
            "blockers": blockers,
        }

    current = _current_after_rules()
    path = "/etc/ufw/after.rules"

    if not os.path.exists(path):
        # UFW is installed but after.rules is missing – create it with the chain.
        new_content = _DOCKER_USER_CHAIN
    else:
        # If the managed block already exists, replace it.
        if _BEGIN_MARKER in current and _END_MARKER in current:
            pattern = re.compile(
                re.escape(_BEGIN_MARKER) + r".*?" + re.escape(_END_MARKER),
                re.DOTALL,
            )
            new_content = pattern.sub(_DOCKER_USER_CHAIN.strip(), current)
        else:
            # Insert before the COMMIT line in the *filter section.
            lines = current.splitlines()
            insert_at = None
            in_filter = False
            for i, line in enumerate(lines):
                if line.strip() == "*filter":
                    in_filter = True
                    continue
                if in_filter and line.strip() == "COMMIT":
                    insert_at = i
                    break
            if insert_at is None:
                # No COMMIT found – append at the end.
                new_content = current.rstrip("\n") + "\n" + _DOCKER_USER_CHAIN.strip() + "\n"
            else:
                before = lines[:insert_at]
                after = lines[insert_at:]
                new_content = "\n".join(before) + "\n" + _DOCKER_USER_CHAIN.strip() + "\n" + "\n".join(after) + "\n"

    file_changes.append({"path": path, "new_content": new_content})

    warnings.append(
        "Published container ports become unreachable from the internet until you allow them "
        "with 'ufw route allow' or by adding a specific allow rule."
    )

    return {
        "file_changes": file_changes,
        "perm_changes": [],
        "validate_commands": [["ufw", "status"]],
        "commands": [["ufw", "reload"]],
        "inverse_commands": [["ufw", "reload"]],
        "warnings": warnings,
        "blockers": blockers,
    }


# ---------------------------------------------------------------------------
# public ACTIONS dict
# ---------------------------------------------------------------------------

ACTIONS: dict[str, dict] = {
    "ufw_baseline": {
        "title": "Enable UFW firewall with sensible defaults",
        "description": (
            "Enable Uncomplicated Firewall (UFW) with default-deny incoming and default-allow outgoing. "
            "SSH port(s) are always allowed first so you will not lock yourself out. "
            "Existing UFW state files are snapshotted for one-click rollback."
        ),
        "build_plan": _build_ufw_baseline,
    },
    "docker_user_isolation": {
        "title": "Isolate Docker published ports from the internet",
        "description": (
            "Insert a DOCKER-USER iptables chain into /etc/ufw/after.rules so that new connections "
            "from public interfaces to published container ports are dropped by default. "
            "Traffic from private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and already "
            "established connections are allowed.  After applying, use 'ufw route allow' to expose "
            "specific container ports to the internet."
        ),
        "build_plan": _build_docker_user_isolation,
    },
}
