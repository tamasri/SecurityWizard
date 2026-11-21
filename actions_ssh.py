import glob
import logging
import os
import re

from common import read_text

logger = logging.getLogger("securitywizard")


def _find_authorized_keys():
    """Check for valid public keys in /root and /home. Returns True if any valid key found."""
    key_prefixes = (
        "ssh-rsa",
        "ssh-ed25519",
        "ecdsa-sha2-",
        "sk-ssh-ed25519@openssh.com",
    )
    key_files = ["/root/.ssh/authorized_keys"]
    try:
        for home in glob.glob("/home/*"):
            key_files.append(os.path.join(home, ".ssh", "authorized_keys"))
    except Exception:  # nosec B110
        pass
    for kf in key_files:
        try:
            content = read_text(kf, default="")
        except Exception:  # nosec B112
            continue
        if not content:
            continue
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            # Strip options before key type
            if " " in stripped:
                parts = stripped.split(None, 1)
                candidate = parts[1] if len(parts) > 1 else stripped
            else:
                candidate = stripped
            for prefix in key_prefixes:
                if candidate.startswith(prefix):
                    return True
    return False


def _rewrite_sshd_config(keyword, value):
    """
    Rewrite /etc/ssh/sshd_config and drop-in files for a given keyword.
    Returns list of file_changes dicts.
    """
    file_changes = []
    main_path = "/etc/ssh/sshd_config"
    main_content = read_text(main_path, default="")

    # Comment out existing keyword lines
    pattern = re.compile(r"^(\s*)" + re.escape(keyword) + r"\b", re.MULTILINE)
    new_lines = []
    for line in main_content.splitlines():
        if pattern.match(line):
            new_lines.append("# " + line)
        else:
            new_lines.append(line)
    # Insert new line before first Match block
    new_line = f"{keyword} {value}"
    inserted = False
    for i, line in enumerate(new_lines):
        if line.strip().lower().startswith("match"):
            new_lines.insert(i, new_line)
            inserted = True
            break
    if not inserted:
        new_lines.append(new_line)
    new_main_content = "\n".join(new_lines) + "\n"
    file_changes.append({"path": main_path, "new_content": new_main_content})

    # Drop-in files
    try:
        dropins = sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf"))
    except Exception:
        dropins = []
    for dp in dropins:
        dp_content = read_text(dp, default="")
        dp_new_lines = []
        for line in dp_content.splitlines():
            if pattern.match(line):
                dp_new_lines.append("# " + line)
            else:
                dp_new_lines.append(line)
        dp_new_content = "\n".join(dp_new_lines) + "\n" if dp_new_lines else ""
        file_changes.append({"path": dp, "new_content": dp_new_content})

    return file_changes


def _build_ssh_plan(keyword, value, lockout_check=False, lockout_value="no"):
    """Common builder for SSH actions."""
    try:
        file_changes = _rewrite_sshd_config(keyword, value)
        warnings = ["Keep your current SSH session open and test a second login before closing."]
        blockers = []
        if lockout_check and value == lockout_value:
            if not _find_authorized_keys():
                blockers.append(
                    "No valid SSH public key found in /root/.ssh/authorized_keys or /home/*/.ssh/authorized_keys. "
                    "Refusing to lock out password authentication to avoid losing access."
                )
        return {
            "file_changes": file_changes,
            "perm_changes": [],
            "validate_commands": [["sshd", "-t"]],
            "commands": [["systemctl", "reload", "ssh"]],
            "inverse_commands": [["systemctl", "reload", "ssh"]],
            "warnings": warnings,
            "blockers": blockers,
            "risky_remote": True,
            "precondition": lambda: _ssh_precondition(keyword, value, lockout_check, lockout_value),
        }
    except Exception as e:
        logger.exception("Error building SSH plan for %s %s", keyword, value)
        return {
            "file_changes": [],
            "perm_changes": [],
            "validate_commands": [["sshd", "-t"]],
            "commands": [["systemctl", "reload", "ssh"]],
            "inverse_commands": [["systemctl", "reload", "ssh"]],
            "warnings": [],
            "blockers": [f"Error building plan: {e}"],
            "risky_remote": True,
            "precondition": lambda: _ssh_precondition(keyword, value, lockout_check, lockout_value),
        }


def _ssh_precondition(keyword, value, lockout_check, lockout_value):
    """
    Precondition check for SSH actions.
    Returns a list of blocker strings. Empty list means safe to apply.
    """
    blockers = []
    if lockout_check and value == lockout_value:
        if not _find_authorized_keys():
            blockers.append(
                "No valid SSH public key found in /root/.ssh/authorized_keys or /home/*/.ssh/authorized_keys. "
                "Refusing to lock out password authentication to avoid losing access."
            )
    return blockers


ACTIONS = {
    "ssh_permit_root_login": {
        "title": "Restrict Root SSH Login",
        "description": "Changes PermitRootLogin to prohibit-password so root can only log in with a public key, not a password. This is safe as long as at least one valid public key exists.",
        "build_plan": lambda: _build_ssh_plan(
            "PermitRootLogin", "prohibit-password", lockout_check=True, lockout_value="prohibit-password"
        ),
    },
    "ssh_password_auth": {
        "title": "Disable SSH Password Authentication",
        "description": "Sets PasswordAuthentication to no, forcing key-based authentication only. Safe if a valid public key is already installed.",
        "build_plan": lambda: _build_ssh_plan("PasswordAuthentication", "no", lockout_check=True, lockout_value="no"),
    },
    "ssh_pubkey_auth": {
        "title": "Enable SSH Public Key Authentication",
        "description": "Ensures PubkeyAuthentication is set to yes so key-based logins work. No lockout risk.",
        "build_plan": lambda: _build_ssh_plan("PubkeyAuthentication", "yes"),
    },
    "ssh_max_auth_tries": {
        "title": "Limit SSH Authentication Attempts",
        "description": "Sets MaxAuthTries to 3 to reduce brute-force exposure. Safe change.",
        "build_plan": lambda: _build_ssh_plan("MaxAuthTries", "3"),
    },
    "ssh_empty_passwords": {
        "title": "Disallow Empty SSH Passwords",
        "description": "Sets PermitEmptyPasswords to no so accounts without a password cannot log in via SSH. Safe change.",
        "build_plan": lambda: _build_ssh_plan("PermitEmptyPasswords", "no"),
    },
    "ssh_x11_forwarding": {
        "title": "Disable SSH X11 Forwarding",
        "description": "Sets X11Forwarding to no to reduce attack surface from X11 connections. Safe change.",
        "build_plan": lambda: _build_ssh_plan("X11Forwarding", "no"),
    },
}
