import base64
import hashlib
import logging
import os
from typing import List, Optional, Tuple

from common import (
    STATUS_PASS, STATUS_WARNING, STATUS_CRITICAL, STATUS_INFO, STATUS_SKIPPED,
    make_check, skipped_check,
)
from sudoers_parse import parse_sudoers_paths, classify_rule, SudoRule

logger = logging.getLogger(__name__)

CATEGORY = "access"
AUTHORIZED_KEYS_PATHS = {
    "root": "/root/.ssh/authorized_keys",
}
GROUP_FILE = "/etc/group"
SUDOERS_PATHS = ["/etc/sudoers", "/etc/sudoers.d"]

EXPECTED_DOCKER_USERS = {"root"}


def _parse_key_line(line: str) -> Optional[Tuple[str, str, str, str]]:
    """Parse an authorized_keys line. Returns (key_type, bits_str, fingerprint, comment) or None."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split(None, 3)
    if len(parts) < 2:
        return None
    options_str = ""
    if parts[0].endswith("=") or "," in parts[0]:
        options_str = parts[0]
        parts = parts[1:]
        if len(parts) < 2:
            return None
    key_type = parts[0]
    key_blob_b64 = parts[1]
    comment = parts[2] if len(parts) > 2 else ""
    try:
        key_blob = base64.b64decode(key_blob_b64)
    except Exception:
        key_blob = b""
    fingerprint = hashlib.sha256(key_blob).digest().hex()
    bits_str = _derive_bits(key_type, key_blob)
    return (key_type, bits_str, fingerprint, comment)


def _derive_bits(key_type: str, blob: bytes) -> str:
    if key_type == "ssh-rsa":
        try:
            pos = 0
            length = int.from_bytes(blob[pos:pos+4], 'big')
            pos += 4
            e_len = int.from_bytes(blob[pos:pos+4], 'big')
            pos += 4 + e_len
            n_len = int.from_bytes(blob[pos:pos+4], 'big')
            bits = n_len * 8
            return str(bits)
        except Exception:
            return "unknown"
    elif key_type == "ssh-dss":
        return "1024"
    elif key_type == "ecdsa-sha2-nistp256":
        return "256"
    elif key_type == "ecdsa-sha2-nistp384":
        return "384"
    elif key_type == "ecdsa-sha2-nistp521":
        return "521"
    elif key_type == "ssh-ed25519":
        return "256"
    return "unknown"


def _parse_options(options_str: str) -> List[str]:
    """Parse SSH authorized_keys options into a list of restriction names."""
    restrictions = []
    if not options_str:
        return restrictions
    # Split by commas, respecting quotes
    current = ""
    in_quotes = False
    for ch in options_str:
        if ch == '"':
            in_quotes = not in_quotes
            current += ch
        elif ch == ',' and not in_quotes:
            restrictions.append(current.strip())
            current = ""
        else:
            current += ch
    if current.strip():
        restrictions.append(current.strip())
    return restrictions


def _check_authorized_keys(root_authorized_keys: str, users_authorized_keys: dict) -> List[dict]:
    results = []
    # Check root
    root_lines = root_authorized_keys.strip().splitlines()
    root_unrestricted = 0
    root_warnings = 0
    root_info = 0
    for line in root_lines:
        parsed = _parse_key_line(line)
        if parsed is None:
            continue
        key_type, bits, fingerprint, comment = parsed
        restrictions = _parse_options(line.split(None, 3)[0] if (line.split(None, 3)[0].endswith("=") or "," in line.split(None, 3)[0]) else "")
        has_restriction = bool(restrictions)
        is_forced_command = any(r.startswith("command=") for r in restrictions)
        
        if key_type == "ssh-dss" or (bits.isdigit() and int(bits) < 3072 and key_type == "ssh-rsa"):
            status = STATUS_WARNING
            risk = "Weak key type or small key size for root."
        elif has_restriction and is_forced_command:
            status = STATUS_INFO
            risk = "Restricted forced-command key (deploy key)."
        elif not has_restriction:
            status = STATUS_WARNING
            risk = "Unrestricted SSH key for root."
        else:
            status = STATUS_INFO
            risk = "Restricted SSH key for root."
        
        results.append(make_check(
            id="ACC-001",
            category=CATEGORY,
            title="Root authorized_keys: {}".format(comment or fingerprint[:16]),
            status=status,
            what_it_checks="SSH authorized_keys entry for root.",
            risk=risk,
            command="cat /root/.ssh/authorized_keys",
            current_value="type={}, bits={}, fingerprint={}, restrictions={}".format(key_type, bits, fingerprint[:32], restrictions),
            recommended_value="Use ed25519 or RSA >= 3072 bits with restrictions." if status != STATUS_PASS else "",
            details=[f"Comment: {comment}", f"Key type: {key_type}", f"Bits: {bits}", f"Fingerprint: {fingerprint}", f"Restrictions: {restrictions}"],
        ))
    
    # Check other users
    for user, content in users_authorized_keys.items():
        if user == "root":
            continue
        lines = content.strip().splitlines()
        for line in lines:
            parsed = _parse_key_line(line)
            if parsed is None:
                continue
            key_type, bits, fingerprint, comment = parsed
            restrictions = _parse_options(line.split(None, 3)[0] if (line.split(None, 3)[0].endswith("=") or "," in line.split(None, 3)[0]) else "")
            has_restriction = bool(restrictions)
            is_forced_command = any(r.startswith("command=") for r in restrictions)
            
            if key_type == "ssh-dss" or (bits.isdigit() and int(bits) < 3072 and key_type == "ssh-rsa"):
                status = STATUS_WARNING
                risk = "Weak key type or small key size for user {}.".format(user)
            elif has_restriction and is_forced_command:
                status = STATUS_INFO
                risk = "Restricted forced-command key for user {} (deploy key).".format(user)
            elif not has_restriction:
                status = STATUS_WARNING
                risk = "Unrestricted SSH key for user {}.".format(user)
            else:
                status = STATUS_INFO
                risk = "Restricted SSH key for user {}.".format(user)
            
            results.append(make_check(
                id="ACC-001",
                category=CATEGORY,
                title="User {} authorized_keys: {}".format(user, comment or fingerprint[:16]),
                status=status,
                what_it_checks="SSH authorized_keys entry for user {}.".format(user),
                risk=risk,
                command="cat /home/{}/.ssh/authorized_keys".format(user),
                current_value="type={}, bits={}, fingerprint={}, restrictions={}".format(key_type, bits, fingerprint[:32], restrictions),
                recommended_value="Use ed25519 or RSA >= 3072 bits with restrictions." if status != STATUS_PASS else "",
                details=[f"Comment: {comment}", f"Key type: {key_type}", f"Bits: {bits}", f"Fingerprint: {fingerprint}", f"Restrictions: {restrictions}"],
            ))
    return results


def _check_sudoers(sudoers_paths: List[str]) -> List[dict]:
    results = []
    try:
        rules = parse_sudoers_paths(sudoers_paths)
    except Exception as exc:
        logger.exception("Failed to parse sudoers: %s", exc)
        return [skipped_check(
            id="ACC-002",
            category=CATEGORY,
            title="Sudoers parse error",
            what_it_checks="Failed to parse sudoers files.",
            risk="Sudoers configuration could not be evaluated.",
            command="sudo -l",
            reason=str(exc),
        )]
    
    for rule in rules:
        classification = classify_rule(rule)
        status = classification.get("status", STATUS_INFO)
        risk = classification.get("reason", "")
        user = rule.user
        command = rule.command
        results.append(make_check(
            id="ACC-002",
            category=CATEGORY,
            title="Sudoers rule for {} on {}".format(user, command),
            status=status,
            what_it_checks="Sudoers rule classification.",
            risk=risk,
            command="sudo -l",
            current_value="user={}, command={}, source={}".format(user, command, rule.source_file),
            recommended_value="Restrict sudoers to narrow commands." if status != STATUS_PASS else "",
            details=[f"User: {user}", f"Command: {command}", f"Source: {rule.source_file}", f"Line: {rule.line_num}"],
        ))
    return results


def _check_docker_group(group_file_content: str) -> List[dict]:
    results = []
    docker_members = []
    for line in group_file_content.strip().splitlines():
        parts = line.split(":")
        if len(parts) >= 4 and parts[0] == "docker":
            members_str = parts[3]
            if members_str:
                docker_members = [m.strip() for m in members_str.split(",") if m.strip()]
            break
    
    if not docker_members:
        return [make_check(
            id="ACC-003",
            category=CATEGORY,
            title="Docker group has no members",
            status=STATUS_PASS,
            what_it_checks="Docker group membership.",
            risk="No users have Docker group access.",
            command="getent group docker",
            current_value="No members",
            recommended_value="",
            details=["Docker group is empty."],
        )]
    
    unexpected = [u for u in docker_members if u not in EXPECTED_DOCKER_USERS]
    if unexpected:
        status = STATUS_WARNING
        risk = "Users in docker group have root-equivalent access."
        recommended = "Remove unexpected users from docker group."
    else:
        status = STATUS_INFO
        risk = "Docker group contains only expected users."
        recommended = ""
    
    results.append(make_check(
        id="ACC-003",
        category=CATEGORY,
        title="Docker group members: {}".format(", ".join(docker_members)),
        status=status,
        what_it_checks="Docker group membership (root-equivalent access).",
        risk=risk,
        command="getent group docker",
        current_value=", ".join(docker_members),
        recommended_value=recommended,
        details=["Docker group members have root-equivalent access to the host."],
    ))
    return results


def run_checks(root_authorized_keys: Optional[str] = None, users_authorized_keys: Optional[dict] = None,
               sudoers_paths: Optional[List[str]] = None, group_file_content: Optional[str] = None) -> List[dict]:
    results = []
    
    # ACC-001: authorized_keys
    if root_authorized_keys is None:
        try:
            with open("/root/.ssh/authorized_keys", "r", encoding="utf-8") as f:
                root_authorized_keys = f.read()
        except Exception as exc:
            logger.warning("Failed to read root authorized_keys: %s", exc)
            results.append(skipped_check(
                id="ACC-001",
                category=CATEGORY,
                title="Root authorized_keys unreadable",
                what_it_checks="SSH authorized_keys for root.",
                risk="Could not evaluate root SSH keys.",
                command="cat /root/.ssh/authorized_keys",
                reason=str(exc),
            ))
    else:
        if users_authorized_keys is None:
            users_authorized_keys = {}
            try:
                with open("/etc/passwd", "r", encoding="utf-8") as f:
                    for line in f:
                        parts = line.strip().split(":")
                        if len(parts) >= 7 and parts[6].startswith("/home/"):
                            user = parts[0]
                            ak_path = "/home/{}/.ssh/authorized_keys".format(user)
                            try:
                                with open(ak_path, "r", encoding="utf-8") as f:
                                    users_authorized_keys[user] = f.read()
                            except Exception:
                                pass
            except Exception as exc:
                logger.warning("Failed to enumerate users: %s", exc)
        results.extend(_check_authorized_keys(root_authorized_keys, users_authorized_keys))
    
    # ACC-002: sudoers
    if sudoers_paths is None:
        sudoers_paths = SUDOERS_PATHS
    results.extend(_check_sudoers(sudoers_paths))
    
    # ACC-003: docker group
    if group_file_content is None:
        try:
            with open(GROUP_FILE, "r", encoding="utf-8") as f:
                group_file_content = f.read()
        except Exception as exc:
            logger.warning("Failed to read group file: %s", exc)
            results.append(skipped_check(
                id="ACC-003",
                category=CATEGORY,
                title="Group file unreadable",
                what_it_checks="Docker group membership.",
                risk="Could not evaluate Docker group access.",
                command="getent group docker",
                reason=str(exc),
            ))
    else:
        results.extend(_check_docker_group(group_file_content))
    
    return results
