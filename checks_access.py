import base64
import hashlib
import logging
from typing import List, Optional, Tuple

from common import (
    STATUS_INFO,
    STATUS_PASS,
    STATUS_WARNING,
    make_check,
    skipped_check,
)
from config import get_config
from sudoers_parse import classify_rule, parse_sudoers_paths

logger = logging.getLogger(__name__)

CATEGORY = "access"
AUTHORIZED_KEYS_PATHS = {
    "root": "/root/.ssh/authorized_keys",
}
GROUP_FILE = "/etc/group"
SUDOERS_PATHS = ["/etc/sudoers", "/etc/sudoers.d"]

EXPECTED_DOCKER_USERS = {"root"}


KEY_TYPE_PREFIXES = ("ssh-", "ecdsa-sha2-", "sk-ssh-", "sk-ecdsa-")


def _tokenize(line: str) -> List[str]:
    """Split on whitespace that is not inside double quotes (authorized_keys options may contain spaces)."""
    tokens: List[str] = []
    current: List[str] = []
    in_quotes = False
    escaped = False
    for ch in line:
        if escaped:
            current.append(ch)
            escaped = False
        elif ch == "\\" and in_quotes:
            current.append(ch)
            escaped = True
        elif ch == '"':
            in_quotes = not in_quotes
            current.append(ch)
        elif ch.isspace() and not in_quotes:
            if current:
                tokens.append("".join(current))
                current = []
        else:
            current.append(ch)
    if current:
        tokens.append("".join(current))
    return tokens


def split_key_line(line: str) -> Optional[Tuple[str, str, str, str]]:
    """Split an authorized_keys line into (options, key_type, key_blob_base64, comment) or None."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    tokens = _tokenize(line)
    for index, token in enumerate(tokens):
        if token.startswith(KEY_TYPE_PREFIXES):
            if index + 1 >= len(tokens):
                return None
            return (" ".join(tokens[:index]), token, tokens[index + 1], " ".join(tokens[index + 2 :]))
    return None


def _line_restrictions(line: str) -> List[str]:
    parts = split_key_line(line)
    return _parse_options(parts[0]) if parts else []


def _read_string(blob: bytes, pos: int) -> Tuple[bytes, int]:
    length = int.from_bytes(blob[pos : pos + 4], "big")
    start = pos + 4
    if length < 0 or start + length > len(blob):
        raise ValueError("truncated SSH key blob")
    return blob[start : start + length], start + length


def fingerprint_sha256(blob: bytes) -> str:
    """OpenSSH style fingerprint: SHA256:<base64 without padding>."""
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")


def _parse_key_line(line: str) -> Optional[Tuple[str, str, str, str]]:
    """Parse an authorized_keys line. Returns (key_type, bits_str, fingerprint, comment) or None."""
    parts = split_key_line(line)
    if parts is None:
        return None
    _options, key_type, key_blob_b64, comment = parts
    try:
        key_blob = base64.b64decode(key_blob_b64, validate=True)
    except Exception:
        return None
    return (key_type, _derive_bits(key_type, key_blob), fingerprint_sha256(key_blob), comment)


def _derive_bits(key_type: str, blob: bytes) -> str:
    if key_type == "ssh-rsa":
        try:
            _type, pos = _read_string(blob, 0)
            _exponent, pos = _read_string(blob, pos)
            modulus, _pos = _read_string(blob, pos)
            return str(int.from_bytes(modulus, "big").bit_length())
        except Exception:
            return "unknown"
    if key_type == "ssh-dss":
        return "1024"
    fixed = {
        "ecdsa-sha2-nistp256": "256",
        "ecdsa-sha2-nistp384": "384",
        "ecdsa-sha2-nistp521": "521",
        "ssh-ed25519": "256",
    }
    return fixed.get(key_type, "unknown")


def _parse_options(options_str: str) -> List[str]:
    """Parse SSH authorized_keys options into a list of restriction names."""
    restrictions: List[str] = []
    if not options_str:
        return restrictions
    # Split by commas, respecting quotes
    current = ""
    in_quotes = False
    for ch in options_str:
        if ch == '"':
            in_quotes = not in_quotes
            current += ch
        elif ch == "," and not in_quotes:
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
    for line in root_lines:
        parsed = _parse_key_line(line)
        if parsed is None:
            continue
        key_type, bits, fingerprint, comment = parsed
        restrictions = _line_restrictions(line)
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

        results.append(
            make_check(
                id="ACC-001",
                category=CATEGORY,
                title="Root authorized_keys: {}".format(comment or fingerprint[:16]),
                status=status,
                what_it_checks="SSH authorized_keys entry for root.",
                risk=risk,
                command="cat /root/.ssh/authorized_keys",
                current_value="type={}, bits={}, fingerprint={}, restrictions={}".format(
                    key_type, bits, fingerprint[:32], restrictions
                ),
                recommended_value="Use ed25519 or RSA >= 3072 bits with restrictions." if status != STATUS_PASS else "",
                details=[
                    f"Comment: {comment}",
                    f"Key type: {key_type}",
                    f"Bits: {bits}",
                    f"Fingerprint: {fingerprint}",
                    f"Restrictions: {restrictions}",
                ],
            )
        )

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
            restrictions = _line_restrictions(line)
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

            results.append(
                make_check(
                    id="ACC-001",
                    category=CATEGORY,
                    title="User {} authorized_keys: {}".format(user, comment or fingerprint[:16]),
                    status=status,
                    what_it_checks="SSH authorized_keys entry for user {}.".format(user),
                    risk=risk,
                    command="cat /home/{}/.ssh/authorized_keys".format(user),
                    current_value="type={}, bits={}, fingerprint={}, restrictions={}".format(
                        key_type, bits, fingerprint[:32], restrictions
                    ),
                    recommended_value="Use ed25519 or RSA >= 3072 bits with restrictions."
                    if status != STATUS_PASS
                    else "",
                    details=[
                        f"Comment: {comment}",
                        f"Key type: {key_type}",
                        f"Bits: {bits}",
                        f"Fingerprint: {fingerprint}",
                        f"Restrictions: {restrictions}",
                    ],
                )
            )
    return results


def _check_sudoers(sudoers_paths: List[str]) -> List[dict]:
    results = []
    try:
        rules = parse_sudoers_paths(sudoers_paths)
    except Exception as exc:
        logger.exception("Failed to parse sudoers: %s", exc)
        return [
            skipped_check(
                id="ACC-002",
                category=CATEGORY,
                title="Sudoers parse error",
                what_it_checks="Failed to parse sudoers files.",
                risk="Sudoers configuration could not be evaluated.",
                command="sudo -l",
                reason=str(exc),
            )
        ]

    for rule in rules:
        status, risk = classify_rule(rule, get_config())
        user = rule.user
        command = ", ".join(rule.commands)
        results.append(
            make_check(
                id="ACC-002",
                category=CATEGORY,
                title="Sudoers rule for {} on {}".format(user, command),
                status=status,
                what_it_checks="Sudoers rule classification.",
                risk=risk,
                command="sudo -l",
                current_value="user={}, command={}, source={}".format(user, command, rule.source_file),
                recommended_value="Restrict sudoers to narrow commands." if status != STATUS_PASS else "",
                details=[
                    f"User: {user}",
                    f"Command: {command}",
                    f"Source: {rule.source_file}",
                    f"Line: {rule.line}",
                ],
            )
        )
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
        return [
            make_check(
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
            )
        ]

    unexpected = [u for u in docker_members if u not in EXPECTED_DOCKER_USERS]
    if unexpected:
        status = STATUS_WARNING
        risk = "Users in docker group have root-equivalent access."
        recommended = "Remove unexpected users from docker group."
    else:
        status = STATUS_INFO
        risk = "Docker group contains only expected users."
        recommended = ""

    results.append(
        make_check(
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
        )
    )
    return results


PASSWD_FILE = "/etc/passwd"  # nosec B105
ROOT_AUTHORIZED_KEYS = "/root/.ssh/authorized_keys"


def _read_file(path: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (content, error). A missing file counts as an empty file; any other failure is an error."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read(), None
    except FileNotFoundError:
        return "", None
    except Exception as exc:
        logger.warning("Failed to read %s: %s", path, exc)
        return None, str(exc)


def _login_users_authorized_keys(passwd_content: str) -> dict:
    """authorized_keys of every account whose home directory is under /home (field 6 of /etc/passwd)."""
    keys = {}
    for line in passwd_content.splitlines():
        parts = line.strip().split(":")
        if len(parts) < 7 or not parts[5].startswith("/home/"):
            continue
        content, _error = _read_file(parts[5].rstrip("/") + "/.ssh/authorized_keys")
        if content:
            keys[parts[0]] = content
    return keys


def run_checks(
    root_authorized_keys: Optional[str] = None,
    users_authorized_keys: Optional[dict] = None,
    sudoers_paths: Optional[List[str]] = None,
    group_file_content: Optional[str] = None,
) -> List[dict]:
    results = []

    # ACC-001: authorized_keys
    if root_authorized_keys is None:
        root_authorized_keys, error = _read_file(ROOT_AUTHORIZED_KEYS)
        if error is not None:
            results.append(
                skipped_check(
                    id="ACC-001",
                    category=CATEGORY,
                    title="Root authorized_keys unreadable",
                    what_it_checks="SSH authorized_keys for root.",
                    risk="Could not evaluate root SSH keys.",
                    command="cat /root/.ssh/authorized_keys",
                    reason=error,
                )
            )
    if root_authorized_keys is not None:
        if users_authorized_keys is None:
            passwd_content, _error = _read_file(PASSWD_FILE)
            users_authorized_keys = _login_users_authorized_keys(passwd_content or "")
        results.extend(_check_authorized_keys(root_authorized_keys, users_authorized_keys))

    # ACC-002: sudoers
    if sudoers_paths is None:
        sudoers_paths = SUDOERS_PATHS
    results.extend(_check_sudoers(sudoers_paths))

    # ACC-003: docker group
    if group_file_content is None:
        group_file_content, error = _read_file(GROUP_FILE)
        if error is not None:
            results.append(
                skipped_check(
                    id="ACC-003",
                    category=CATEGORY,
                    title="Group file unreadable",
                    what_it_checks="Docker group membership.",
                    risk="Could not evaluate Docker group access.",
                    command="getent group docker",
                    reason=error,
                )
            )
    if group_file_content is not None:
        results.extend(_check_docker_group(group_file_content))

    return results
