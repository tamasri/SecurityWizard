"""Authentication for the SecurityWizard dashboard.

The dashboard is locked by default. On the first start a simple random username and password are
generated, printed once to the console/log and stored (hashed) in ``credentials.json`` inside the data
directory. The user is invited, but never forced, to change them from the dashboard.

Modes (``get_auth_mode()``):
  * ``credentials`` - generated/stored credentials (default)
  * ``password``    - password hash supplied through SECURITYWIZARD_PASSWORD_HASH / _FILE
  * ``token``       - static bearer token supplied through SECURITYWIZARD_TOKEN
  * ``off``         - authentication explicitly disabled with SECURITYWIZARD_AUTH=0
"""
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import tempfile
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Optional, Tuple

from fastapi import HTTPException, Request

logger = logging.getLogger("securitywizard")

SESSION_COOKIE = "sw_session"
SESSION_MAX_AGE = 12 * 3600
CREDENTIALS_FILE = "credentials.json"
INITIAL_CREDENTIALS_FILE = "initial-credentials.txt"
MIN_PASSWORD_LENGTH = 8

_WORDS = [
    "river", "moon", "stone", "cloud", "tiger", "maple", "amber", "falcon", "ocean", "winter",
    "silver", "garden", "forest", "bridge", "candle", "desert", "eagle", "ember", "harbor", "island",
    "jungle", "kettle", "lemon", "meadow", "north", "olive", "pearl", "quiet", "rocket", "sunset",
    "thunder", "violet", "willow", "yellow", "zebra", "anchor", "breeze", "copper", "dragon", "echo",
]

# --- configuration and state -------------------------------------------------------------------

_lock = threading.RLock()
_allowed_hosts: Optional[list] = None
_auth_enabled: Optional[bool] = None
_auth_mode: Optional[str] = None
_password_hash: Optional[str] = None
_username: Optional[str] = None
_is_default: bool = False
_session_secret: Optional[str] = None
_session_epoch: int = 0
_generated_token: Optional[str] = None
_env_managed: bool = False
_initialized: bool = False


def get_data_dir() -> str:
    explicit = os.environ.get("SECURITYWIZARD_DATA_DIR", "").strip()
    if explicit:
        return explicit
    return os.path.join(os.environ.get("SECURITYWIZARD_BACKUP_DIR", "/var/backups/securitywizard"), "data")


def init(bind_address: str = "127.0.0.1") -> None:
    """Initialise authentication from the environment (idempotent)."""
    global _allowed_hosts, _auth_enabled, _auth_mode, _password_hash, _username, _is_default
    global _session_secret, _generated_token, _env_managed, _initialized

    with _lock:
        if _initialized:
            return
        auth_env = os.environ.get("SECURITYWIZARD_AUTH", "").strip().lower()
        _auth_enabled = auth_env not in ("0", "false", "off", "no")
        _allowed_hosts = _parse_allowed_hosts()
        _session_secret = secrets.token_hex(32)
        if _auth_enabled:
            _load_credentials()
        else:
            _auth_mode = "off"
            if bind_address not in ("127.0.0.1", "localhost", "::1"):
                logger.warning("Authentication is DISABLED while binding to %s. This is not recommended.", bind_address)
        _initialized = True
        logger.info("Auth initialised: enabled=%s mode=%s hosts=%s", _auth_enabled, _auth_mode, _allowed_hosts)


def _parse_allowed_hosts() -> list:
    raw = os.environ.get("SECURITYWIZARD_ALLOWED_HOSTS", "127.0.0.1,localhost,[::1]")
    hosts = [h.strip() for h in raw.split(",") if h.strip()]
    return hosts or ["127.0.0.1", "localhost", "[::1]"]


# --- credential storage ------------------------------------------------------------------------

def _write_private(path: str, text: str) -> None:
    """Atomically write ``text`` to ``path`` with owner-only permissions."""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".sw-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _generate_default_credentials() -> Tuple[str, str]:
    username = "wizard%04d" % secrets.randbelow(10000)
    password = "%s-%s-%03d" % (secrets.choice(_WORDS), secrets.choice(_WORDS), secrets.randbelow(1000))
    return username, password


def _read_store() -> Optional[dict]:
    path = os.path.join(get_data_dir(), CREDENTIALS_FILE)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict) and data.get("username") and data.get("password_hash"):
            return data
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        logger.error("Cannot read credential store %s: %s", path, exc)
    return None


def _save_store(username: str, password_hash: str, is_default: bool) -> None:
    payload = {
        "username": username,
        "password_hash": password_hash,
        "is_default": bool(is_default),
        "created": datetime.now(timezone.utc).isoformat(),
    }
    _write_private(os.path.join(get_data_dir(), CREDENTIALS_FILE), json.dumps(payload, indent=2) + "\n")


def _announce_initial_credentials(username: str, password: str) -> None:
    """Print the generated credentials exactly once (console + private file)."""
    path = os.path.join(get_data_dir(), INITIAL_CREDENTIALS_FILE)
    note = ("SecurityWizard initial credentials (default, please change them after the first login)\n"
            "username: %s\npassword: %s\n" % (username, password))
    try:
        _write_private(path, note)
    except OSError as exc:
        logger.error("Could not write %s: %s", path, exc)
        path = "(not saved)"
    line = "=" * 64
    banner = ("\n%s\n SecurityWizard is locked. Default login credentials:\n"
              "   username: %s\n   password: %s\n"
              " These are the DEFAULT credentials - please change them after logging in.\n"
              " Also saved in: %s\n%s\n" % (line, username, password, path, line))
    print(banner, flush=True)


def _load_credentials() -> None:
    global _auth_mode, _password_hash, _username, _is_default, _generated_token, _env_managed

    token_env = os.environ.get("SECURITYWIZARD_TOKEN", "")
    pw_file = os.environ.get("SECURITYWIZARD_PASSWORD_FILE", "")
    pw_hash_env = os.environ.get("SECURITYWIZARD_PASSWORD_HASH", "")

    if token_env:
        _auth_mode, _generated_token, _env_managed = "token", token_env, True
        return
    if pw_file or pw_hash_env:
        value = pw_hash_env
        if pw_file:
            try:
                with open(pw_file, "r", encoding="utf-8") as handle:
                    value = handle.read().strip()
                if not value:
                    raise ValueError("empty password file")
            except Exception as exc:  # fail closed: nobody can log in
                logger.error("Failed to read password file: %s", exc)
                _auth_mode, _password_hash, _env_managed = "error", None, True
                return
        _auth_mode, _password_hash, _env_managed = "password", value, True
        _username = os.environ.get("SECURITYWIZARD_USERNAME", "admin") or "admin"
        _is_default = False
        return

    _auth_mode, _env_managed = "credentials", False
    store = _read_store()
    if store is None:
        username, password = _generate_default_credentials()
        _save_store(username, hash_password(password), True)
        _announce_initial_credentials(username, password)
        store = _read_store()
        if store is None:  # data dir not writable: keep working in memory for this run
            store = {"username": username, "password_hash": hash_password(password), "is_default": True}
    _username = store["username"]
    _password_hash = store["password_hash"]
    _is_default = bool(store.get("is_default", False))


# --- password hashing --------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """Hash a password with argon2 when available, otherwise PBKDF2-HMAC-SHA256."""
    try:
        from argon2 import PasswordHasher
        return PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4).hash(password)
    except ImportError:
        salt = secrets.token_hex(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 600000)
        return "pbkdf2_sha256$600000$%s$%s" % (salt, digest.hex())


def verify_password(password: str, password_hash: Optional[str]) -> bool:
    if not password_hash:
        return False
    if password_hash.startswith("$argon2"):
        try:
            from argon2 import PasswordHasher
            return bool(PasswordHasher().verify(password_hash, password))
        except ImportError:
            return False
        except Exception:
            return False
    if password_hash.startswith("pbkdf2_sha256$"):
        try:
            _, iterations, salt, stored = password_hash.split("$")
            digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), int(iterations))
            return hmac.compare_digest(digest.hex(), stored)
        except Exception:
            return False
    return False


_DUMMY_HASH = "pbkdf2_sha256$600000$00000000000000000000000000000000$" + "0" * 64


def verify_login(username: str, password: str) -> bool:
    """Constant-time-ish check of a username + password pair."""
    with _lock:
        stored_user, stored_hash = _username or "", _password_hash
    user_ok = hmac.compare_digest((username or "").encode("utf-8"), stored_user.encode("utf-8"))
    pw_ok = verify_password(password or "", stored_hash or _DUMMY_HASH)
    return bool(user_ok and pw_ok and stored_hash)


def change_credentials(current_password: str, new_password: str, new_username: Optional[str] = None) -> Tuple[bool, str]:
    """Change the stored credentials. Returns (ok, message)."""
    global _username, _password_hash, _is_default, _session_epoch
    with _lock:
        if _auth_mode != "credentials":
            return False, "Credentials are managed through the environment and cannot be changed here."
        if not verify_password(current_password or "", _password_hash):
            return False, "The current password is incorrect."
        if not isinstance(new_password, str) or len(new_password) < MIN_PASSWORD_LENGTH:
            return False, "The new password must be at least %d characters." % MIN_PASSWORD_LENGTH
        if new_password == current_password:
            return False, "The new password must differ from the current one."
        username = (new_username or "").strip() or (_username or "admin")
        if len(username) > 64 or any(ch.isspace() for ch in username):
            return False, "The username must be 1-64 characters without spaces."
        new_hash = hash_password(new_password)
        _save_store(username, new_hash, False)
        _username, _password_hash, _is_default = username, new_hash, False
        _session_epoch += 1
        try:
            os.unlink(os.path.join(get_data_dir(), INITIAL_CREDENTIALS_FILE))
        except OSError:
            pass
        return True, "Credentials updated."


# --- sessions ----------------------------------------------------------------------------------

def _sign(payload_b64: str) -> str:
    return hmac.new((_session_secret or "").encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256).hexdigest()


def _create_session_token(username: str) -> str:
    payload = "%s|%d|%d" % (username, int(time.time()), _session_epoch)
    payload_b64 = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("utf-8")
    return "%s.%s" % (payload_b64, _sign(payload_b64))


def _verify_session_token(token: str) -> Optional[str]:
    if not token or "." not in token or not _session_secret:
        return None
    payload_b64, signature = token.split(".", 1)
    if not hmac.compare_digest(signature, _sign(payload_b64)):
        return None
    try:
        payload = base64.urlsafe_b64decode(payload_b64.encode("utf-8")).decode("utf-8")
        parts = payload.rsplit("|", 2)
        if len(parts) == 3:
            username, issued, epoch = parts[0], int(parts[1]), int(parts[2])
        else:
            username, issued, epoch = parts[0], int(parts[1]), 0
    except Exception:
        return None
    if epoch != _session_epoch or time.time() - issued > SESSION_MAX_AGE:
        return None
    return username


def request_user(request: Request) -> Optional[str]:
    """Return the authenticated user name for a request (cookie session or bearer token), else None."""
    cookie = request.cookies.get(SESSION_COOKIE, "")
    if cookie:
        user = _verify_session_token(cookie)
        if user:
            return user
    if _auth_mode == "token" and _generated_token:
        header = request.headers.get("authorization", "")
        if header.startswith("Bearer ") and hmac.compare_digest(header[7:], _generated_token):
            return "token-user"
    return None


def get_auth_dependency() -> Optional[Callable]:
    if not _auth_enabled:
        return None

    def auth_dependency(request: Request):
        user = request_user(request)
        if user:
            return user
        raise HTTPException(status_code=401, detail="Authentication required")

    return auth_dependency


# --- accessors ---------------------------------------------------------------------------------

def is_auth_enabled() -> bool:
    return bool(_auth_enabled)


def get_auth_mode() -> Optional[str]:
    return _auth_mode


def get_password_hash() -> Optional[str]:
    return _password_hash


def get_username() -> Optional[str]:
    return _username


def using_default_credentials() -> bool:
    return bool(_auth_enabled and _auth_mode == "credentials" and _is_default)


def get_generated_token() -> Optional[str]:
    return _generated_token


def get_allowed_hosts() -> list:
    return _allowed_hosts or ["127.0.0.1", "localhost", "[::1]"]


def check_host_allowed(host: str) -> bool:
    if not host:
        return False
    if host.startswith("["):
        end = host.find("]")
        host_part = host[1:end] if end > 0 else host
        allowed = [h.strip("[]") for h in get_allowed_hosts()]
        return host_part in allowed
    return host.split(":")[0] in get_allowed_hosts()


def reset_for_tests() -> None:
    global _allowed_hosts, _auth_enabled, _auth_mode, _password_hash, _username, _is_default
    global _session_secret, _session_epoch, _generated_token, _env_managed, _initialized
    with _lock:
        _allowed_hosts = None
        _auth_enabled = None
        _auth_mode = None
        _password_hash = None
        _username = None
        _is_default = False
        _session_secret = None
        _session_epoch = 0
        _generated_token = None
        _env_managed = False
        _initialized = False


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "hash":
        print(hash_password(sys.stdin.read().strip()))
    else:
        print("Usage: python -m auth hash   (reads the password from stdin)")
