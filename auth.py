import os
import re
import hmac
import secrets
import hashlib
import logging
import time
import base64
from typing import Optional, Tuple

from fastapi import Request, HTTPException

logger = logging.getLogger(__name__)

# --- Configuration and State ---

_allowed_hosts: Optional[list] = None
_auth_enabled: Optional[bool] = None
_auth_mode: Optional[str] = None
_password_hash: Optional[str] = None
_session_secret: Optional[str] = None
_generated_token: Optional[str] = None
_initialized: bool = False

def init(bind_address: str = "127.0.0.1") -> None:
    """Initialize authentication settings based on environment and bind address."""
    global _allowed_hosts, _auth_enabled, _auth_mode, _password_hash, _session_secret, _generated_token, _initialized
    
    if _initialized:
        return

    bind_address = bind_address or "127.0.0.1"
    is_loopback = bind_address in ("127.0.0.1", "localhost", "::1")
    
    auth_env = os.environ.get("SECURITYWIZARD_AUTH", "").lower()
    if auth_env == "1" or auth_env == "true":
        _auth_enabled = True
    elif auth_env == "0" or auth_env == "false":
        _auth_enabled = False
    else:
        _auth_enabled = not is_loopback

    _allowed_hosts = _parse_allowed_hosts()
    _session_secret = secrets.token_hex(32)

    if _auth_enabled:
        _auth_mode, _password_hash, _generated_token = _load_auth_credentials()
    
    _initialized = True
    logger.info("Auth initialized: enabled=%s, mode=%s, hosts=%s", _auth_enabled, _auth_mode, _allowed_hosts)

def _parse_allowed_hosts() -> list:
    hosts_env = os.environ.get("SECURITYWIZARD_ALLOWED_HOSTS", "127.0.0.1,localhost,[::1]")
    hosts = [h.strip() for h in hosts_env.split(",") if h.strip()]
    return hosts if hosts else ["127.0.0.1", "localhost", "[::1]"]

def _load_auth_credentials() -> Tuple[str, Optional[str], Optional[str]]:
    """Load credentials. Returns (mode, password_hash, generated_token)."""
    global _password_hash, _generated_token

    token_env = os.environ.get("SECURITYWIZARD_TOKEN", "")
    if token_env:
        return "token", None, token_env

    pw_file = os.environ.get("SECURITYWIZARD_PASSWORD_FILE", "")
    pw_hash_env = os.environ.get("SECURITYWIZARD_PASSWORD_HASH", "")
    
    if pw_file:
        try:
            with open(pw_file, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if not content:
                raise ValueError("Empty password file")
            return "password", content, None
        except Exception as e:
            logger.error("Failed to read password file: %s", e)
            return "error", None, None

    if pw_hash_env:
        return "password", pw_hash_env, None

    _generated_token = secrets.token_urlsafe(32)
    return "token", None, _generated_token

def hash_password(password: str) -> str:
    """Generate a password hash. Uses argon2 if available, else PBKDF2-HMAC-SHA256."""
    try:
        from argon2 import PasswordHasher
        ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
        return ph.hash(password)
    except ImportError:
        salt = secrets.token_hex(16)
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 600000)
        return f"pbkdf2_sha256$600000${salt}${dk.hex()}"

def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against a stored hash."""
    if not password_hash:
        return False
    if password_hash.startswith("$argon2"):
        try:
            from argon2 import PasswordHasher
            ph = PasswordHasher()
            return ph.verify(password_hash, password)
        except ImportError:
            return False
        except Exception as e:
            logger.error("Argon2 verification error: %s", e)
            return False
    
    if password_hash.startswith("pbkdf2_sha256$"):
        try:
            parts = password_hash.split("$")
            if len(parts) != 4:
                return False
            iterations = int(parts[1])
            salt = parts[2]
            stored_dk = parts[3]
            dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), iterations)
            return hmac.compare_digest(dk.hex(), stored_dk)
        except Exception as e:
            logger.error("PBKDF2 verification error: %s", e)
            return False
    
    return False

def _create_session_token(username: str) -> str:
    """Create a signed session token."""
    payload = f"{username}|{int(time.time())}"
    payload_b64 = base64.urlsafe_b64encode(payload.encode('utf-8')).decode('utf-8')
    signature = hmac.new(_session_secret.encode('utf-8'), payload_b64.encode('utf-8'), hashlib.sha256).hexdigest()
    return f"{payload_b64}.{signature}"

def _verify_session_token(token: str) -> Optional[str]:
    """Verify a session token and return the username if valid."""
    if not token or "." not in token:
        return None
    parts = token.split(".", 1)
    if len(parts) != 2:
        return None
    payload_b64, signature = parts
    expected_sig = hmac.new(_session_secret.encode('utf-8'), payload_b64.encode('utf-8'), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected_sig):
        return None
    try:
        payload = base64.urlsafe_b64decode(payload_b64.encode('utf-8')).decode('utf-8')
        username, _ = payload.split("|", 1)
        return username
    except Exception:
        return None

def get_auth_dependency() -> Optional[callable]:
    """Return an auth dependency function if auth is enabled, else None."""
    if not _auth_enabled:
        return None

    def auth_dependency(request: Request):
        cookie_token = request.cookies.get("sw_session", "")
        if cookie_token:
            username = _verify_session_token(cookie_token)
            if username:
                return username
        
        if _auth_mode == "token" and _generated_token:
            auth_header = request.headers.get("authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]
                if hmac.compare_digest(token, _generated_token):
                    return "token-user"
        
        raise HTTPException(status_code=401, detail="Authentication required")

    return auth_dependency

def is_auth_enabled() -> bool:
    return bool(_auth_enabled)

def get_generated_token() -> Optional[str]:
    return _generated_token

def get_allowed_hosts() -> list:
    return _allowed_hosts or ["127.0.0.1", "localhost", "[::1]"]

def check_host_allowed(host: str) -> bool:
    """Check if the Host header is in the allowed list."""
    if not host:
        return False
    host_part = host.split(":")[0]
    if host_part.startswith("[") and host_part.endswith("]"):
        host_part = host_part[1:-1]
    return host_part in get_allowed_hosts()

def reset_for_tests() -> None:
    """Reset state for testing."""
    global _allowed_hosts, _auth_enabled, _auth_mode, _password_hash, _session_secret, _generated_token, _initialized
    _allowed_hosts = None
    _auth_enabled = None
    _auth_mode = None
    _password_hash = None
    _session_secret = None
    _generated_token = None
    _initialized = False

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "hash":
        password = sys.stdin.read().strip()
        print(hash_password(password))
    else:
        print("Usage: python -m auth hash")
