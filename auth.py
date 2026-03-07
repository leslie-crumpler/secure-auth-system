"""
auth.py - Secure authentication helpers
Includes: password hashing, input validation, brute-force protection, login logging
"""

import logging
import time
from werkzeug.security import generate_password_hash, check_password_hash

# ── Logging Setup ────────────────────────────────────────
logging.basicConfig(
    filename="auth.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)
logger = logging.getLogger(__name__)

# ── Brute-Force Protection ────────────────────────────────
# Tracks {ip: {"count": int, "lockout_until": float}}
_failed_attempts = {}
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 300  # 5-minute lockout


def is_locked_out(ip: str) -> bool:
    """Return True if the IP is currently locked out."""
    record = _failed_attempts.get(ip)
    if not record:
        return False
    if record["lockout_until"] and time.time() < record["lockout_until"]:
        return True
    # Lockout expired — reset
    _failed_attempts.pop(ip, None)
    return False


def record_failed_attempt(ip: str):
    """Increment failed attempt count. Lock out after MAX_ATTEMPTS."""
    if ip not in _failed_attempts:
        _failed_attempts[ip] = {"count": 0, "lockout_until": 0.0}
    _failed_attempts[ip]["count"] += 1
    count = _failed_attempts[ip]["count"]

    if count >= MAX_ATTEMPTS:
        _failed_attempts[ip]["lockout_until"] = time.time() + LOCKOUT_SECONDS
        logger.warning(f"IP {ip} locked out after {MAX_ATTEMPTS} failed attempts.")
    else:
        logger.warning(f"IP {ip} failed login attempt #{count}.")


def reset_attempts(ip: str):
    """Clear attempts on successful login."""
    _failed_attempts.pop(ip, None)


# ── Password Utilities ───────────────────────────────────

def hash_password(plain: str) -> str:
    """Hash a plain-text password securely."""
    return generate_password_hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plain-text password against its hash."""
    return check_password_hash(hashed, plain)


# ── Input Validation ─────────────────────────────────────

def validate_registration(username: str, password: str):
    """Return (ok: bool, message: str) for registration inputs."""
    username = username.strip() if username else ""
    if len(username) < 3 or len(username) > 30:
        return False, "Username must be 3–30 characters."
    if not username.isalnum():
        return False, "Username must contain only letters and numbers."
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    return True, "OK"


# ── Audit Logging ────────────────────────────────────────

def log_login_success(username: str, ip: str):
    logger.info(f"Successful login | user={username} | ip={ip}")


def log_login_failure(username: str, ip: str):
    logger.warning(f"Failed login | user={username} | ip={ip}")


def log_logout(username: str, ip: str):
    logger.info(f"Logout | user={username} | ip={ip}")
