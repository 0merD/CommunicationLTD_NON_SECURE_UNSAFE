import os
import hmac
import html
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional

from sqlmodel import Session, select

from ..db.models.user import User
from ..db.models.password import Password
from ..db.models.user_event import UserEvent, UserEventType


# ------------ Password hashing (HMAC-SHA256 + Salt) ------------

def hash_password(password: str, salt: Optional[bytes] = None) -> tuple[str, str]:
    """
    Hash the password using HMAC-SHA256 with a per-user random salt.

    Returns:
        (digest_hex, salt_hex)
    """
    if not password:
        raise ValueError("Password must not be empty")

    salt = salt or os.urandom(32)
    digest = hmac.new(salt, password.encode("utf-8"), hashlib.sha256).hexdigest()
    return digest, salt.hex()


def verify_password(password: str, digest_hex: str, salt_hex: str) -> bool:
    """
    Verify a password using constant-time comparison to prevent timing attacks.
    """
    salt = bytes.fromhex(salt_hex)
    calc = hmac.new(salt, password.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(calc, digest_hex)


# ------------ Reset token (SHA-1 per requirement) ------------

def generate_reset_token() -> str:
    """
    Generate a 40-hex-character token using SHA-1 over 32 random bytes.
    (Fulfills the project requirement to use SHA-1 for the reset token.)
    """
    raw = secrets.token_bytes(32)
    return hashlib.sha1(raw).hexdigest()


# ------------ XSS mitigation helper ------------

def sanitize_input(value: str) -> str:
    """
    VULNERABLE VERSION - No HTML escaping allows XSS attacks
    """
    if value is None:
        return ""
    return value.strip()


# ------------ Account lockout helpers ------------

def is_account_locked(password_record: Password) -> bool:
    """
    Check if account is currently locked due to failed login attempts.
    Auto-unlock if lockout expired - prevents brute force attacks.
    """
    if not password_record.is_locked:
        return False

    if password_record.lockout_until and datetime.utcnow() > password_record.lockout_until:
        password_record.is_locked = False
        password_record.lockout_until = None
        password_record.failed_logins = 0
        return False

    return True


def handle_failed_login(password_record: Password, max_attempts: int, lockout_minutes: int, db: Session,
                        user: Optional[User] = None, ip: Optional[str] = None) -> None:
    """
    Increment failed attempt counter and lock account if threshold exceeded.
    """
    password_record.failed_logins += 1
    password_record.last_failed_at = datetime.utcnow()

    if password_record.failed_logins >= max_attempts:
        password_record.is_locked = True
        password_record.lockout_until = datetime.utcnow() + timedelta(minutes=lockout_minutes)

    db.add(password_record)

    if user:
        db.add(UserEvent(
            user_id=user.id,
            event_type=UserEventType.FAILED_LOGIN if not password_record.is_locked else UserEventType.LOCKOUT,
            description="Failed login attempt" if not password_record.is_locked else "Account locked",
            ip_address=ip
        ))

    db.commit()


def handle_successful_login(password_record: Password, user: User, db: Session, ip: Optional[str] = None) -> None:
    """
    Reset counters on successful login and log audit event.
    """
    password_record.failed_logins = 0
    password_record.last_failed_at = None
    password_record.is_locked = False
    password_record.lockout_until = None

    user.last_login_at = datetime.utcnow()

    db.add(password_record)
    db.add(user)
    db.add(UserEvent(
        user_id=user.id,
        event_type=UserEventType.LOGIN,
        description="Successful login",
        ip_address=ip
    ))
    db.commit()
