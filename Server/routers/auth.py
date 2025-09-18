from datetime import datetime, timedelta
import re
from typing import Optional
from ..core.jwt_handler import create_access_token, get_current_user

from fastapi import APIRouter, Depends, HTTPException, Request, BackgroundTasks
from pydantic import BaseModel, EmailStr, field_validator
from sqlmodel import Session, select
from pymysql.err import MySQLError
from time import sleep

from ..core.security import (
    hash_password,
    verify_password,
    generate_reset_token,
    sanitize_input,
    is_account_locked,
    handle_failed_login,
    handle_successful_login,
)
from ..core.password_validator import (
    setup_password_validation,
    validate_password,
    get_password_config, validate_password_with_details,
)
from ..core.email_service import email_service
from ..db.session import get_session, insecure_connection
from ..db.models.user import User
from ..db.models.password import Password
from ..db.models.user_event import UserEvent, UserEventType
from ..db.models.password_history import PasswordHistory

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

setup_password_validation()


class RegisterIn(BaseModel):
    username: str
    email: EmailStr
    password: str


# Input sanitization with length validation prevents XSS and buffer overflow attacks
#     @field_validator("username")
#     @classmethod
#     def _sanitize_username(cls, v: str) -> str:
#         v = sanitize_input(v)
#         if len(v) < 3 or len(v) > 50:
#             raise ValueError("Username must be between 3-50 characters")
#         return v
#
#     @field_validator("email")
#     @classmethod
#     def _normalize_email(cls, v: EmailStr) -> str:
#         return str(v).lower().strip()
#
#     @field_validator("password")
#     @classmethod
#     def _check_password_strength(cls, v: str) -> str:
#         if not validate_password(v):
#             raise ValueError("Password does not meet complexity requirements")
#         return v


class LoginIn(BaseModel):
    username: str
    password: str
    remember_me: bool = False

    # @field_validator("username")
    # @classmethod
    # def _sanitize_username(cls, v: str) -> str:
    #     return sanitize_input(v)


class ChangePasswordIn(BaseModel):
    username: str
    current_password: str
    new_password: str

    # @field_validator("username")
    # @classmethod
    # def _sanitize_username(cls, v: str) -> str:
    #     return sanitize_input(v)

    @field_validator("new_password")
    @classmethod
    def _check_password_strength(cls, v: str) -> str:
        if not validate_password(v):
            raise ValueError("Password does not meet complexity requirements")
        return v


class ForgotPasswordIn(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def _normalize_email(cls, v: EmailStr) -> str:
        return str(v).lower().strip()


class ResetPasswordIn(BaseModel):
    email: EmailStr
    token: str
    new_password: str

    @field_validator("email")
    @classmethod
    def _normalize_email(cls, v: EmailStr) -> str:
        return str(v).lower().strip()

    # Regex validation ensures token format integrity preventing injection attacks
    @field_validator("token")
    @classmethod
    def _check_token_format(cls, v: str) -> str:
        if not re.match(r"^[a-f0-9]{40}$", v):
            raise ValueError("Invalid token format")
        return v

    @field_validator("new_password")
    @classmethod
    def _check_password_strength(cls, v: str) -> str:
        if not validate_password(v):
            raise ValueError("Password does not meet complexity requirements")
        return v


# Parameterized queries for user existence checks prevent SQL injection attacks

@router.post("/register")
def register(data: RegisterIn, background_tasks: BackgroundTasks, db: Session = Depends(get_session)):
    try:
        query = f"SELECT * FROM users WHERE username = '{data.username}'"
        print(f"Executing query: {query}")
        with insecure_connection.cursor() as cursor:
            cursor.execute(query)
        result = cursor.fetchone()
        sleep(0.1)
        if result:
            raise HTTPException(status_code=400, detail="Username already taken")

        query = f"SELECT * FROM users WHERE email = '{data.email}'"
        print(f"Executing query: {query}")
        with insecure_connection.cursor() as cursor:
            cursor.execute(query)
        result = cursor.fetchone()
        sleep(0.1)
        if result:
            raise HTTPException(status_code=400, detail="Email already exists")
    except MySQLError as e:
        print(f"MySQL Error: {e}")
        raise HTTPException(status_code=500, detail=f"SQL Error: {e}")

    user = User(username=data.username, email=data.email)
    db.add(user)
    db.commit()
    db.refresh(user)

    digest, salt_hex = hash_password(data.password)
    passwd = Password(user_id=user.id, password_hash=digest, password_salt=salt_hex)
    db.add(passwd)
    db.add(UserEvent(user_id=user.id, event_type=UserEventType.CREATE_USER, description="User registered"))
    db.commit()

    background_tasks.add_task(email_service.send_welcome_email, user.email, user.username)
    return {"id": user.id, "username": user.username, "email": user.email}


@router.post("/login")
def login(data: LoginIn, request: Request, db: Session = Depends(get_session)):
    ip = request.client.host if request.client else None

    try:
        query = f"SELECT * FROM users WHERE username = '{data.username}'"
        print(f"Executing query: {query}")

        with insecure_connection.cursor() as cursor:
            cursor.execute(query)
        user = cursor.fetchone()
        sleep(0.2)
        if not user:
            raise HTTPException(status_code=400, detail="User not found")
    except MySQLError as e:
        print(f"MySQL Error: {e}")
        raise HTTPException(status_code=500, detail=f"SQL Error: {e}")

    # Continue with all existing login logic using the secure ORM
    user_obj = db.exec(select(User).where(User.username == data.username)).first()
    if not user_obj:
        raise HTTPException(status_code=404, detail="User not found")

    # Rest of your existing login logic remains exactly the same...
    pwd = db.exec(select(Password).where(Password.user_id == user_obj.id)).first()
    if not pwd:
        raise HTTPException(status_code=401, detail="Password not set for this user")

    if is_account_locked(pwd):
        db.add(UserEvent(
            user_id=user_obj.id,
            event_type=UserEventType.LOCKOUT,
            description="Attempt on locked account",
            ip_address=ip
        ))
        db.commit()
        raise HTTPException(
            status_code=423,
            detail="Account is temporarily locked due to multiple failed login attempts"
        )

    if verify_password(data.password, pwd.password_hash, pwd.password_salt):
        is_policy_compliant, policy_violations = validate_password_with_details(data.password)
        print(f"DEBUG SERVER: Policy compliant: {is_policy_compliant}")
        print(f"DEBUG SERVER: Policy violations: {policy_violations}")

        if not is_policy_compliant:
            cfg = get_password_config()
            policy_message = cfg.get("policy_message", {})
            requirements_parts = []
            if cfg["password_requirements"].get("uppercase"):
                requirements_parts.append("uppercase letters")
            if cfg["password_requirements"].get("lowercase"):
                requirements_parts.append("lowercase letters")
            if cfg["password_requirements"].get("digits"):
                requirements_parts.append("numbers")
            if cfg["password_requirements"].get("special"):
                requirements_parts.append("special characters")

            requirements_text = ", ".join(requirements_parts)
            requirements_msg = policy_message.get(
                "requirements_message",
                "Password must contain at least {min_length} characters including {requirements}. "
                "It cannot match common passwords or your previous {history_count} passwords."
            ).format(
                min_length=cfg["password_requirements"].get("min_length", 10),
                requirements=requirements_text,
                history_count=cfg["password_requirements"].get("history_count", 3)
            )

            main_message = policy_message.get(
                "non_compliant_message",
                "Your current password no longer meets our updated security policy. "
                "For your account security, please update your password now."
            )

            detail_response = {
                "message": f"{main_message} {requirements_msg}",
                "violations": policy_violations,
                "requires_password_change": True
            }

            db.add(UserEvent(
                user_id=user_obj.id,
                event_type=UserEventType.PASSWORD_POLICY_VIOLATION,
                description="Login with non-compliant password",
                ip_address=ip
            ))
            db.commit()

            raise HTTPException(status_code=426, detail=detail_response)

        handle_successful_login(pwd, user_obj, db, ip=ip)
        token_data = create_access_token(
            user_id=user_obj.id,
            username=user_obj.username,
            remember_me=data.remember_me
        )
        pwd.policy_checked_at = datetime.utcnow()
        db.add(pwd)
        db.commit()
        return {
            "message": "Login successful",
            "username": user_obj.username,
            **token_data
        }

    cfg = get_password_config()
    max_attempts = cfg["password_requirements"].get("max_login_attempts", 3)
    lockout_minutes = cfg["password_requirements"].get("lockout_duration_minutes", 15)
    handle_failed_login(pwd, max_attempts, lockout_minutes, db, user=user_obj, ip=ip)
    raise HTTPException(status_code=401, detail="Incorrect password")


@router.post("/change-password")
def change_password(data: ChangePasswordIn, db: Session = Depends(get_session)):
    """
    Change password for a user:
    - Verify current password.
    - Enforce "no reuse of last N passwords" (including the current one).
    - Archive the current password into PasswordHistory.
    - Update the single active password in `Password`.
    - Trim history to keep only the last N entries.
    """
    # 1) Load user and their single active password row
    user = db.exec(select(User).where(User.username == data.username)).first()
    is_valid, reasons = validate_password_with_details(data.new_password)
    if not is_valid:
        raise HTTPException(status_code=422, detail=reasons)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    pwd = db.exec(select(Password).where(Password.user_id == user.id)).first()
    if not pwd:
        raise HTTPException(status_code=404, detail="Password not found")

    # 2) Verify the provided current password
    if not verify_password(data.current_password, pwd.password_hash, pwd.password_salt):
        db.add(UserEvent(user_id=user.id, event_type=UserEventType.FAILED_LOGIN, description="Wrong current password"))
        db.commit()
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    # 3) History policy (N)
    cfg = get_password_config()
    history_n = cfg["password_requirements"].get("history_count", 3)

    # Fetch at most the last N history rows (most recent first)
    recent_hist = db.exec(
        select(PasswordHistory)
        .where(PasswordHistory.user_id == user.id)
        .order_by(PasswordHistory.created_at.desc())
        .limit(history_n)
    ).all()

    # Build a list of (hash, salt) to test reuse against:
    # include current active password + last N history items
    reuse_candidates = [(pwd.password_hash, pwd.password_salt)] + [
        (h.password_hash, h.password_salt) for h in recent_hist
    ]

    # 4) Reject if new password matches any candidate
    for old_hash, old_salt in reuse_candidates:
        if verify_password(data.new_password, old_hash, old_salt):
            raise HTTPException(status_code=400, detail="HISTORY_REUSE_ERROR")

    # 5) Archive the current active password into history (before updating it)
    db.add(PasswordHistory(
        user_id=user.id,
        password_hash=pwd.password_hash,
        password_salt=pwd.password_salt,
    ))

    # 6) Update the single active password
    new_digest, new_salt = hash_password(data.new_password)
    pwd.password_hash = new_digest
    pwd.password_salt = new_salt
    pwd.updated_at = datetime.utcnow()

    # 7) Trim history so only the last N remain
    extras = db.exec(
        select(PasswordHistory)
        .where(PasswordHistory.user_id == user.id)
        .order_by(PasswordHistory.created_at.desc())
        .offset(history_n)  # everything beyond the most recent N
    ).all()
    for e in extras:
        db.delete(e)

    # 8) Audit
    db.add(UserEvent(user_id=user.id, event_type=UserEventType.PASSWORD_CHANGE, description="Password changed"))

    db.commit()
    return {"detail": "Password changed successfully"}


@router.post("/forgot-password")
def forgot_password(data: ForgotPasswordIn, background_tasks: BackgroundTasks, db: Session = Depends(get_session)):
    user = db.exec(select(User).where(User.email == data.email)).first()
    if not user:
        return {"detail": "If the email exists in the system, a password reset token has been sent"}

    token = generate_reset_token()
    user.reset_token_sha1 = token
    user.reset_token_expires_at = datetime.utcnow() + timedelta(minutes=15)
    user.reset_token_used = False
    db.add(user)
    db.add(UserEvent(user_id=user.id, event_type=UserEventType.PASSWORD_RESET, description="Reset token generated"))
    db.commit()

    background_tasks.add_task(email_service.send_password_reset_email, user.email, token)
    return {"detail": "If the email exists in the system, a reset code was sent."}


@router.post("/reset-password")
def reset_password(data: ResetPasswordIn, db: Session = Depends(get_session)):
    """
    Reset password using a time-limited token stored on the user:
    - Validate reset token (exists, not used, not expired).
    - Enforce "no reuse of last N passwords" (including the current one).
    - Archive the current password (if exists) into PasswordHistory.
    - Update the single active password in `Password` (create if first-time).
    - Invalidate the reset token.
    - Trim history to keep only the last N entries.
    """
    # 1) Load user + check reset token validity
    user = db.exec(select(User).where(User.email == data.email)).first()
    is_valid, reasons = validate_password_with_details(data.new_password)
    if not is_valid:
        raise HTTPException(status_code=422, detail=reasons)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.reset_token_used or not user.reset_token_sha1 or user.reset_token_sha1 != data.token:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    if not user.reset_token_expires_at or user.reset_token_expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    # 2) Load (single) active password row if exists
    current_pwd = db.exec(select(Password).where(Password.user_id == user.id)).first()

    # 3) History policy (N)
    cfg = get_password_config()
    history_n = cfg["password_requirements"].get("history_count", 3)

    recent_hist = db.exec(
        select(PasswordHistory)
        .where(PasswordHistory.user_id == user.id)
        .order_by(PasswordHistory.created_at.desc())
        .limit(history_n)
    ).all()

    # Build candidates: current (if exists) + last N history
    reuse_candidates = []
    if current_pwd:
        reuse_candidates.append((current_pwd.password_hash, current_pwd.password_salt))
    reuse_candidates.extend((h.password_hash, h.password_salt) for h in recent_hist)

    for old_hash, old_salt in reuse_candidates:
        if verify_password(data.new_password, old_hash, old_salt):
            raise HTTPException(status_code=400, detail=f"Something went wrong")

    # 4) Archive current active password into history (if exists)
    if current_pwd:
        db.add(PasswordHistory(
            user_id=user.id,
            password_hash=current_pwd.password_hash,
            password_salt=current_pwd.password_salt,
        ))

    # 5) Update/create the single active password
    new_digest, new_salt = hash_password(data.new_password)
    if current_pwd:
        current_pwd.password_hash = new_digest
        current_pwd.password_salt = new_salt
        current_pwd.updated_at = datetime.utcnow()
    else:
        db.add(Password(user_id=user.id, password_hash=new_digest, password_salt=new_salt))

    # 6) Invalidate the reset token on the user
    user.reset_token_used = True
    user.reset_token_sha1 = None
    user.reset_token_expires_at = None
    db.add(user)

    # 7) Trim history down to last N
    extras = db.exec(
        select(PasswordHistory)
        .where(PasswordHistory.user_id == user.id)
        .order_by(PasswordHistory.created_at.desc())
        .offset(history_n)
    ).all()
    for e in extras:
        db.delete(e)

    # 8) Audit
    db.add(UserEvent(user_id=user.id, event_type=UserEventType.PASSWORD_RESET, description="Password reset completed"))

    db.commit()
    return {"detail": "Password reset successfully"}


@router.post("/refresh-token")
def refresh_token(current_user: User = Depends(get_current_user)):
    """Refresh the access token for authenticated user"""
    token_data = create_access_token(
        user_id=current_user.id,
        username=current_user.username,
        remember_me=False
    )
    return token_data


@router.get("/me")
def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information"""
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "last_login_at": current_user.last_login_at,
        "is_active": current_user.is_active
    }
