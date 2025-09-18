from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlmodel import Session, select

from ..db.models import Password
from ..settings import settings
from ..db.session import get_session
from ..db.models.user import User

security = HTTPBearer()

# JWT Configuration
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REMEMBER_TOKEN_EXPIRE_DAYS = 30


def create_access_token(user_id: int, username: str, remember_me: bool = False) -> dict:
    """Create JWT token with expiration based on remember_me flag"""
    if remember_me:
        expire = datetime.utcnow() + timedelta(days=REMEMBER_TOKEN_EXPIRE_DAYS)
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    payload = {
        "sub": str(user_id),  # subject (user ID)
        "username": username,
        "exp": expire,
        "iat": datetime.utcnow(),  # issued at
        "remember": remember_me
    }

    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": int((expire - datetime.utcnow()).total_seconds()),
        "remember_me": remember_me
    }


def verify_token(token: str) -> Optional[dict]:
    """JWT token validation with secure algorithm prevents token manipulation attacks"""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


def get_current_user(
        credentials: HTTPAuthorizationCredentials = Depends(security),
        db: Session = Depends(get_session)
) -> User:
    """Dependency to get current authenticated user"""
    token = credentials.credentials
    payload = verify_token(token)

    if payload is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"}
        )

    try:
        user_id = int(payload.get("sub"))
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=401,
            detail="Invalid token format",
            headers={"WWW-Authenticate": "Bearer"}
        )

    user = db.exec(select(User).where(User.id == user_id)).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=401,
            detail="User not found or inactive",
            headers={"WWW-Authenticate": "Bearer"}
        )
    password_record = db.exec(select(Password).where(Password.user_id == user.id)).first()
    if password_record:

        policy_check_required = (
                not hasattr(password_record, 'policy_checked_at') or
                password_record.policy_checked_at is None or
                password_record.policy_checked_at < datetime.utcnow() - timedelta(hours=24)
        )

        if policy_check_required:
            raise HTTPException(
                status_code=426,  # Upgrade Required
                detail={
                    "message": "Your password policy compliance needs to be verified. Please log in again.",
                    "requires_password_check": True
                },
                headers={"WWW-Authenticate": "Bearer"}
            )

    return user


# Optional: Dependency for endpoints that don't require authentication
def get_current_user_optional(
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
        db: Session = Depends(get_session)
) -> Optional[User]:
    """Optional authentication - returns None if no token provided"""
    if not credentials:
        return None

    try:
        return get_current_user(credentials, db)
    except HTTPException:
        return None
