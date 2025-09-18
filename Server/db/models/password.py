from __future__ import annotations
from datetime import datetime
from typing import Optional

from sqlmodel import SQLModel, Field, Relationship, Column, Integer, String, DateTime, Boolean, text
from sqlalchemy import UniqueConstraint


class Password(SQLModel, table=True):
    """
    Stores user's password data (HMAC-SHA256 + Salt) and lockout/reset metadata.
    One row per user; uniqueness is enforced by a UNIQUE constraint on user_id.
    """
    __tablename__ = "passwords"
    __table_args__ = (
        UniqueConstraint("user_id", name="uq_passwords_user_id"),
    )

    id: Optional[int] = Field(default=None, primary_key=True, index=True)
    user_id: int = Field(foreign_key="users.id", nullable=False)

    # Password material (hex-encoded)
    password_hash: str = Field(sa_column=Column(String(64), nullable=False))    # SHA-256 hex = 64 chars
    password_salt: str = Field(sa_column=Column(String(64), nullable=False))    # 32 bytes hex = 64 chars

    # Lockout mechanism
    failed_logins: int = Field(default=0, sa_column=Column(Integer, default=0))
    last_failed_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime))
    lockout_until: Optional[datetime] = Field(default=None, sa_column=Column(DateTime))
    is_locked: bool = Field(default=False, sa_column=Column(Boolean, default=False))

    # Password reset tokens (project uses SHA-1)
    reset_token_sha1: Optional[str] = Field(default=None, sa_column=Column(String(40)))
    reset_token_expires_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime))
    reset_token_used: bool = Field(default=False, sa_column=Column(Boolean, default=False))

    # Audit
    created_at: datetime = Field(sa_column=Column(DateTime, server_default=text("CURRENT_TIMESTAMP"), nullable=False))
    updated_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime, onupdate=datetime.utcnow))
    policy_checked_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime))
