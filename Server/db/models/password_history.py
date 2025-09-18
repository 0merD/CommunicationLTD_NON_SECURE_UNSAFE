from __future__ import annotations
from datetime import datetime
from typing import Optional

from sqlmodel import SQLModel, Field, Column, String, DateTime


class PasswordHistory(SQLModel, table=True):
    """
    Stores previous passwords per user to enforce password history policy.
    Each row is an *old* password (hash + salt) with when it became history.
    The active/current password lives in the `Password` table (one row per user).
    """
    __tablename__ = "password_history"

    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id", nullable=False)

    # Hex-encoded materials (e.g., HMAC-SHA256 64-hex chars)
    password_hash: str = Field(sa_column=Column(String(64), nullable=False))
    password_salt: str = Field(sa_column=Column(String(64), nullable=False))

    # When the password was archived into history
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, nullable=False))

