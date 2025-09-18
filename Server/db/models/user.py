from __future__ import annotations
from datetime import datetime
from typing import List, Optional

from sqlmodel import SQLModel, Field, Relationship, Column, String, DateTime, Boolean, text

# SQLModel ORM automatically provides SQL injection protection through parameterized queries

class User(SQLModel, table=True):
    """
    User model for storing user account data.
    Notes:
    - reset token fields are kept here per project requirements (SHA-1 hex length = 40).
    - relationships use SQLModel.Relationship, additional SA args go in sa_relationship_kwargs.
    """
    __tablename__ = "users"

    id: Optional[int] = Field(default=None, primary_key=True, index=True)
    username: str = Field(sa_column=Column(String(50), unique=True, index=True, nullable=False))
    email: str = Field(sa_column=Column(String(191), unique=True, index=True, nullable=False))  # 191 for MySQL utf8mb4

    # Audit timestamps
    created_at: datetime = Field(sa_column=Column(DateTime, server_default=text("CURRENT_TIMESTAMP"), nullable=False))
    last_login_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime))

    # Password reset (project requires SHA-1)
    reset_token_sha1: Optional[str] = Field(default=None, sa_column=Column(String(40)))
    reset_token_expires_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime))
    reset_token_used: bool = Field(default=False, sa_column=Column(Boolean, default=False))

    # Account status
    is_active: bool = Field(default=True, sa_column=Column(Boolean, default=True))