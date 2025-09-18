from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Optional

from sqlmodel import SQLModel, Field, Column, String, Integer, DateTime, Text
from sqlalchemy import text
from sqlalchemy import Enum as SAEnum


class UserEventType(str, Enum):
    """
    Allowed event types for auditing user actions.
    Stored as VARCHAR via SQLAlchemy Enum with string values.
    """
    CREATE_USER = "CREATE_USER"
    DELETE_USER = "DELETE_USER"
    LOGIN = "LOGIN"
    LOGOUT = "LOGOUT"
    FAILED_LOGIN = "FAILED_LOGIN"
    LOCKOUT = "LOCKOUT"
    PASSWORD_CHANGE = "PASSWORD_CHANGE"
    PASSWORD_RESET = "PASSWORD_RESET"
    PASSWORD_POLICY_VIOLATION = "PASSWORD_POLICY_VIOLATION"


class UserEvent(SQLModel, table=True):
    """
    Audit log for user-related events.
    """
    __tablename__ = "user_events"

    id: Optional[int] = Field(default=None, primary_key=True, index=True)
    user_id: int = Field(foreign_key="users.id", nullable=False)

    # Persist enum as VARCHAR (not native DB enum) for portability
    event_type: UserEventType = Field(sa_column=Column(SAEnum(UserEventType), nullable=False))

    description: Optional[str] = Field(default=None, sa_column=Column(Text))
    value: Optional[str] = Field(default=None, sa_column=Column(String(255)))
    ip_address: Optional[str] = Field(default=None, sa_column=Column(String(45)))

    date: datetime = Field(sa_column=Column(DateTime, server_default=text("CURRENT_TIMESTAMP"), nullable=False))