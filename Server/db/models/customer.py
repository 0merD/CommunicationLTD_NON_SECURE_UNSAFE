from __future__ import annotations
from datetime import date
from typing import Optional
from sqlmodel import SQLModel, Field
from sqlmodel import Column, String, Integer, Boolean, Date

class Customer(SQLModel, table=True):
    __tablename__ = "customers"

    id: Optional[int] = Field(default=None, primary_key=True, index=True)
    full_name: str = Field(sa_column=Column(String(255), nullable=False))
    email: str = Field(sa_column=Column(String(191), unique=True, index=True, nullable=False))
    phone: str = Field(sa_column=Column(String(20), nullable=False))

    plan_id: Optional[int] = Field(default=None, foreign_key="plans.id")

    subscription_start_date: date = Field(default_factory=date.today, sa_column=Column(Date))
    active: bool = Field(default=True, sa_column=Column(Boolean, default=True))