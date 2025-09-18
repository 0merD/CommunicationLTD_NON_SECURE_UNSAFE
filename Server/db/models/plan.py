from __future__ import annotations
from typing import Optional
from decimal import Decimal
from sqlmodel import SQLModel, Field
from sqlmodel import Column, String, Integer
from sqlalchemy import DECIMAL
from pydantic import field_serializer


class Plan(SQLModel, table=True):
    __tablename__ = "plans"

    id: Optional[int] = Field(default=None, primary_key=True, index=True)
    name: str = Field(sa_column=Column(String(100), nullable=False))
    upload_speed_mbps: int = Field(sa_column=Column(Integer, nullable=False))
    download_speed_mbps: int = Field(sa_column=Column(Integer, nullable=False))
    price: Decimal = Field(sa_column=Column(DECIMAL(10, 2), nullable=False))

    @field_serializer('price')
    def serialize_price(self, value: Decimal) -> float:
        return float(value)