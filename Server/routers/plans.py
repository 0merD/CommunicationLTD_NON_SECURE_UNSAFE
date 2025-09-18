from fastapi import APIRouter, Depends
from typing import List
from sqlmodel import Session, select

from ..db.session import get_session
from ..db.models.plan import Plan
from ..core.jwt_handler import get_current_user
from ..db.models.user import User

router = APIRouter(prefix="/api/v1/plans", tags=["plans"])


@router.get("", response_model=List[Plan])
def list_plans(current_user: User = Depends(get_current_user), db: Session = Depends(get_session)):
    return db.exec(select(Plan)).all()
