# Server/db/init_db.py
"""
Database initialization script for CommunicationLTD project.
Creates initial data including sample plans and an admin user.
Run as:  python -m Server.db.init_db   (from project root)
"""

from datetime import datetime
import hmac, hashlib, os as os_module
from typing import List

from sqlmodel import Session, select

# --- Relative imports within the package ---
from .session import engine, init_db
from .models.user import User
from .models.password import Password
from .models.plan import Plan
from .models.customer import Customer
from .models.user_event import UserEvent, UserEventType
from ..core.password_validator import setup_password_validation


def _hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    """Hash password using HMAC-SHA256 + per-user salt (project requirement)."""
    salt = salt or os_module.urandom(32)
    digest = hmac.new(salt, password.encode("utf-8"), hashlib.sha256).hexdigest()
    return digest, salt.hex()


def create_sample_plans(session: Session) -> None:
    plans_data = [
        {"name": "Basic Home", "download_speed_mbps": 50, "upload_speed_mbps": 10, "price": 39.99},
        {"name": "Family Plus", "download_speed_mbps": 100, "upload_speed_mbps": 20, "price": 59.99},
        {"name": "Premium Unlimited", "download_speed_mbps": 300, "upload_speed_mbps": 50, "price": 89.99},
        {"name": "Business Essential", "download_speed_mbps": 200, "upload_speed_mbps": 100, "price": 149.99},
        {"name": "Enterprise Pro", "download_speed_mbps": 1000, "upload_speed_mbps": 500, "price": 299.99},
    ]
    for data in plans_data:
        if not session.exec(select(Plan).where(Plan.name == data["name"])).first():
            session.add(Plan(**data))
    session.commit()


def create_admin_user(session: Session) -> User:
    admin_username = "admin"
    admin_email = "admin@communicationltd.com"
    admin_password = "AdminPass123!"
    existing = session.exec(select(User).where(User.username == admin_username)).first()
    if existing:
        return existing

    user = User(username=admin_username, email=admin_email, created_at=datetime.utcnow())
    session.add(user);
    session.commit();
    session.refresh(user)

    digest, salt_hex = _hash_password(admin_password)
    session.add(Password(user_id=user.id, password_hash=digest, password_salt=salt_hex));
    session.commit()

    session.add(UserEvent(user_id=user.id, event_type=UserEventType.CREATE_USER,
                          description="Initial admin user created"));
    session.commit()
    return user


def create_sample_customers(session: Session, plans: List[Plan]) -> None:
    if not plans:
        return
    samples = [
        {"full_name": "John Smith", "email": "john.smith@email.com", "phone": "+1-555-0101", "plan_id": plans[0].id},
        {"full_name": "Sarah Johnson", "email": "sarah.j@email.com", "phone": "+1-555-0202", "plan_id": plans[1].id},
        {"full_name": "Tech Solutions Ltd", "email": "contact@techsolutions.com", "phone": "+1-555-0303",
         "plan_id": plans[3].id},
    ]
    for data in samples:
        if not session.exec(select(Customer).where(Customer.email == data["email"])).first():
            session.add(Customer(**data))
    session.commit()


def main() -> None:
    print("Initializing CommunicationLTD database")
    setup_password_validation()
    init_db()

    with Session(engine) as session:
        create_sample_plans(session)
        create_admin_user(session)
        plans = session.exec(select(Plan)).all()
        create_sample_customers(session, plans)

    print("Database initialization completed")


if __name__ == "__main__":
    main()
