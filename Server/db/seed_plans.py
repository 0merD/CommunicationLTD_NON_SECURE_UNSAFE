from sqlmodel import Session, select
from .session import engine
from .models.plan import Plan


def seed_plans():
    plans_data = [
        {"id": 1, "name": "Basic", "upload_speed_mbps": 10, "download_speed_mbps": 50, "price": 49.90},
        {"id": 2, "name": "Standard", "upload_speed_mbps": 50, "download_speed_mbps": 200, "price": 79.90},
        {"id": 3, "name": "Pro", "upload_speed_mbps": 100, "download_speed_mbps": 500, "price": 119.90},
        {"id": 4, "name": "Business", "upload_speed_mbps": 500, "download_speed_mbps": 1000, "price": 249.90},
        {"id": 5, "name": "Enterprise", "upload_speed_mbps": 1000, "download_speed_mbps": 2000, "price": 499.90},
    ]

    with Session(engine) as session:
        for pdata in plans_data:
            existing = session.exec(select(Plan).where(Plan.id == pdata["id"])).first()
            if not existing:
                plan = Plan(**pdata)
                session.add(plan)
        session.commit()
        print(" Plans seeded successfully.")


if __name__ == "__main__":
    seed_plans()
