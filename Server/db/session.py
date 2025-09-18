# Server/db/session.py
import time
import logging
from sqlalchemy.exc import OperationalError
from sqlalchemy import text
from sqlmodel import SQLModel, Session, create_engine
import pymysql
from pymysql.cursors import DictCursor
from pymysql.constants import CLIENT
from ..settings import settings

logger = logging.getLogger(__name__)

# Create engine; connection is lazy until first use
engine = create_engine(
    settings.DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
    pool_recycle=3600,  # refresh stale connections
)

insecure_connection = pymysql.connect(host=settings.DB_HOST, user='root', password=settings.MYSQL_ROOT_PASSWORD,
                                      database=settings.DB_NAME, cursorclass=pymysql.cursors.DictCursor,
                                      client_flag=CLIENT.MULTI_STATEMENTS)


# Context manager ensures proper database session cleanup and prevents connection leaks
def get_session():
    with Session(engine) as session:
        yield session


def _wait_for_db_once() -> None:
    """Try a simple connection and SELECT 1 to verify DB is reachable."""
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))


def init_db(retries: int = 12, backoff_sec: int = 2) -> None:
    """
    Wait for the DB to be reachable, then create all tables.
    Retries with exponential backoff (total ~80s by default).
    """
    attempt = 0
    delay = backoff_sec
    last_err: Exception | None = None

    while attempt < retries:
        try:
            _wait_for_db_once()
            # DB reachable -> create schema and return
            SQLModel.metadata.create_all(engine)
            return
        except OperationalError as e:
            last_err = e
            logger.warning("DB not ready (attempt %d/%d): %s", attempt + 1, retries, str(e))
            time.sleep(delay)
            delay = min(delay * 2, 15)  # cap backoff
            attempt += 1

    # Exhausted retries
    msg = f"DB not available after {retries} attempts"
    if last_err:
        msg += f" | last error: {last_err}"
    raise RuntimeError(msg)
