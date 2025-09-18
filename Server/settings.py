import os
from typing import List


class Settings:
    """
    Centralized application settings loaded from environment variables.
    Uses os.getenv only; simple and container-friendly.
    """

    # App
    APP_NAME: str = os.getenv("APP_NAME", "CommunicationLTD")
    APP_VERSION: str = os.getenv("APP_VERSION", "1.0.0")
    SECRET_KEY: str = os.getenv("SECRET_KEY")

    # CORS
    _cors = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000")
    CORS_ORIGINS: List[str] = [o.strip() for o in _cors.split(",") if o.strip()]

    # Database (MySQL)
    DB_HOST: str = os.getenv("DB_HOST", os.getenv("DATABASE_HOST", "db"))
    DB_PORT: str = os.getenv("DB_PORT", os.getenv("DATABASE_PORT", "3306"))
    DB_USER: str = os.getenv("DB_USER", os.getenv("DATABASE_USER"))
    DB_PASSWORD: str = os.getenv("DB_PASSWORD", os.getenv("DATABASE_PASSWORD"))
    DB_NAME: str = os.getenv("DB_NAME", os.getenv("DATABASE_NAME", "CommunicationLTD"))
    DB_CHARSET: str = os.getenv("DB_CHARSET", "utf8mb4")
    MYSQL_ROOT_PASSWORD: str = os.getenv("MYSQL_ROOT_PASSWORD", "rootpassword")

    @property
    def DATABASE_URL(self) -> str:
        """
        Build SQLAlchemy URL for PyMySQL driver.
        If DATABASE_URL is provided explicitly in the environment, prefer it.
        """
        env_url = os.getenv("DATABASE_URL")
        if env_url:
            return env_url
        return (
            f"mysql+pymysql://{self.DB_USER}:{self.DB_PASSWORD}"
            f"@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}?charset={self.DB_CHARSET}"
        )

    # Email
    SMTP_SERVER: str = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SENDER_EMAIL: str = os.getenv("SENDER_EMAIL", "noreply@communicationltd.com")
    SENDER_PASSWORD: str = os.getenv("SENDER_PASSWORD")
    SENDER_NAME: str = os.getenv("SENDER_NAME", "Communication LTD")
    USE_TLS: bool = os.getenv("USE_TLS", "true").lower() == "true"

    # Config files location for password policy
    CONFIG_DIR: str = os.getenv("CONFIG_DIR", "./config")
    PASSWORD_POLICY_FILE: str = os.getenv("PASSWORD_POLICY_FILE", "password_policy.yaml")


settings = Settings()
