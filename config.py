"""Application configuration. Secrets come from the environment, never from code."""
import os
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def _csv(name: str) -> list[str]:
    return [v.strip().lower() for v in os.environ.get(name, "").split(",") if v.strip()]


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY")

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{(BASE_DIR / 'instance' / 'voicebox.db').as_posix()}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session cookie: not readable by scripts, not sent on cross-site requests.
    SESSION_COOKIE_NAME = "vb_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)  # idle timeout
    SESSION_ABSOLUTE_LIFETIME = timedelta(hours=8)      # forced re-login

    WTF_CSRF_TIME_LIMIT = 3600
    # Uploads live outside the web root and are only served through an authorised route.
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", str(BASE_DIR / "instance" / "uploads"))
    MAX_UPLOAD_BYTES = 5 * 1024 * 1024
    MAX_CONTENT_LENGTH = 6 * 1024 * 1024  # hard cap on any request body

    # Account lockout
    MAX_FAILED_LOGINS = 5
    LOCKOUT_PERIOD = timedelta(minutes=15)

    RATELIMIT_STORAGE_URI = "memory://"
    RATELIMIT_HEADERS_ENABLED = True

    ALLOWED_EMAIL_DOMAINS = _csv("ALLOWED_EMAIL_DOMAINS")


class DevelopmentConfig(Config):
    pass


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_NAME = "__Host-vb_session"


class TestingConfig(Config):
    TESTING = True
    SECRET_KEY = "testing-only-not-a-secret"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    RATELIMIT_ENABLED = False


CONFIGS = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}


def get_config(name: str | None = None) -> type[Config]:
    name = name or os.environ.get("APP_ENV", "development")
    try:
        return CONFIGS[name]
    except KeyError:
        raise RuntimeError(f"Unknown APP_ENV '{name}'") from None
