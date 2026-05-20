from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from backend.core.config import settings


class Base(DeclarativeBase):
    pass


engine_kwargs = {
    "echo": settings.db.ECHO_SQL,
    "future": True,
}

if settings.db.URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    engine_kwargs["pool_size"] = settings.db.POOL_SIZE
    engine_kwargs["max_overflow"] = settings.db.MAX_OVERFLOW

engine = create_engine(settings.db.URL, **engine_kwargs)


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_all():
    from backend.db import models  # noqa: F401
    Base.metadata.create_all(bind=engine)


def health_check() -> str:
    try:
        from sqlalchemy import text
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return "connected"
    except Exception as exc:
        return f"error: {exc}"
