"""
ShieldNet — Database Initialization
"""
from backend.core.logging import get_logger
from backend.db.database import engine, Base
from backend.db import models

logger = get_logger("shieldnet.db.init")

def init_db():
    logger.info("Initializing database schema...")
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database schema initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise

if __name__ == "__main__":
    init_db()
