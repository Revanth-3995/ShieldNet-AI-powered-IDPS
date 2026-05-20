from typing import List
from sqlalchemy.orm import Session
from backend.db import models

class HoneypotRepository:
    @staticmethod
    def create_log(db: Session, log_data: dict) -> models.HoneypotLog:
        log = models.HoneypotLog(**log_data)
        db.add(log)
        db.commit()
        return log

    @staticmethod
    def get_logs(db: Session, limit: int = 100) -> List[models.HoneypotLog]:
        return db.query(models.HoneypotLog).order_by(models.HoneypotLog.timestamp.desc()).limit(limit).all()

    @staticmethod
    def get_total_count(db: Session) -> int:
        return db.query(models.HoneypotLog).count()

    @staticmethod
    def reset_data(db: Session):
        db.query(models.HoneypotLog).delete()
