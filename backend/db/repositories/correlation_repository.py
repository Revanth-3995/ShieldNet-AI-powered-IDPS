from typing import List
from sqlalchemy.orm import Session
from backend.db import models

class CorrelationRepository:
    @staticmethod
    def get_correlations(db: Session, limit: int = 50) -> List[models.CorrelationGroup]:
        return db.query(models.CorrelationGroup).order_by(models.CorrelationGroup.last_seen.desc()).limit(limit).all()

    @staticmethod
    def get_total_count(db: Session) -> int:
        return db.query(models.CorrelationGroup).count()

    @staticmethod
    def reset_data(db: Session):
        db.query(models.CorrelationGroup).delete()
