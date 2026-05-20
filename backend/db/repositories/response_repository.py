from typing import List, Optional
from sqlalchemy.orm import Session
from backend.db import models

class ResponseRepository:
    @staticmethod
    def get_blocked_ips(db: Session) -> List[models.BlockedIP]:
        return db.query(models.BlockedIP).filter(models.BlockedIP.unblocked_at.is_(None)).order_by(models.BlockedIP.blocked_at.desc()).all()

    @staticmethod
    def get_total_blocked_count(db: Session) -> int:
        return db.query(models.BlockedIP).filter(models.BlockedIP.unblocked_at.is_(None)).count()

    @staticmethod
    def get_watch_endpoints(db: Session) -> List[models.WatchEndpoint]:
        return db.query(models.WatchEndpoint).all()

    @staticmethod
    def get_watch_endpoint_by_ip(db: Session, ip: str) -> Optional[models.WatchEndpoint]:
        return db.query(models.WatchEndpoint).filter(models.WatchEndpoint.src_ip == ip).first()

    @staticmethod
    def add_watch_endpoint(db: Session, endpoint_data: dict) -> models.WatchEndpoint:
        endpoint = models.WatchEndpoint(**endpoint_data)
        db.add(endpoint)
        return endpoint

    @staticmethod
    def reset_data(db: Session):
        db.query(models.BlockedIP).delete()
        db.query(models.WatchEndpoint).delete()
