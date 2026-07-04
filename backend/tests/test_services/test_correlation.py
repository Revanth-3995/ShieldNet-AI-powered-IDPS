"""
ShieldNet — Test Correlation Engine
Verifies that detection events are grouped within a time window,
and a new group is created when events occur outside the window.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.db.database import Base
from backend.db import models
from backend.services.correlation.service import assign_correlation


def test_incident_correlation_window():
    """
    Test correlation:
    - 2 incidents within window get the same correlation_group_id.
    - 3rd incident outside window gets a new correlation_group_id.
    """
    # Create in-memory SQLite database for testing
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    
    db = TestingSessionLocal()
    try:
        source_ip = "192.168.10.45"
        
        # 1. Create first incident
        inc1 = models.Incident(
            incident_uid="uid-1",
            timestamp=datetime.utcnow(),
            source_ip=source_ip,
            pipeline="A",
            pipeline_primary="idps",
            attack_type="DoS",
            confidence=0.90,
            severity="high",
            detected_at=datetime.utcnow()
        )
        db.add(inc1)
        db.commit()
        
        gid1 = assign_correlation(db, inc1)
        assert gid1 is not None
        assert inc1.correlation_group_id == gid1
        
        # Verify group is created in DB
        group1 = db.query(models.CorrelationGroup).filter(models.CorrelationGroup.group_id == gid1).first()
        assert group1 is not None
        assert group1.event_count == 1
        
        # 2. Create second incident from same IP within window
        inc2 = models.Incident(
            incident_uid="uid-2",
            timestamp=datetime.utcnow(),
            source_ip=source_ip,
            pipeline="A",
            pipeline_primary="idps",
            attack_type="BruteForce",
            confidence=0.50,
            severity="medium",
            detected_at=datetime.utcnow()
        )
        db.add(inc2)
        db.commit()
        
        gid2 = assign_correlation(db, inc2)
        assert gid2 == gid1  # Should belong to the same correlation group
        assert inc2.correlation_group_id == gid1
        
        # Verify group state
        db.refresh(group1)
        assert group1.event_count == 2
        
        # 3. Simulate passage of time (shift the group's last_seen outside the window)
        # The correlation window is read from settings (usually 30 minutes)
        from backend.core.config import settings
        window_mins = settings.detection.CORRELATION_WINDOW_MINUTES
        
        # Move group's last_seen to be 2 * window_mins ago
        past_time = datetime.utcnow() - timedelta(minutes=2 * window_mins)
        group1.last_seen = past_time
        db.commit()
        
        # 4. Create third incident from same IP (outside the window now)
        inc3 = models.Incident(
            incident_uid="uid-3",
            timestamp=datetime.utcnow(),
            source_ip=source_ip,
            pipeline="B",
            pipeline_primary="steg",
            attack_type="image_steg_detected",
            confidence=0.95,
            severity="high",
            detected_at=datetime.utcnow()
        )
        db.add(inc3)
        db.commit()
        
        gid3 = assign_correlation(db, inc3)
        assert gid3 is not None
        assert gid3 != gid1  # Should create a NEW correlation group
        assert inc3.correlation_group_id == gid3
        
        # Verify new group exists
        group2 = db.query(models.CorrelationGroup).filter(models.CorrelationGroup.group_id == gid3).first()
        assert group2 is not None
        assert group2.event_count == 1
        
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
