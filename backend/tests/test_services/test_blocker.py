"""
ShieldNet — Test IP Blocker Service
Verifies that IP blocking creates database records, invokes OS firewall commands,
and updates block state correctly.
"""
from __future__ import annotations

from unittest.mock import patch, MagicMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.db.database import Base
from backend.db import models
from backend.services.response.blocker import block_ip, unblock_ip, is_blocked


def test_ip_blocker_lifecycle():
    """
    Test block lifecycle:
    - Mock subprocess.run to prevent real OS firewall modification.
    - block_ip() creates a DB record and invokes subprocess.run.
    - is_blocked() returns True.
    - unblock_ip() marks DB record as unblocked and invokes subprocess.run.
    - is_blocked() returns False.
    """
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    
    db = TestingSessionLocal()
    
    # Target mock of subprocess.run inside blocker.py
    with patch("backend.services.response.blocker.subprocess.run") as mock_run:
        # Mock successful execution
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_run.return_value = mock_result
        
        test_ip = "198.51.100.12"
        reason = "Test Auto-block"
        blocked_by = "test_suite"
        
        # 1. Assert not blocked initially
        assert not is_blocked(db, test_ip)
        
        # 2. Block the IP
        record = block_ip(db, test_ip, blocked_by=blocked_by, reason=reason)
        assert record is not None
        assert record.ip_address == test_ip
        assert record.blocked_by == blocked_by
        assert record.reason == reason
        assert record.unblocked_at is None
        
        # Verify DB is updated and is_blocked is True
        assert is_blocked(db, test_ip)
        
        # Verify OS command was called
        assert mock_run.called
        # Check command args (should contain the IP)
        args, kwargs = mock_run.call_args
        cmd_list = args[0]
        assert test_ip in " ".join(cmd_list)
        
        # Reset mock call count
        mock_run.reset_mock()
        
        # 3. Unblock the IP
        unblock_ok = unblock_ip(db, test_ip)
        assert unblock_ok
        
        # Verify DB reflects unblock and is_blocked is False
        assert not is_blocked(db, test_ip)
        
        db_record = db.query(models.BlockedIP).filter(models.BlockedIP.ip_address == test_ip).first()
        assert db_record.unblocked_at is not None
        
        # Verify OS command was called to delete/unblock
        assert mock_run.called
        args, kwargs = mock_run.call_args
        cmd_list = args[0]
        assert test_ip in " ".join(cmd_list)
        
    db.close()
    Base.metadata.drop_all(bind=engine)
