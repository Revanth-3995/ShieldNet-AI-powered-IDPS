"""
ShieldNet IP Blocking Service.
Manages OS-level firewall blocks (iptables on Linux, netsh on Windows)
and shared blocked_ips table for proxy enforcement.
"""
from __future__ import annotations

import platform
import subprocess
from datetime import datetime
from sqlalchemy.orm import Session

from backend.core.logging import get_logger
from backend.db import models

logger = get_logger("shieldnet.blocker")
OS = platform.system()


def _run_cmd(cmd: list[str]) -> bool:
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=5)
        return result.returncode == 0
    except Exception as e:
        logger.warning(f"Firewall command failed: {e}")
        return False


def block_ip_firewall(ip: str) -> bool:
    """Block IP at OS firewall level. Attacker receives no response."""
    if OS == "Linux":
        ok = _run_cmd(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        if ok:
            logger.info(f"[iptables] Blocked {ip}")
        return ok
    elif OS == "Windows":
        ok = _run_cmd([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name=ShieldNet_Block_{ip}", "dir=in", "action=block",
            f"remoteip={ip}"
        ])
        if ok:
            logger.info(f"[netsh] Blocked {ip}")
        return ok
    else:
        logger.warning(f"[blocker] Unsupported OS '{OS}' — skipping firewall block for {ip}")
        return False


def unblock_ip_firewall(ip: str) -> bool:
    if OS == "Linux":
        return _run_cmd(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
    elif OS == "Windows":
        return _run_cmd([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name=ShieldNet_Block_{ip}"
        ])
    return False


def block_ip(db: Session, ip: str, blocked_by: str, reason: str) -> models.BlockedIP:
    """Record IP block in DB and apply OS-level firewall rule."""
    existing = db.query(models.BlockedIP).filter(models.BlockedIP.ip_address == ip).first()
    if existing and existing.unblocked_at is None:
        logger.info(f"{ip} already blocked")
        return existing

    block_ip_firewall(ip)

    if existing:
        existing.unblocked_at = None
        existing.blocked_at = datetime.utcnow()
        existing.blocked_by = blocked_by
        existing.reason = reason
        db.commit()
        return existing

    record = models.BlockedIP(
        ip_address=ip,
        blocked_by=blocked_by,
        reason=reason,
        blocked_at=datetime.utcnow(),
        both_pipelines=True,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    logger.info(f"[DB] Blocked IP recorded: {ip} ({blocked_by})")
    return record


def unblock_ip(db: Session, ip: str) -> bool:
    record = db.query(models.BlockedIP).filter(models.BlockedIP.ip_address == ip).first()
    if record:
        record.unblocked_at = datetime.utcnow()
        db.commit()
    unblock_ip_firewall(ip)
    return True


def is_blocked(db: Session, ip: str) -> bool:
    record = db.query(models.BlockedIP).filter(
        models.BlockedIP.ip_address == ip,
        models.BlockedIP.unblocked_at.is_(None),
    ).first()
    return record is not None
