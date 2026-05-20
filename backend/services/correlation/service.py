"""
ShieldNet — Correlation Engine
Groups detection events by source IP within a time window.
"""
from __future__ import annotations

import json
from datetime import timedelta

from sqlalchemy.orm import Session

from backend.db import models
from backend.utils.helpers import correlation_group_id, max_severity, utcnow_naive
from backend.core.config import settings
from backend.core.logging import get_logger

logger = get_logger("shieldnet.correlation")


def _get_involved_ips(group: models.CorrelationGroup) -> set[str]:
    """Deserialise the involved_ips JSON field."""
    if not group.involved_ips:
        return set()
    try:
        return set(json.loads(group.involved_ips))
    except (json.JSONDecodeError, TypeError):
        # Legacy: plain comma-separated string
        return {ip.strip() for ip in group.involved_ips.split(",") if ip.strip()}


def _set_involved_ips(group: models.CorrelationGroup, ips: set[str]) -> None:
    group.involved_ips = json.dumps(sorted(ips))


def get_or_create_correlation_group(
    db: Session, source_ip: str, severity: str
) -> str:
    """
    Find or create a correlation group for `source_ip`.
    Returns the group_id string.
    """
    window_start = utcnow_naive() - timedelta(
        minutes=settings.detection.CORRELATION_WINDOW_MINUTES
    )

    # Fetch recent groups and filter in Python (avoids unreliable LIKE on JSON)
    recent_groups = (
        db.query(models.CorrelationGroup)
        .filter(models.CorrelationGroup.last_seen >= window_start)
        .order_by(models.CorrelationGroup.last_seen.desc())
        .limit(200)
        .all()
    )

    matching_group = None
    for group in recent_groups:
        if source_ip in _get_involved_ips(group):
            matching_group = group
            break

    now = utcnow_naive()

    if matching_group:
        matching_group.last_seen = now
        matching_group.event_count += 1
        matching_group.max_severity = max_severity(
            severity, matching_group.max_severity or "low"
        )
        ips = _get_involved_ips(matching_group)
        ips.add(source_ip)
        _set_involved_ips(matching_group, ips)
        db.commit()
        logger.debug(
            f"Updated correlation group",
            extra={
                "group_id": matching_group.group_id,
                "source_ip": source_ip,
                "event_count": matching_group.event_count,
            },
        )
        return matching_group.group_id

    # Create new group
    gid = correlation_group_id(source_ip)
    new_group = models.CorrelationGroup(
        group_id=gid,
        first_seen=now,
        last_seen=now,
        event_count=1,
        max_severity=severity,
    )
    _set_involved_ips(new_group, {source_ip})
    db.add(new_group)
    db.commit()
    logger.info(
        f"New correlation group created",
        extra={"group_id": gid, "source_ip": source_ip, "severity": severity},
    )
    return gid


def assign_correlation(db: Session, incident: models.Incident) -> str:
    """Assign a correlation group to an incident in-place."""
    gid = get_or_create_correlation_group(db, incident.source_ip, incident.severity)
    incident.correlation_group_id = gid
    db.commit()
    return gid


def get_correlated_incidents(
    db: Session, group_id: str
) -> list[models.Incident]:
    return (
        db.query(models.Incident)
        .filter(models.Incident.correlation_group_id == group_id)
        .order_by(models.Incident.detected_at.asc())
        .all()
    )
