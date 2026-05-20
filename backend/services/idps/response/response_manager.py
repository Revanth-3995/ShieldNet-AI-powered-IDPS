"""
ShieldNet — IDPS Response Manager
Orchestrates automated responses based on detection severity.
"""
from typing import Dict, Any
from backend.core.logging import get_logger
from backend.services.response.blocker import block_ip

logger = get_logger("shieldnet.idps.response")

class ResponseManager:
    def __init__(self, db_session_factory):
        self.db_session_factory = db_session_factory

    async def handle_detection(self, detection: Dict[str, Any]):
        """Decide and execute automated response with escalating logic."""
        src_ip = detection.get("source_ip")
        confidence = detection.get("confidence", 0)
        severity = detection.get("severity", "low")
        attack_type = detection.get("attack_type")
        fusion_data = detection.get("fusion_data", {})

        logger.info(f"Escalating response check for {src_ip} (Severity: {severity})")

        # 1. Critical Attacks -> Permanent Block
        if severity == "critical" and confidence > 0.8:
            self._execute_block(src_ip, f"Critical {attack_type}", duration_hours=0) # 0 = Perm
            
        # 2. High Severity -> Temporary Block (24h)
        elif severity == "high" and confidence > 0.7:
            self._execute_block(src_ip, f"High-risk {attack_type}", duration_hours=24)
            
        # 3. Medium Severity -> Quarantine / Rate Limit
        elif severity == "medium" and confidence > 0.5:
            logger.info(f"Quarantining {src_ip} for suspicious behavioral patterns.")
            # Logic for rate limiting or restricted access would go here
            self._execute_block(src_ip, f"Suspicious activity ({attack_type})", duration_hours=1)

    def _execute_block(self, ip: str, reason: str, duration_hours: int = 0):
        # Prevent accidental blocking of critical infrastructure
        WHITELIST = ["127.0.0.1", "192.168.1.1"]
        if ip in WHITELIST:
            logger.warning(f"Blocking aborted: {ip} is in system whitelist.")
            return

        with self.db_session_factory() as db:
            block_ip(db, ip, "idps", reason)
            # Future: add duration handling to block_ip
