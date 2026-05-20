"""
ShieldNet — Demo Seed Data
When DEMO_MODE=true, pre-populates DB with realistic fake events
so the dashboard shows meaningful data without live network capture.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone

from backend.core.logging import get_logger
from backend.db.database import get_db

logger = get_logger("shieldnet.demo_seed")

DEMO_IPS = ["185.220.101.45", "193.32.127.81", "45.155.205.225", "91.108.4.0", "198.98.55.110"]
ATTACK_TYPES = ["PortScan", "BruteForce", "DDoS", "WebAttack", "Bot"]
STEG_FILES = ["marketing_photo.jpg", "promo_video.mp4", "invoice_scan.png", "company_logo.webp"]


def seed_demo_data() -> None:
    """Insert 50 incidents and 20 steg scans for demo mode."""
    try:
        from backend.db.models import Incident, StegScan, HoneypotLog, BlockedIP
        for db in get_db():
            # Only seed if empty
            existing = db.query(Incident).count()
            if existing > 0:
                logger.info("Demo DB already has data — skipping seed")
                return

            now = datetime.now(timezone.utc)
            for i in range(50):
                ip = random.choice(DEMO_IPS)
                at = random.choice(ATTACK_TYPES)
                conf = round(random.uniform(0.70, 0.98), 3)
                db.add(Incident(
                    incident_uid=f"seed-{i}",
                    timestamp=now - timedelta(minutes=random.randint(0, 120)),
                    source_ip=ip,
                    pipeline="A",
                    pipeline_primary="idps",
                    attack_type=at,
                    media_type=None,
                    confidence=conf,
                    severity="critical" if conf > 0.85 else "high",
                    explanation=f"Demo: {at} from {ip} (confidence={conf})",
                    blocked=conf > 0.85,
                ))

            for j in range(20):
                filename = random.choice(STEG_FILES)
                conf = round(random.uniform(0.72, 0.96), 3)
                media_type = "video" if filename.endswith(".mp4") else "image"
                alg_scores = {
                    "chi_square": round(random.uniform(0.6, 0.95), 3),
                    "sample_pair": round(random.uniform(0.5, 0.90), 3),
                    "rs_analysis": round(random.uniform(0.55, 0.92), 3),
                    "dct_histogram": round(random.uniform(0.7, 0.98), 3),
                    "pixel_histogram": round(random.uniform(0.4, 0.85), 3),
                    "noise_residual": round(random.uniform(0.5, 0.88), 3),
                    "benfords_law": round(random.uniform(0.45, 0.87), 3),
                }
                
                inc = Incident(
                    incident_uid=f"steg-seed-{j}",
                    timestamp=now - timedelta(minutes=random.randint(0, 120)),
                    source_ip=random.choice(DEMO_IPS),
                    pipeline="B",
                    pipeline_primary="steg",
                    attack_type=f"{media_type}_steg",
                    media_type=media_type,
                    confidence=conf,
                    severity="critical" if conf > 0.85 else "high",
                    explanation=f"Demo: {media_type} steg (confidence={conf})",
                    blocked=conf > 0.85,
                )
                db.add(inc)
                db.flush()
                
                db.add(StegScan(
                    incident_id=inc.id,
                    filename=filename,
                    file_size=random.randint(200_000, 5_000_000),
                    source_ip=inc.source_ip,
                    media_type=media_type,
                    confidence=conf,
                    algorithm_detected="dct_histogram",
                    forensic_json=json.dumps({
                        "filename": filename, "confidence_score": conf,
                        "severity": "critical", "algorithm_scores": alg_scores,
                        "estimated_payload_bytes": random.randint(5000, 50000),
                        "probable_tool": "F5/OutGuess",
                    }),
                ))

            db.commit()
            logger.info("Demo data seeded successfully.")
            break
    except Exception as exc:
        logger.error(f"Demo seed failed: {exc}")

if __name__ == "__main__":
    seed_demo_data()
