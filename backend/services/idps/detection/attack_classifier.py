"""
ShieldNet — IDPS Attack Classifier & Fusion Engine
Combines Rule, ML, and Sequence outputs with behavioral reputation.
"""
from typing import Dict, Any, List, Tuple, Optional
import numpy as np
from backend.core.logging import get_logger

logger = get_logger("shieldnet.idps.fusion")

class FusionEngine:
    # Class-specific reliability weights
    RELIABILITY_WEIGHTS = {
        "PortScan": 0.8,
        "DoS": 0.75,
        "BruteForce": 0.85,
        "WebAttack": 0.9,
        "Benign": 1.0
    }

    def __init__(self):
        self.reputation_cache = {}
        self.smoothing_cache = {}
        self.MAX_SMOOTHING_WINDOW = 5

    def update_reputation(self, ip: str, attack_confidence: float):
        """Escalating reputation score with time-based decay."""
        if ip not in self.reputation_cache:
            self.reputation_cache[ip] = {"score": 0.0, "hits": 0, "last_seen": time.time()}
        
        now = time.time()
        time_diff = now - self.reputation_cache[ip]["last_seen"]
        decay = np.exp(-time_diff / 3600)
        
        current_score = self.reputation_cache[ip]["score"] * decay
        self.reputation_cache[ip]["score"] = min(current_score + (attack_confidence * 0.15), 1.0)
        self.reputation_cache[ip]["hits"] += 1
        self.reputation_cache[ip]["last_seen"] = now

    def fuse_results(self, 
                     rule_hit: Optional[Dict], 
                     ml_hit: Tuple[str, float], 
                     seq_hit: Tuple[str, float], 
                     ip: str) -> Dict[str, Any]:
        """
        Calibrated Hybrid Fusion.
        Handles detector disagreement and filters noise through temporal smoothing.
        """
        ml_class, ml_conf = ml_hit
        seq_class, seq_conf = seq_hit
        
        # 1. Base Scores & Weights
        scores, weights = [], []
        
        # Heuristic Layer (High priority if matched)
        if rule_hit:
            w = self.RELIABILITY_WEIGHTS.get(rule_hit["attack_type"], 0.7)
            weights.append(w)
            scores.append(rule_hit["confidence"])
        
        # Behavioral Layer (XGBoost)
        if ml_class != "Benign":
            w = self.RELIABILITY_WEIGHTS.get(ml_class, 0.5) * (1.2 if ml_class == seq_class else 0.8)
            weights.append(w)
            scores.append(ml_conf)
            
        # Temporal Layer (Sequence)
        if seq_class != "Benign":
            w = self.RELIABILITY_WEIGHTS.get(seq_class, 0.4)
            weights.append(w)
            scores.append(seq_conf)

        if not scores:
            return {"attack_type": "Benign", "confidence": 0.0, "severity": "info"}

        # 2. Weighted Aggregation
        raw_conf = float(np.average(scores, weights=weights))
        
        # 3. Contextual Noise Smoothing
        if ip not in self.smoothing_cache: self.smoothing_cache[ip] = []
        self.smoothing_cache[ip].append(raw_conf)
        if len(self.smoothing_cache[ip]) > self.MAX_SMOOTHING_WINDOW:
            self.smoothing_cache[ip].pop(0)
            
        smoothed_conf = float(np.mean(self.smoothing_cache[ip]))
        
        # 4. Reputation Boost
        reputation = self.reputation_cache.get(ip, {"score": 0.0})["score"]
        final_conf = min(smoothed_conf + (reputation * 0.20), 1.0)
        
        # 5. Severity & Class Assignment
        primary_attack = ml_class if ml_class != "Benign" else (rule_hit["attack_type"] if rule_hit else seq_class)
        
        # Suppression: If confidence is high but disagreement is extreme, lower severity
        disagreement = ml_class != "Benign" and seq_class != "Benign" and ml_class != seq_class
        if disagreement: final_conf *= 0.85

        severity = "low"
        if final_conf > 0.85: severity = "critical"
        elif final_conf > 0.7: severity = "high"
        elif final_conf > 0.4: severity = "medium"

        return {
            "attack_type": primary_attack,
            "confidence": round(final_conf, 4),
            "severity": severity,
            "disagreement": disagreement,
            "reputation_score": round(reputation, 4),
            "sources": {
                "rule": rule_hit["rule"] if rule_hit else None,
                "ml": ml_class if ml_class != "Benign" else None,
                "sequence": seq_class if seq_class != "Benign" else None
            }
        }

