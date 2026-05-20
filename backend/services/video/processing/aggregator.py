"""
ShieldNet — Video Result Aggregator
Combines frame-level results into a comprehensive video-level assessment.
"""
import numpy as np
from typing import List, Dict, Any

class VideoResultAggregator:
    def aggregate(self, frame_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Perform advanced aggregation with temporal consistency analysis.
        """
        if not frame_results:
            return {
                "confidence": 0.0, "is_suspicious": False, "max_frame_confidence": 0.0,
                "mean_frame_confidence": 0.0, "suspicious_frame_density": 0.0,
                "frame_count": 0, "frame_results": []
            }

        # 1. Temporal Smoothing
        # Nearby frames should influence each other's confidence
        confidences = np.array([f["confidence"] for f in frame_results])
        if len(confidences) > 3:
            # Simple moving average to smooth noise
            smoothed_conf = np.convolve(confidences, np.ones(3)/3, mode='same')
        else:
            smoothed_conf = confidences

        # 2. Anomaly Burst Detection
        # Count consecutive suspicious frames or "bursts" within a short time window
        is_suspicious = [f.get("is_suspicious", False) for f in frame_results]
        max_burst = 0
        current_burst = 0
        for s in is_suspicious:
            if s:
                current_burst += 1
                max_burst = max(max_burst, current_burst)
            else:
                current_burst = 0

        # 3. Motion-Weighted Aggregation
        # Anomalies in high-motion areas are often more significant or harder to detect
        motion_scores = np.array([f.get("motion_score", 1.0) for f in frame_results])
        # Weights combine importance (priority) and motion intensity
        priorities = np.array([f.get("priority", 1.0) for f in frame_results])
        combined_weights = priorities * (1.0 + np.log1p(motion_scores))
        
        weighted_conf = np.average(smoothed_conf, weights=combined_weights)
        max_conf = np.max(smoothed_conf)
        
        # 4. Density Analysis
        suspicious_count = sum(1 for s in is_suspicious if s)
        density = suspicious_count / len(frame_results)
        
        # 5. Final Scoring with Temporal Intelligence
        # Boost confidence if we see sustained bursts of anomalies
        burst_multiplier = 1.0 + (min(max_burst, 10) / 20.0) # up to 1.5x boost
        final_confidence = (0.6 * max_conf + 0.4 * weighted_conf) * burst_multiplier
        final_confidence = min(final_confidence, 1.0)

        # Algorithm detection logic
        alg_counts = {}
        for f in frame_results:
            alg = f.get("algorithm_detected")
            if alg:
                alg_counts[alg] = alg_counts.get(alg, 0) + 1
        primary_algorithm = max(alg_counts, key=alg_counts.get) if alg_counts else None

        return {
            "confidence": float(final_confidence),
            "is_suspicious": final_confidence > 0.4,
            "max_frame_confidence": float(max_conf),
            "mean_frame_confidence": float(np.mean(confidences)),
            "suspicious_frame_density": float(density),
            "anomaly_burst_max": max_burst,
            "frame_count": len(frame_results),
            "algorithm_detected": primary_algorithm,
            "frame_results": frame_results
        }
