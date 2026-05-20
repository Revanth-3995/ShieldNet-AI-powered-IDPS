"""
ShieldNet — IDPS Explainability
Provides human-readable reasons for AI detections using SHAP or feature importance.
"""
from typing import Dict, Any, List
import numpy as np

class ExplainabilityEngine:
    def __init__(self, model):
        self.model = model

    def explain_fusion(self, fusion_data: Dict[str, Any]) -> str:
        """Explains the hybrid reasoning behind a detection for SOC analysts."""
        sources = fusion_data.get("sources", {})
        reputation = fusion_data.get("reputation_score", 0.0)
        disagreement = fusion_data.get("disagreement", False)
        
        reasons = []
        if sources.get("rule"):
            reasons.append(f"matched heuristic signature '{sources['rule']}'")
        if sources.get("ml"):
            reasons.append(f"behavioral ML patterns ({sources['ml']})")
        if sources.get("sequence"):
            reasons.append("suspicious temporal sequence detected")
            
        summary = "Detection triggered by " + " and ".join(reasons) + "."
        
        if disagreement:
            summary += " Note: Secondary detectors show low consensus, indicating a potentially complex or novel attack variant."
            
        if reputation > 0.3:
            summary += f" Risk score boosted by historical IP reputation ({reputation:.2f})."
            
        return summary

    def explain_detection(self, features: Dict[str, Any], attack_type: str) -> Dict[str, Any]:
        """Detailed feature-level attribution and reasoning."""
        if not features:
            return {"summary": "No feature data available.", "top_contributors": []}

        # 1. SHAP / Feature Importance Attribution
        importances = self.model.explain(features) if hasattr(self.model, "explain") else {}
        
        # 2. Heuristic Anomaly Attribution (Domain Knowledge)
        anomalies = []
        if features.get("syn_ack_ratio", 0) > 5.0:
            anomalies.append(("Abnormal SYN/ACK ratio (potential SYN flood)", 0.3))
        if features.get("payload_entropy", 0) > 7.5:
            anomalies.append(("High payload entropy (potential encrypted/obfuscated payload)", 0.4))
        if features.get("fwd_burstiness", 0) > 10.0:
            anomalies.append(("Highly bursty traffic pattern", 0.2))

        # Combine importance and anomalies
        combined = {f: importances.get(f, 0.0) for f in features if isinstance(features[f], (int, float))}
        # Add weights from domain anomalies
        for name, weight in anomalies:
            # Simplified: map anomaly name to a dummy feature key for consistent output
            combined[name] = weight
            
        sorted_features = sorted(combined.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            "summary": self._generate_soc_summary(attack_type, sorted_features),
            "top_contributors": [
                {"feature": f.replace("_", " "), "weight": round(w, 4)} for f, w in sorted_features
            ],
            "severity_justification": self._justify_severity(attack_type, sorted_features)
        }

    def _generate_soc_summary(self, attack_type: str, top_features: List[tuple]) -> str:
        if not top_features:
            return f"Classified as {attack_type} based on overall behavioral baseline."
            
        main_feat = top_features[0][0].replace("_", " ")
        return f"This {attack_type} alert is primarily driven by anomalies in '{main_feat}', suggesting a breach of standard behavioral thresholds."

    def _justify_severity(self, attack_type: str, top_features: List[tuple]) -> str:
        # Heuristic severity reasoning
        if any(f[1] > 0.5 for f in top_features):
            return "Severity is elevated due to extreme divergence in primary behavioral indicators."
        return "Severity is based on cumulative evidence from multiple behavioral signals."

