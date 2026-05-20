"""
ShieldNet — XGBoost Intrusion Detector
High-performance behavioral analysis using Gradient Boosting.
"""
import os
import pickle
from typing import Dict, Any, Tuple, List
import numpy as np
from backend.core.logging import get_logger
from backend.services.idps.models.inference.base_model import IDPSBaseModel

logger = get_logger("shieldnet.idps.models.xgboost")

class XGBoostDetector(IDPSBaseModel):
    ATTACK_CLASSES = [
        "Benign", "Bot", "DoS", "Infiltration", "Other", "PortScan"
    ]
    
    # Standard feature order matching the training dataset (e.g. CIC-IDS-2017)
    FEATURES = [
        "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts", "tot_len_fwd_pkts",
        "tot_len_bwd_pkts", "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean",
        "fwd_pkt_len_std", "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean",
        "bwd_pkt_len_std", "flow_byts_s", "flow_pkts_s", "flow_iat_mean",
        "flow_iat_std", "flow_iat_max", "flow_iat_min", "fwd_iat_tot",
        "bwd_iat_tot", "fwd_iat_std", "bwd_iat_std", "fin_flag_cnt", 
        "syn_flag_cnt", "rst_flag_cnt", "psh_flag_cnt", "ack_flag_cnt", 
        "urg_flag_cnt", "syn_ack_ratio", "rst_syn_ratio", "pkt_len_mean",
        "pkt_size_avg", "fwd_burstiness", "fwd_pkts_bwd_pkts_ratio",
        "fwd_bytes_bwd_bytes_ratio", "payload_entropy", "dst_port_type",
        "pkt_count_asymmetry", "byte_count_asymmetry",
        "log_flow_byts_s", "log_flow_pkts_s", "log_tot_len_fwd_pkts", "log_tot_len_bwd_pkts"
    ]


    def __init__(self, model_path: str = None):
        self.model = None
        self.model_metadata = {}
        self.scaler = None
        self.label_encoder = None
        if model_path:
            self.load(model_path)

    def load(self, path: str):
        if not os.path.exists(path):
            logger.warning(f"XGBoost model file not found at {path}")
            return
        try:
            with open(path, "rb") as f:
                data = pickle.load(f)
                self.model_metadata = data
                self.model = data["model"]
                self.ATTACK_CLASSES = data.get("classes", self.ATTACK_CLASSES)
                self.FEATURES = data.get("features", self.FEATURES)

            base_dir = os.path.dirname(path)
            scaler_path = os.path.join(base_dir, "scaler.pkl")
            if os.path.exists(scaler_path):
                with open(scaler_path, "rb") as f:
                    self.scaler = pickle.load(f)
            le_path = os.path.join(base_dir, "label_encoder.pkl")
            if os.path.exists(le_path):
                with open(le_path, "rb") as f:
                    self.label_encoder = pickle.load(f)
            logger.info(f"XGBoost model loaded from {path}")
        except Exception as e:
            logger.error(f"Failed to load XGBoost model: {e}")


    def predict(self, features: Dict[str, Any]) -> Tuple[str, float]:
        """Calibrated prediction with dynamic threshold optimization."""
        if not self.model:
            return "Benign", 0.0
        
        try:
            # Align features with the order used during training
            x = np.array([[features.get(f, 0.0) for f in self.FEATURES]])
            
            if self.scaler:
                x = self.scaler.transform(x)
            
            # Use predict_proba if available (for calibrated models)
            if hasattr(self.model, "predict_proba"):
                probs = self.model.predict_proba(x)[0]
                idx = np.argmax(probs)
                attack_type = self.ATTACK_CLASSES[idx]
                confidence = float(probs[idx])
            else:
                pred = self.model.predict(x)[0]
                attack_type = self.ATTACK_CLASSES[int(pred)]
                confidence = 1.0 # Fallback
            
            # Use optimized thresholds from model metadata if available
            effective_threshold = self.model_metadata.get("thresholds", {}).get(attack_type, 0.6)
            
            if attack_type != "Benign" and confidence < effective_threshold:
                return "Benign", 0.1
                
            return attack_type, confidence


            
        except Exception as e:
            logger.error(f"XGBoost prediction error: {e}")
            return "Benign", 0.0

    def explain(self, features: Dict[str, Any]) -> Dict[str, float]:
        """Simple feature importance explanation."""
        if not self.model or not hasattr(self.model, "feature_importances_"):
            return {}
            
        importances = self.model.feature_importances_
        return {f: float(importances[i]) for i, f in enumerate(self.FEATURES)}
