"""
ShieldNet — BiLSTM Sequence Detector
Analyzes temporal progression of flows to detect multi-stage attacks.
"""
import numpy as np
from typing import List, Dict, Any, Tuple
import asyncio
from backend.core.logging import get_logger

logger = get_logger("shieldnet.idps.models.bilstm")

import torch
from .model_arch import BiLSTMIDS

class BiLSTMDetector:
    def __init__(self, sequence_length: int = 10, feature_dim: int = 35, model_path: str = None):
        self.sequence_length = sequence_length
        self.feature_dim = feature_dim
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = None
        self.classes = []
        
        if model_path:
            self.load(model_path)
            
    def load(self, path: str):
        try:
            checkpoint = torch.load(path, map_location=self.device)
            self.classes = checkpoint.get("classes", [])
            input_dim = checkpoint.get("input_dim", self.feature_dim)
            num_classes = len(self.classes)
            
            self.model = BiLSTMIDS(input_dim=input_dim, hidden_dim=128, num_layers=2, num_classes=num_classes)
            self.model.load_state_dict(checkpoint["model_state_dict"])
            self.model.to(self.device)
            self.model.eval()
            logger.info(f"BiLSTM model loaded from {path}")
        except Exception as e:
            logger.error(f"Failed to load BiLSTM model: {e}")

    def prepare_sequence(self, flow_history: List[Dict[str, Any]]) -> np.ndarray:
        """Pad or truncate flow history to sequence_length."""
        # Convert dict features to array in correct order
        from ..classical_ml.xgboost_detector import XGBoostDetector
        feature_order = XGBoostDetector.FEATURES
        
        processed_history = []
        for feat_dict in flow_history:
            vec = np.array([feat_dict.get(f, 0.0) for f in feature_order])
            processed_history.append(vec)

        if len(processed_history) >= self.sequence_length:
            seq = processed_history[-self.sequence_length:]
        else:
            padding = [np.zeros(self.feature_dim)] * (self.sequence_length - len(processed_history))
            seq = padding + processed_history
        return np.array(seq)

    async def predict_sequence(self, sequence: np.ndarray) -> Tuple[str, float]:
        if self.model is None:
            return "Benign", 0.1
            
        try:
            x = torch.tensor(sequence, dtype=torch.float32).unsqueeze(0).to(self.device)
            with torch.no_grad():
                outputs = self.model(x)
                probs = torch.softmax(outputs, dim=1).cpu().numpy()[0]
                
            idx = np.argmax(probs)
            attack_type = self.classes[idx]
            confidence = float(probs[idx])
            
            return attack_type, confidence
        except Exception as e:
            logger.error(f"BiLSTM prediction error: {e}")
            return "Benign", 0.0

