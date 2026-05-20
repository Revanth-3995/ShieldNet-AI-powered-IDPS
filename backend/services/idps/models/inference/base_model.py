"""
ShieldNet — IDPS Model Base
Defines the interface for all intrusion detection models.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Tuple, List
import numpy as np

class IDPSBaseModel(ABC):
    @abstractmethod
    def predict(self, features: Dict[str, Any]) -> Tuple[str, float]:
        """
        Returns (attack_class, confidence).
        """
        pass

    @abstractmethod
    def explain(self, features: Dict[str, Any]) -> Dict[str, float]:
        """
        Returns feature importances or SHAP values.
        """
        pass
    
    @abstractmethod
    def load(self, path: str):
        pass
