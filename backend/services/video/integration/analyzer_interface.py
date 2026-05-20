"""
ShieldNet — Video Analyzer Interface
Defines the contract for frame-level analysis.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List
import numpy as np

class FrameAnalyzer(ABC):
    @abstractmethod
    async def analyze_frame(self, frame: np.ndarray, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Analyze a single video frame.
        Returns:
            {
                "confidence": float,
                "is_suspicious": bool,
                "algorithm_detected": str,
                "anomaly_score": float,
                "forensic_data": dict
            }
        """
        pass

    @abstractmethod
    async def analyze_batch(self, frames: List[np.ndarray], metadata: List[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Analyze a batch of frames (for GPU/AI optimization).
        """
        pass
