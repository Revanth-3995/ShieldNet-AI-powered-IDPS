"""
ShieldNet — Internal Frame Analyzer Client
Connects the video pipeline to the image steganalysis engine.
"""
from typing import Dict, Any, List
import numpy as np
import asyncio
from .analyzer_interface import FrameAnalyzer

# Import the existing image analyzer
try:
    from backend.services.steg.algorithms import analyze_image
    STEG_ALG_AVAILABLE = True
except ImportError:
    STEG_ALG_AVAILABLE = False

class InternalAnalyzerClient(FrameAnalyzer):
    def __init__(self):
        self.available = STEG_ALG_AVAILABLE

    async def analyze_frame(self, frame: np.ndarray, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        if not self.available:
            # Mock analysis for demo if algorithm is missing
            await asyncio.sleep(0.01)  # Simulate some latency
            return {
                "confidence": float(np.random.beta(1, 5)),
                "is_suspicious": False,
                "algorithm_detected": None,
                "forensic_data": {}
            }

        # Run the synchronous image analysis in a thread to keep the loop free
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, analyze_image, frame)
        
        return {
            "confidence": result.get("confidence", 0.0),
            "is_suspicious": result.get("confidence", 0.0) > 0.4,
            "algorithm_detected": result.get("algorithm_detected"),
            "forensic_data": result
        }

    async def analyze_batch(self, frames: List[np.ndarray], metadata: List[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        # For now, just process sequentially until we have real batch support (e.g. GPU)
        tasks = [self.analyze_frame(f, m) for f, m in zip(frames, metadata or [{}] * len(frames))]
        return await asyncio.gather(*tasks)
