"""
ShieldNet — Batch Frame Processor
Optimizes analysis throughput by grouping frames for batch inference.
"""
from typing import List, Dict, Any, Callable, Awaitable, Optional
import numpy as np
import asyncio
from backend.core.logging import get_logger

logger = get_logger("shieldnet.video.batch")

class BatchProcessor:
    def __init__(self, 
                 analyzer_fn: Callable[[List[np.ndarray], List[Dict[str, Any]]], Awaitable[List[Dict[str, Any]]]], 
                 batch_size: int = 8):
        self.analyzer_fn = analyzer_fn
        self.batch_size = batch_size
        self._batch_frames = []
        self._batch_metadata = []

    async def add_and_process(self, frame: np.ndarray, metadata: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
        """
        Add a frame to the current batch. If batch is full, process it.
        """
        self._batch_frames.append(frame)
        self._batch_metadata.append(metadata)
        
        if len(self._batch_frames) >= self.batch_size:
            return await self.flush()
        return None

    async def flush(self) -> List[Dict[str, Any]]:
        """
        Process the remaining frames in the batch.
        """
        if not self._batch_frames:
            return []
            
        logger.debug(f"Processing batch of {len(self._batch_frames)} frames")
        
        frames = self._batch_frames
        metadata = self._batch_metadata
        
        self._batch_frames = []
        self._batch_metadata = []
        
        try:
            results = await self.analyzer_fn(frames, metadata)
            return results
        except Exception as e:
            logger.error(f"Batch processing error: {e}")
            return [{"error": str(e)} for _ in frames]
