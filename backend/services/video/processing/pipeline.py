"""
ShieldNet — Video Processing Pipeline
Orchestrates async frame extraction, analysis, and aggregation.
"""
import asyncio
import time
from typing import List, Dict, Any, Optional, Callable, Awaitable

import cv2
import numpy as np
from backend.core.logging import get_logger
from backend.services.video.extractor.frame_extractor import SmartFrameExtractor
from backend.services.video.integration.analyzer_interface import FrameAnalyzer
from .aggregator import VideoResultAggregator


logger = get_logger("shieldnet.video.pipeline")

class VideoAnalysisPipeline:
    def __init__(self, analyzer: FrameAnalyzer, max_workers: int = 4, batch_size: int = 8):
        self.analyzer = analyzer
        self.max_workers = max_workers
        self.batch_size = batch_size
        self.extractor = SmartFrameExtractor()
        self.aggregator = VideoResultAggregator()
        self.stats = {"processed_frames": 0, "total_estimated": 0}

    async def process_video(self, 
                            video_path: str, 
                            video_id: str = None, 
                            on_progress: Optional[Callable[[Dict[str, Any]], Awaitable[None]]] = None) -> Dict[str, Any]:
        """
        Main entry point for processing a video file with progress tracking.
        """
        start_time = time.time()
        logger.info(f"Starting optimized async processing for video: {video_path}")
        
        # Estimate total frames for progress
        cap = cv2.VideoCapture(video_path)
        self.stats["total_estimated"] = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        cap.release()

        # Bounded queue for back-pressure
        frame_queue = asyncio.Queue(maxsize=self.batch_size * 2)
        
        # Batch Processor shared across workers
        from .batch_processor import BatchProcessor
        batcher = BatchProcessor(analyzer_fn=self.analyzer.analyze_batch, batch_size=self.batch_size)
        batch_lock = asyncio.Lock()

        # Start workers
        workers = [
            asyncio.create_task(self._worker(frame_queue, i, batcher, batch_lock, on_progress))
            for i in range(self.max_workers)
        ]
        
        # Start extractor (producer)
        loop = asyncio.get_event_loop()
        extraction_task = loop.run_in_executor(None, self._extract_to_queue, video_path, frame_queue)
        
        await extraction_task
        
        # Signal workers to finish
        for _ in range(self.max_workers):
            await frame_queue.put(None)
            
        worker_results = await asyncio.gather(*workers)
        
        # Final flush for any remaining batch
        remaining = await batcher.flush()
        
        all_frame_results = []
        for res in worker_results:
            all_frame_results.extend(res)
        all_frame_results.extend(remaining)
            
        all_frame_results.sort(key=lambda x: x["timestamp_ms"])
        
        # Aggregate with temporal reasoning
        final_result = self.aggregator.aggregate(all_frame_results)
        
        duration = time.time() - start_time
        logger.info(f"Analysis complete. Confidence: {final_result['confidence']:.4f}, Time: {duration:.2f}s")
        
        return {
            "video_id": video_id,
            "processing_duration": duration,
            "extraction_stats": self.extractor.stats,
            **final_result
        }

    def _extract_to_queue(self, video_path: str, queue: asyncio.Queue):
        """Producer function: extracts frames and puts them in the queue."""
        for frame_data in self.extractor.extract_intelligent_frames(video_path):
            try:
                # We use a timeout to avoid hanging if something goes wrong
                asyncio.run_coroutine_threadsafe(queue.put(frame_data), asyncio.get_event_loop()).result(timeout=30)
            except Exception as e:
                logger.error(f"Failed to put frame in queue: {e}")
                break
        logger.debug("Extraction finished")

    async def _worker(self, 
                      queue: asyncio.Queue, 
                      worker_id: int, 
                      batcher: Any, 
                      batch_lock: asyncio.Lock,
                      on_progress: Optional[Callable] = None) -> List[Dict[str, Any]]:
        """Consumer function: handles batching and analysis."""
        results = []
        while True:
            item = await queue.get()
            if item is None:
                queue.task_done()
                break
                
            frame = item.pop("frame")
            
            # Explicit memory management: we process in batches
            async with batch_lock:
                batch_results = await batcher.add_and_process(frame, item)
                
            if batch_results:
                results.extend(batch_results)
                self.stats["processed_frames"] += len(batch_results)
                
                # Progress update
                if on_progress:
                    progress = (self.stats["processed_frames"] / self.extractor.max_frames) * 100
                    await on_progress({
                        "progress": min(progress, 99.9),
                        "frames_processed": self.stats["processed_frames"],
                        "current_confidence": np.mean([r["confidence"] for r in batch_results]) if batch_results else 0
                    })

            # Cleanup
            del frame
            queue.task_done()
                
        return results
