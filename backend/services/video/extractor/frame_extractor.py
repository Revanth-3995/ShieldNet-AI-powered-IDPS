"""
ShieldNet — Smart Frame Extractor
Implements intelligent, motion-aware frame extraction.
"""
import cv2
import numpy as np
from typing import Generator, Dict, Any, Tuple
from .motion_analyzer import MotionAnalyzer, calculate_ssim
from .keyframe_detector import KeyframeDetector
from backend.core.logging import get_logger

logger = get_logger("shieldnet.video.extractor")

class SmartFrameExtractor:
    def __init__(self, 
                 max_frames: int = 150, 
                 base_interval_ms: float = 300, 
                 motion_threshold: float = 1.5,
                 scene_threshold: float = 0.4):
        self.max_frames = max_frames
        self.base_interval_ms = base_interval_ms
        self.motion_analyzer = MotionAnalyzer(threshold=motion_threshold)
        self.keyframe_detector = KeyframeDetector(scene_threshold=scene_threshold)
        self.last_extracted_time = -float('inf')
        self.prev_frame = None
        self.stats = {"extracted": 0, "skipped": 0, "reason_counts": {}}

    def extract_intelligent_frames(self, video_path: str) -> Generator[Dict[str, Any], None, None]:
        """
        Aggressively extracts only the most visually important frames.
        """
        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened():
            logger.error(f"Failed to open video: {video_path}")
            return

        fps = cap.get(cv2.CAP_PROP_FPS) or 25.0
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        
        frame_idx = 0
        while cap.isOpened() and self.stats["extracted"] < self.max_frames:
            ret, frame = cap.read()
            if not ret:
                break
                
            timestamp_ms = (frame_idx / fps) * 1000
            
            # 1. Adaptive Timing
            # Extract faster when there is high motion, slower when static
            # We'll calculate motion first for a subset of frames to decide
            motion_score, heatmap = self.motion_analyzer.calculate_motion_score(frame)
            
            # Adjust interval dynamically: higher motion -> smaller interval
            dynamic_interval = self.base_interval_ms / max(motion_score, 0.5)
            
            if timestamp_ms - self.last_extracted_time < dynamic_interval:
                self.stats["skipped"] += 1
                frame_idx += 1
                continue

            # 2. Keyframe & Uniqueness
            is_key = self.keyframe_detector.is_keyframe(frame)
            uniqueness = self.keyframe_detector.calculate_uniqueness(frame)
            
            # 3. Decision Logic
            should_extract = False
            reason = None
            priority = 0.0

            if is_key:
                should_extract = True
                reason = "keyframe"
                priority = 1.0
            elif motion_score > 2.5:
                should_extract = True
                reason = "high_motion"
                priority = min(0.4 + (motion_score / 10.0), 0.9)
            elif uniqueness > 0.4:
                should_extract = True
                reason = "unique_content"
                priority = 0.7
            
            # SSIM fallback for redundant content
            if should_extract and self.prev_frame is not None:
                # Downsample for faster SSIM
                small_prev = cv2.resize(self.prev_frame, (128, 128))
                small_curr = cv2.resize(frame, (128, 128))
                similarity = calculate_ssim(small_prev, small_curr)
                if similarity > 0.98: # Almost identical despite motion/keyframe trigger
                    should_extract = False
                    self.stats["skipped"] += 1

            if should_extract:
                self.last_extracted_time = timestamp_ms
                self.prev_frame = frame.copy()
                self.stats["extracted"] += 1
                self.stats["reason_counts"][reason] = self.stats["reason_counts"].get(reason, 0) + 1
                
                yield {
                    "frame_idx": frame_idx,
                    "timestamp_ms": timestamp_ms,
                    "frame": frame, # We yield the original frame for analysis
                    "priority": priority,
                    "reason": reason,
                    "motion_score": motion_score,
                    "motion_heatmap": heatmap,
                    "uniqueness": uniqueness,
                    "entropy": self.keyframe_detector.calculate_entropy(frame)
                }
            else:
                self.stats["skipped"] += 1
            
            frame_idx += 1
            
        cap.release()
        reduction = (self.stats["skipped"] / (self.stats["extracted"] + self.stats["skipped"])) * 100 if (self.stats["extracted"] + self.stats["skipped"]) > 0 else 0
        logger.info(f"Extraction complete. Reduced {total_frames} frames to {self.stats['extracted']} ({reduction:.1f}% reduction)")
