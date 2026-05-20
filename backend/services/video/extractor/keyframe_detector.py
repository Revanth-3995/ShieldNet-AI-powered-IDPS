"""
ShieldNet — Keyframe Detector
Identifies visually unique frames and scene transitions.
"""
import cv2
import numpy as np

class KeyframeDetector:
    def __init__(self, scene_threshold: float = 0.5):
        self.scene_threshold = scene_threshold
        self.prev_hist = None
        self.prev_hash = None

    def calculate_phash(self, frame: np.ndarray) -> np.ndarray:
        """Calculate a simple perceptual hash (DCT-based)."""
        resized = cv2.resize(cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY), (32, 32))
        dct = cv2.dct(resized.astype(np.float32))
        dct_low = dct[:8, :8]
        avg = np.mean(dct_low)
        return (dct_low > avg).flatten()

    def calculate_uniqueness(self, frame: np.ndarray) -> float:
        """Calculate how unique a frame is compared to the previous one using pHash."""
        curr_hash = self.calculate_phash(frame)
        if self.prev_hash is None:
            self.prev_hash = curr_hash
            return 1.0
        
        diff = np.sum(curr_hash != self.prev_hash)
        uniqueness = diff / len(curr_hash)
        self.prev_hash = curr_hash
        return float(uniqueness)

    def is_keyframe(self, frame: np.ndarray) -> bool:
        """
        Detect if the frame is a keyframe based on histogram correlation and hashing.
        """
        hsv = cv2.cvtColor(frame, cv2.COLOR_BGR2HSV)
        hist = cv2.calcHist([hsv], [0, 1], None, [50, 60], [0, 180, 0, 256])
        cv2.normalize(hist, hist, 0, 1, cv2.NORM_MINMAX)
        
        if self.prev_hist is None:
            self.prev_hist = hist
            return True
        
        score = cv2.compareHist(self.prev_hist, hist, cv2.HISTCMP_CORREL)
        self.prev_hist = hist
        
        # Combine histogram with hash uniqueness
        uniqueness = self.calculate_uniqueness(frame)
        
        return score < (1.0 - self.scene_threshold) or uniqueness > 0.3

    def calculate_entropy(self, frame: np.ndarray) -> float:
        """
        Calculate image entropy. High entropy frames often contain more information.
        """
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        hist = cv2.calcHist([gray], [0], None, [256], [0, 256])
        hist /= hist.sum()
        hist = hist[hist > 0]
        return float(-np.sum(hist * np.log2(hist)))
