"""
ShieldNet — Video Motion Analyzer
Identifies frames with significant motion or temporal anomalies.
"""
import cv2
import numpy as np

class MotionAnalyzer:
    def __init__(self, threshold: float = 30.0, heatmap_size: tuple = (32, 32)):
        self.threshold = threshold
        self.heatmap_size = heatmap_size
        self.prev_gray = None
        self.motion_history = []

    def calculate_motion_score(self, frame: np.ndarray) -> tuple[float, np.ndarray]:
        """
        Calculate a motion score and a motion heatmap.
        Returns (score, heatmap).
        """
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        
        if self.prev_gray is None:
            self.prev_gray = gray
            return 1.0, np.zeros(self.heatmap_size, dtype=np.float32)
        
        # Calculate absolute difference
        diff = cv2.absdiff(self.prev_gray, gray)
        
        # Create heatmap
        heatmap = cv2.resize(diff, self.heatmap_size, interpolation=cv2.INTER_AREA)
        heatmap = heatmap.astype(np.float32) / 255.0
        
        # Calculate score (mean of difference)
        score = float(np.mean(diff))
        
        # Temporal smoothing/normalization
        self.motion_history.append(score)
        if len(self.motion_history) > 30:
            self.motion_history.pop(0)
            
        avg_motion = np.mean(self.motion_history)
        normalized_score = score / (avg_motion + 1e-6)
        
        self.prev_gray = gray
        return normalized_score, heatmap

    def detect_abnormal_movement(self, score: float) -> bool:
        """Detect sudden spikes in motion compared to history."""
        if len(self.motion_history) < 10:
            return False
        avg = np.mean(self.motion_history[:-1])
        std = np.std(self.motion_history[:-1])
        return score > (avg + 3 * std)

    def is_significant_change(self, score: float) -> bool:
        # Score is normalized, so 1.0 means average motion. 
        # Threshold might need adjustment if using normalized scores.
        return score > 2.0 or self.detect_abnormal_movement(score)

def calculate_ssim(img1: np.ndarray, img2: np.ndarray) -> float:
    """
    Calculate Structural Similarity Index between two frames.
    """
    # Simple SSIM approximation using OpenCV
    C1 = 6.5025
    C2 = 58.5225
    
    img1 = img1.astype(np.float32)
    img2 = img2.astype(np.float32)
    
    mu1 = cv2.GaussianBlur(img1, (11, 11), 1.5)
    mu2 = cv2.GaussianBlur(img2, (11, 11), 1.5)
    
    mu1_sq = mu1 * mu1
    mu2_sq = mu2 * mu2
    mu1_mu2 = mu1 * mu2
    
    sigma1_sq = cv2.GaussianBlur(img1 * img1, (11, 11), 1.5) - mu1_sq
    sigma2_sq = cv2.GaussianBlur(img2 * img2, (11, 11), 1.5) - mu2_sq
    sigma12 = cv2.GaussianBlur(img1 * img2, (11, 11), 1.5) - mu1_mu2
    
    ssim_map = ((2 * mu1_mu2 + C1) * (2 * sigma12 + C2)) / ((mu1_sq + mu2_sq + C1) * (sigma1_sq + sigma2_sq + C2))
    return float(np.mean(ssim_map))
