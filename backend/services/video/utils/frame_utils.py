"""
ShieldNet — Video Frame Utilities
Preprocessing and transformation helpers for analysis.
"""
import cv2
import numpy as np

def preprocess_for_inference(frame: np.ndarray, target_size: tuple = (224, 224)) -> np.ndarray:
    """
    Standard preprocessing for CNN models (like EfficientNet).
    """
    # Resize
    resized = cv2.resize(frame, target_size, interpolation=cv2.INTER_AREA)
    
    # Convert BGR to RGB
    rgb = cv2.cvtColor(resized, cv2.COLOR_BGR2RGB)
    
    # Normalize (0-1)
    normalized = rgb.astype(np.float32) / 255.0
    
    # Standard normalization (ImageNet stats)
    mean = np.array([0.485, 0.456, 0.406])
    std = np.array([0.229, 0.224, 0.225])
    normalized = (normalized - mean) / std
    
    return normalized

def extract_srm_features(frame: np.ndarray) -> np.ndarray:
    """
    Placeholder for SRM (Spatial Rich Model) preprocessing.
    SRM filters help reveal high-frequency noise patterns typical in steganography.
    """
    # This would involve applying 30+ high-pass filters
    # For now, just a Laplacian filter as a placeholder
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    laplacian = cv2.Laplacian(gray, cv2.CV_64F)
    return laplacian
def calculate_phash_fast(frame: np.ndarray, hash_size: int = 8) -> np.ndarray:
    """Fast DCT-based perceptual hash."""
    # Resize to a square and convert to grayscale
    resized = cv2.resize(frame, (hash_size * 4, hash_size * 4), interpolation=cv2.INTER_AREA)
    gray = cv2.cvtColor(resized, cv2.COLOR_BGR2GRAY)
    
    # Compute DCT
    dct = cv2.dct(gray.astype(np.float32))
    
    # Take the top-left low-frequency components
    dct_low = dct[:hash_size, :hash_size]
    
    # Calculate median and threshold to get binary hash
    median = np.median(dct_low)
    return (dct_low > median).flatten()

def optimized_decode_params():
    """Returns optimal OpenCV capture parameters if supported."""
    # Example: use HW acceleration if possible
    # return [cv2.CAP_PROP_HW_ACCELERATION, cv2.VIDEO_ACCELERATION_ANY]
    return []

def safe_frame_copy(frame: np.ndarray) -> np.ndarray:
    """Returns a contiguous, memory-safe copy of a frame."""
    return np.ascontiguousarray(frame.copy())
