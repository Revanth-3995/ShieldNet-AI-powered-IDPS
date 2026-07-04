"""
ShieldNet — Pipeline B: Video Steganalysis Engine.
"""
from __future__ import annotations

import logging

import numpy as np

from backend.core.logging import get_logger

logger = get_logger("shieldnet.steg.video")

try:
    import cv2
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False
    logger.warning("OpenCV not available — video analysis will use mock values")

try:
    from backend.services.steg.algorithms import analyze_image
    STEG_ALG_AVAILABLE = True
except ImportError:
    STEG_ALG_AVAILABLE = False


def extract_frames(video_path: str, sample_rate: int = 30) -> list[dict]:
    if not CV2_AVAILABLE:
        return _synthetic_frames(video_path)
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        return []
    fps = cap.get(cv2.CAP_PROP_FPS) or 25
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    frames = []
    frame_idx = 0
    while True:
        ret, frame = cap.read()
        if not ret:
            break
        include = frame_idx == 0 or frame_idx == total_frames - 1 or frame_idx % sample_rate == 0
        if include:
            frames.append({"frame_number": frame_idx, "timestamp_ms": (frame_idx / fps) * 1000, "frame_array": frame})
        frame_idx += 1
        if len(frames) >= 100:
            break
    cap.release()
    return frames


def _synthetic_frames(video_path: str) -> list[dict]:
    frames = []
    for i in range(15):
        np.random.seed(hash(video_path + str(i)) % 10000)
        frame_array = np.random.randint(0, 256, (64, 64, 3), dtype=np.uint8)
        frames.append({"frame_number": i * 30, "timestamp_ms": i * 1200.0, "frame_array": frame_array})
    return frames


def inter_frame_lsb_consistency(frames: list[dict]) -> float:
    if len(frames) < 2:
        return 0.0
    lsb_variances = []
    for f in frames:
        arr = f["frame_array"]
        lsb_plane = (arr[:, :, 0] & 1) if arr.ndim == 3 else (arr & 1)
        lsb_variances.append(float(np.var(lsb_plane.astype(float))))
    variances = np.array(lsb_variances)
    if len(variances) < 3 or np.std(variances) == 0:
        return 0.0
    z_scores = np.abs((variances - np.mean(variances)) / np.std(variances))
    spike_count = np.sum(z_scores > 3.0)
    return float(min(spike_count / max(len(frames) * 0.1, 1), 1.0))


def dct_coefficient_drift(frames: list[dict]) -> float:
    if len(frames) < 3:
        return 0.0
    histograms = []
    for f in frames:
        arr = f["frame_array"]
        gray = arr[:, :, 0].astype(float) if arr.ndim == 3 else arr.astype(float)
        coeffs = []
        for i in range(0, min(gray.shape[0], 64) - 8, 8):
            for j in range(0, min(gray.shape[1], 64) - 8, 8):
                coeffs.extend(np.fft.fft2(gray[i:i + 8, j:j + 8]).real.flatten())
        if coeffs:
            hist, _ = np.histogram(coeffs, bins=32, range=(-100, 100), density=True)
            histograms.append(hist + 1e-10)
    if len(histograms) < 2:
        return 0.0
    ref = np.mean(histograms, axis=0)
    ref /= ref.sum()
    kl_divs = []
    for h in histograms:
        h_norm = h / h.sum()
        kl_divs.append(np.sum(h_norm * np.log(h_norm / ref)))
    return float(np.clip(min(np.mean(kl_divs) * 10, 1.0), 0, 1))


def analyze_audio_track(video_path: str) -> dict:
    return {"rs_score": 0.1, "echo_score": 0.1, "confidence": 0.1, "channel": "unknown", "sample_range_flagged": None}


def analyze_video_metadata(video_path: str) -> float:
    return 0.0


def analyze_video(video_path: str) -> dict:
    frames = extract_frames(video_path)
    if not frames:
        return {"confidence": 0.0, "error": "No frames extracted", "frame_results": []}

    frame_results = []
    for f in frames:
        arr = f["frame_array"]
        result = analyze_image(arr) if STEG_ALG_AVAILABLE else {"confidence": float(np.random.beta(1, 5))}
        frame_results.append({
            "frame_number": f["frame_number"],
            "timestamp_ms": f["timestamp_ms"],
            "confidence": result.get("confidence", 0.0),
            "chi_square": result.get("chi_square", 0.0),
            "rs_score": result.get("rs_analysis", 0.0),
            "dct_score": result.get("dct_histogram", 0.0),
            "anomaly_type": result.get("algorithm_detected"),
        })

    frame_confidences = [f["confidence"] for f in frame_results]
    mean_frame_conf = float(np.mean(frame_confidences)) if frame_confidences else 0.0
    max_frame_conf = float(np.max(frame_confidences)) if frame_confidences else 0.0
    fraction_flagged = sum(1 for c in frame_confidences if c > 0.40) / max(len(frame_confidences), 1)
    inter_frame_score = inter_frame_lsb_consistency(frames)
    dct_drift_score = dct_coefficient_drift(frames)
    audio_result = analyze_audio_track(video_path)
    audio_score = audio_result.get("confidence", 0.0)
    metadata_score = analyze_video_metadata(video_path)

    video_score = 0.50 * mean_frame_conf + 0.20 * max_frame_conf + 0.30 * audio_score
    if fraction_flagged > 0.3:
        video_score = min(video_score * 1.2, 1.0)
    video_score = min(video_score + (inter_frame_score * 0.1 + dct_drift_score * 0.1), 1.0)
    if metadata_score > 0.3:
        video_score = max(video_score, 0.60)

    algorithm_detected = None
    if video_score > 0.40:
        if inter_frame_score > 0.5:
            algorithm_detected = "LSB-VideoFrames"
        elif audio_score > 0.5:
            algorithm_detected = "AudioLSB-EchoHiding"
        elif dct_drift_score > 0.5:
            algorithm_detected = "DCT-VideoCodec"
        elif metadata_score > 0.3:
            algorithm_detected = "ContainerMetadata"
        else:
            algorithm_detected = "SpreadSpectrum-Video"

    return {
        "confidence": float(np.clip(video_score, 0, 1)),
        "frame_count": len(frames),
        "frame_results": frame_results,
        "audio_results": [audio_result],
        "temporal": {"inter_frame_lsb_consistency": inter_frame_score, "dct_coefficient_drift": dct_drift_score},
        "metadata_score": metadata_score,
        "mean_frame_confidence": mean_frame_conf,
        "max_frame_confidence": max_frame_conf,
        "fraction_frames_flagged": fraction_flagged,
        "audio_score": audio_score,
        "algorithm_detected": algorithm_detected,
    }
