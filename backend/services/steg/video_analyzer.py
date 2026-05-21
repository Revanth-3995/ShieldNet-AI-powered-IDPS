"""
ShieldNet — Pipeline B: Video Steganalysis Engine.
"""
from __future__ import annotations

import logging
import os

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
    """
    RS analysis + echo hiding detection on the audio track of a video file.
    Falls back gracefully if pydub/ffmpeg not available.
    """
    try:
        from pydub import AudioSegment
        import numpy as np

        audio = AudioSegment.from_file(video_path)
        samples = np.array(audio.get_array_of_samples(), dtype=np.float32)

        if len(samples) < 100:
            return {"rs_score": 0.0, "echo_score": 0.0, "confidence": 0.0,
                    "channel": "mono", "sample_range_flagged": None}

        # --- RS Analysis on audio samples ---
        # Treat audio samples as 1D signal; apply LSB flip and measure regularity
        def rs_groups(s, mask):
            flipped = s.copy()
            flipped[mask == 1] = np.where(
                flipped[mask == 1] % 2 == 0,
                flipped[mask == 1] + 1,
                flipped[mask == 1] - 1
            )
            orig_var = np.mean(np.abs(np.diff(s)))
            flip_var = np.mean(np.abs(np.diff(flipped)))
            return orig_var, flip_var

        chunk = samples[:min(44100, len(samples))]  # analyze first second
        mask = np.array([i % 2 for i in range(len(chunk))])
        orig_var, flip_var = rs_groups(chunk, mask)

        # High similarity between original and LSB-flipped variance → hidden data
        rs_ratio = abs(orig_var - flip_var) / (orig_var + 1e-9)
        rs_score = float(np.clip(1.0 - rs_ratio * 3, 0.0, 1.0))

        # --- Echo Hiding Detection ---
        # Look for periodic peaks in autocorrelation at typical echo delays (50–500 samples)
        corr = np.correlate(chunk[:8000] / (np.max(np.abs(chunk[:8000])) + 1e-9),
                            chunk[:8000] / (np.max(np.abs(chunk[:8000])) + 1e-9),
                            mode='full')
        half = corr[len(corr)//2:]
        # Echo hiding produces a secondary peak at the echo delay offset
        search_region = half[50:500]
        main_peak = half[0]
        secondary_max = float(np.max(search_region)) if len(search_region) > 0 else 0.0
        echo_ratio = secondary_max / (abs(main_peak) + 1e-9)
        echo_score = float(np.clip(echo_ratio * 2, 0.0, 1.0))

        confidence = float(np.clip((rs_score * 0.6 + echo_score * 0.4), 0.0, 1.0))

        sample_range = f"0–{min(44100, len(samples))}" if confidence > 0.3 else None

        return {
            "rs_score": round(rs_score, 3),
            "echo_score": round(echo_score, 3),
            "confidence": round(confidence, 3),
            "channel": "stereo" if audio.channels == 2 else "mono",
            "sample_range_flagged": sample_range,
        }

    except Exception as e:
        # Graceful fallback — pydub/ffmpeg not available or file has no audio
        logger.debug(f"Audio analysis unavailable: {e}")
        return {"rs_score": 0.0, "echo_score": 0.0, "confidence": 0.0,
                "channel": "unknown", "sample_range_flagged": None}


# Standard MP4 box types — anything outside this set is suspicious
_KNOWN_MP4_BOXES = {
    b'ftyp', b'moov', b'mdat', b'free', b'skip', b'udta', b'meta',
    b'ilst', b'trak', b'mdia', b'minf', b'stbl', b'mvhd', b'tkhd',
    b'mdhd', b'hdlr', b'smhd', b'vmhd', b'dinf', b'stsd', b'stts',
    b'stss', b'ctts', b'stsc', b'stsz', b'stco', b'co64', b'edts',
    b'elst', b'url ', b'dref', b'avc1', b'mp4a', b'esds', b'btrt',
    b'pasp', b'colr', b'clap', b'wide', b'moof', b'mfhd', b'traf',
    b'tfhd', b'trun', b'mfra', b'tfra', b'mfro', b'styp', b'sidx',
}


def analyze_video_metadata(video_path: str) -> float:
    """
    Parse MP4 container structure for steganographic metadata anomalies.
    Pure Python — no external libraries required.
    Returns anomaly score 0.0–1.0.
    """
    if not video_path or not os.path.exists(video_path):
        return 0.0

    ext = os.path.splitext(video_path)[1].lower()
    if ext not in ('.mp4', '.m4v', '.mov', '.m4a'):
        return 0.0  # Only handle ISO Base Media File Format

    anomalies = []

    try:
        file_size = os.path.getsize(video_path)
        with open(video_path, 'rb') as f:
            offset = 0
            max_iterations = 500  # Prevent infinite loop on malformed files

            for _ in range(max_iterations):
                header = f.read(8)
                if len(header) < 8:
                    break

                box_size = int.from_bytes(header[:4], 'big')
                box_type = header[4:8]

                if box_size == 0:
                    break  # box extends to end of file — normal
                if box_size < 8:
                    anomalies.append(f"malformed_size:{box_type}")
                    break

                # Flag unknown box types
                if box_type not in _KNOWN_MP4_BOXES:
                    anomalies.append(f"unknown_box:{box_type.decode(errors='replace')}")

                # Flag oversized free/skip padding (> 1KB is unusual)
                if box_type in (b'free', b'skip') and box_size > 1024:
                    anomalies.append(f"large_padding:{box_size}")

                # Flag box claiming to exceed file size
                if box_size > file_size:
                    anomalies.append(f"oversized_box:{box_type}")

                # Check udta (user data) for non-UTF8 content
                if box_type == b'udta' and box_size < 65536:
                    content = f.read(box_size - 8)
                    try:
                        content.decode('utf-8')
                    except UnicodeDecodeError:
                        anomalies.append("udta_non_utf8")
                    f.seek(offset + box_size)
                else:
                    f.seek(offset + box_size)

                offset += box_size

    except Exception as e:
        logger.debug(f"Metadata parse error: {e}")
        return 0.0

    if not anomalies:
        return 0.0
    elif len(anomalies) == 1:
        return 0.60
    else:
        return min(0.95, 0.60 + len(anomalies) * 0.10)


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
