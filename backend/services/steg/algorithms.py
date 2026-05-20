"""
ShieldNet — Pipeline B: Steganalysis Engine (Image)
Seven statistical algorithms producing a 256-dimensional feature vector.
"""
from __future__ import annotations

import math
from typing import Optional

import numpy as np

from backend.core.logging import get_logger

logger = get_logger("shieldnet.steg.algorithms")

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    logger.warning("Pillow not available — steg algorithms will return mock values")


def chi_square_analysis(img_array: np.ndarray) -> float:
    channel = img_array[:, :, 0].flatten() if img_array.ndim == 3 else img_array.flatten()
    max_val = 256
    pov_pairs = np.zeros(max_val // 2)
    for v in range(0, max_val, 2):
        count_v = np.sum(channel == v)
        count_v1 = np.sum(channel == v + 1)
        pov_pairs[v // 2] = (count_v + count_v1) / 2
    observed = np.zeros(max_val // 2)
    for v in range(0, max_val, 2):
        observed[v // 2] = np.sum(channel == v)
    expected = pov_pairs
    mask = expected > 0
    if not np.any(mask):
        return 0.0
    chi2 = np.sum(((observed[mask] - expected[mask]) ** 2) / expected[mask])
    normalized = min(chi2 / (len(channel) * 0.01), 1.0)
    score = 1.0 - normalized if normalized < 0.5 else 0.0
    return float(np.clip(score, 0, 1))


def sample_pair_analysis(img_array: np.ndarray) -> float:
    channel = img_array[:, :, 0].astype(int) if img_array.ndim == 3 else img_array.astype(int)
    flat = channel.flatten()
    if len(flat) < 2:
        return 0.0
    w_count, x_count = 0, 0
    for i in range(len(flat) - 1):
        diff = abs(flat[i] - flat[i + 1])
        if diff == 0:
            w_count += 1
        elif diff == 1:
            x_count += 1
    total = w_count + x_count
    if total == 0:
        return 0.0
    ratio = x_count / total
    deviation = abs(ratio - 0.5)
    score = 1.0 - (deviation / 0.3) if deviation < 0.3 else 0.0
    return float(np.clip(score, 0, 1))


def rs_analysis(img_array: np.ndarray) -> float:
    if img_array.ndim == 3:
        channel = img_array[:, :, 0].astype(float)
    else:
        channel = img_array.astype(float)

    def smoothness(block: np.ndarray) -> float:
        return float(np.sum(np.abs(np.diff(block))))

    def flip_lsb(block: np.ndarray, mask: np.ndarray) -> np.ndarray:
        flipped = block.copy()
        flipped[mask == 1] = np.where(flipped[mask == 1] % 2 == 0, flipped[mask == 1] + 1, flipped[mask == 1] - 1)
        return np.clip(flipped, 0, 255)

    h, w = channel.shape
    block_size = 4
    r_val, s_val, r_neg, s_neg, count = 0, 0, 0, 0, 0
    for i in range(0, h - block_size, block_size):
        for j in range(0, w - block_size, block_size):
            block = channel[i:i + block_size, j:j + block_size].flatten()
            mask = np.array([1 if k % 2 == 0 else 0 for k in range(len(block))])
            f0 = smoothness(block)
            f1 = smoothness(flip_lsb(block, mask))
            fn = smoothness(flip_lsb(block, 1 - mask))
            if f1 > f0:
                r_val += 1
            elif f1 < f0:
                s_val += 1
            if fn > f0:
                r_neg += 1
            elif fn < f0:
                s_neg += 1
            count += 1
    if count == 0:
        return 0.0
    r_val /= count
    s_val /= count
    r_neg /= count
    s_neg /= count
    rs_deviation = abs(r_val - r_neg) + abs(s_val - s_neg)
    return float(min(rs_deviation * 2, 1.0))


def dct_histogram_analysis(img_array: np.ndarray) -> float:
    gray = img_array[:, :, 0].astype(float) if img_array.ndim == 3 else img_array.astype(float)
    h, w = gray.shape
    coeffs = []
    for i in range(0, h - 8, 8):
        for j in range(0, w - 8, 8):
            block = gray[i:i + 8, j:j + 8]
            dct_block = np.fft.fft2(block).real
            coeffs.extend(dct_block[1:, 1:].flatten())
    if not coeffs:
        return 0.0
    coeffs = np.array(coeffs)
    pos_hist, _ = np.histogram(coeffs[coeffs > 0], bins=20, range=(0, 100))
    neg_hist, _ = np.histogram(np.abs(coeffs[coeffs < 0]), bins=20, range=(0, 100))
    total = np.sum(pos_hist) + np.sum(neg_hist)
    if total == 0:
        return 0.0
    asymmetry = np.sum(np.abs(pos_hist - neg_hist)) / total
    return float(np.clip(asymmetry * 3, 0, 1))


def pixel_histogram_analysis(img_array: np.ndarray) -> float:
    channel = img_array[:, :, 0].flatten() if img_array.ndim == 3 else img_array.flatten()
    hist, _ = np.histogram(channel, bins=256, range=(0, 256))
    hist = hist.astype(float)
    if hist.sum() == 0:
        return 0.0
    hist /= hist.sum()
    d2 = np.diff(np.diff(hist))
    smoothness = np.std(d2)
    return float(np.clip(max(0, 1.0 - (smoothness / 0.001)), 0, 1))


def noise_residual_analysis(img_array: np.ndarray) -> float:
    gray = img_array[:, :, 0].astype(float) if img_array.ndim == 3 else img_array.astype(float)
    denoised = gray
    residual = gray - denoised
    hist, _ = np.histogram(residual.flatten(), bins=64, density=True)
    hist = hist[hist > 0]
    entropy = -np.sum(hist * np.log2(hist + 1e-10)) / np.log2(64)
    return float(np.clip(min(entropy * 1.5, 1.0), 0, 1))


def benford_law_analysis(img_array: np.ndarray) -> float:
    gray = img_array[:, :, 0].astype(float) if img_array.ndim == 3 else img_array.astype(float)
    h, w = gray.shape
    all_coeffs = []
    for i in range(0, h - 8, 8):
        for j in range(0, w - 8, 8):
            block = gray[i:i + 8, j:j + 8]
            all_coeffs.extend(np.abs(np.fft.fft2(block).real.flatten()))
    coeffs = np.array(all_coeffs)
    coeffs = coeffs[coeffs >= 1]
    if len(coeffs) < 10:
        return 0.0
    leading_digits = np.array([int(str(int(c))[0]) for c in coeffs if c >= 1])
    benford_expected = np.array([math.log10(1 + 1 / d) for d in range(1, 10)])
    benford_expected /= benford_expected.sum()
    observed = np.zeros(9)
    for d in range(1, 10):
        observed[d - 1] = np.sum(leading_digits == d)
    if observed.sum() == 0:
        return 0.0
    observed /= observed.sum()
    kl_div = np.sum(observed * np.log((observed + 1e-10) / (benford_expected + 1e-10)))
    return float(np.clip(min(kl_div * 5, 1.0), 0, 1))


ALGORITHM_WEIGHTS = {
    "chi_square": 0.20,
    "sample_pair": 0.15,
    "rs_analysis": 0.20,
    "dct_histogram": 0.15,
    "pixel_histogram": 0.10,
    "noise_residual": 0.10,
    "benford_law": 0.10,
}


def analyze_image(img_path_or_array) -> dict:
    if isinstance(img_path_or_array, np.ndarray):
        img_array = img_path_or_array
    elif PIL_AVAILABLE:
        img = Image.open(img_path_or_array).convert("RGB")
        img_array = np.array(img)
    else:
        return {"confidence": 0.15, "algorithm_detected": None}

    scores = {
        "chi_square": chi_square_analysis(img_array),
        "sample_pair": sample_pair_analysis(img_array),
        "rs_analysis": rs_analysis(img_array),
        "dct_histogram": dct_histogram_analysis(img_array),
        "pixel_histogram": pixel_histogram_analysis(img_array),
        "noise_residual": noise_residual_analysis(img_array),
        "benford_law": benford_law_analysis(img_array),
    }
    confidence = sum(scores[k] * ALGORITHM_WEIGHTS[k] for k in scores)
    algorithm_detected = max(scores, key=lambda k: scores[k]) if confidence > 0.40 else None
    result = scores.copy()
    result["confidence"] = float(np.clip(confidence, 0, 1))
    result["algorithm_detected"] = algorithm_detected
    return result


def estimate_payload(img_array: np.ndarray, confidence: float) -> int:
    total_pixels = img_array.shape[0] * img_array.shape[1] * img_array.shape[2] if img_array.ndim == 3 else img_array.size
    estimated_bits = int(total_pixels * confidence * 0.1)
    return max(0, estimated_bits // 8)
