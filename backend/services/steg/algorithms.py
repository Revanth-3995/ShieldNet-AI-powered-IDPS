"""
ShieldNet — Pipeline B: Steganalysis Engine (Image)
Seven statistical algorithms producing a 7-dimensional feature vector.
Each returns a score in [0, 1] where higher = more likely steganographic.
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


# ────────────────────────────────────────────────────────────────
# 1. Chi-Square Attack  (pairs-of-values analysis)
#    LSB embedding makes even/odd pairs more uniform → chi² drops.
# ────────────────────────────────────────────────────────────────
def chi_square_analysis(img_array: np.ndarray) -> float:
    channel = img_array[:, :, 0].flatten() if img_array.ndim == 3 else img_array.flatten()
    n = len(channel)
    if n < 10:
        return 0.0

    # Build Pairs-of-Values (PoV) histogram
    hist = np.bincount(channel.astype(np.int32), minlength=256)[:256]
    expected = np.zeros(128, dtype=float)
    observed = np.zeros(128, dtype=float)
    for v in range(0, 256, 2):
        expected[v // 2] = (hist[v] + hist[v + 1]) / 2.0
        observed[v // 2] = hist[v]

    mask = expected > 0
    if not np.any(mask):
        return 0.0

    chi2 = np.sum(((observed[mask] - expected[mask]) ** 2) / expected[mask])
    dof = np.sum(mask) - 1
    if dof <= 0:
        return 0.0

    # Normalise: a *low* chi² relative to DoF means PoV pairs are
    # suspiciously uniform — the hallmark of LSB embedding.
    ratio = chi2 / dof
    if ratio >= 1.0:
        return 0.0
    score = (1.0 - ratio) / 0.5
    return float(np.clip(score, 0, 1))


# ────────────────────────────────────────────────────────────────
# 2. Sample Pair Analysis (Dumitrescu et al.)
# ────────────────────────────────────────────────────────────────
def sample_pair_analysis(img_array: np.ndarray) -> float:
    channel = img_array[:, :, 0].astype(int) if img_array.ndim == 3 else img_array.astype(int)
    flat = channel.flatten()
    if len(flat) < 2:
        return 0.0

    diffs = np.abs(np.diff(flat))
    w_count = np.sum(diffs == 0)
    x_count = np.sum(diffs == 1)
    total = w_count + x_count
    if total == 0:
        return 0.0

    ratio = float(x_count) / total
    deviation = abs(ratio - 0.5)
    
    base_score = 0.0
    if deviation < 0.165:
        base_score = (0.165 - deviation) / 0.02
        base_score = float(np.clip(base_score, 0, 1))

    # Scale down score on clean natural images using LSB correlation differences
    lsb1 = channel & 1
    lsb2 = (channel >> 1) & 1
    if channel.ndim == 2:
        same1_h = np.mean(lsb1[:, 1:] == lsb1[:, :-1])
        same2_h = np.mean(lsb2[:, 1:] == lsb2[:, :-1])
    else:
        same1_h = np.mean(lsb1[1:] == lsb1[:-1])
        same2_h = np.mean(lsb2[1:] == lsb2[:-1])
    diff_sc = same2_h - same1_h
    scaler = 1.0
    if diff_sc > 0.01:
        scaler = max(0.0, 1.0 - (diff_sc - 0.01) / 0.03)
        
    return float(np.clip(base_score * scaler, 0, 1))


# ────────────────────────────────────────────────────────────────
# 3. RS Analysis (Regular/Singular groups)
# ────────────────────────────────────────────────────────────────
def rs_analysis(img_array: np.ndarray) -> float:
    if img_array.ndim == 3:
        channel = img_array[:, :, 0].astype(float)
    else:
        channel = img_array.astype(float)

    def smoothness(block: np.ndarray) -> float:
        return float(np.sum(np.abs(np.diff(block))))

    def flip_lsb(block: np.ndarray, mask: np.ndarray) -> np.ndarray:
        flipped = block.copy()
        flipped[mask == 1] = np.where(
            flipped[mask == 1] % 2 == 0,
            flipped[mask == 1] + 1,
            flipped[mask == 1] - 1,
        )
        return np.clip(flipped, 0, 255)

    h, w = channel.shape
    block_size = 4
    r_p, s_p, r_n, s_n, count = 0, 0, 0, 0, 0
    for i in range(0, h - block_size, block_size):
        for j in range(0, w - block_size, block_size):
            block = channel[i : i + block_size, j : j + block_size].flatten()
            mask = np.array([1 if k % 2 == 0 else 0 for k in range(len(block))])
            f0 = smoothness(block)
            fp = smoothness(flip_lsb(block, mask))
            fn = smoothness(flip_lsb(block, 1 - mask))
            if fp > f0:
                r_p += 1
            elif fp < f0:
                s_p += 1
            if fn > f0:
                r_n += 1
            elif fn < f0:
                s_n += 1
            count += 1
    if count == 0:
        return 0.0

    r_p /= count
    s_p /= count
    r_n /= count
    s_n /= count

    # In clean images R_p - S_p is large, while LSB stego makes them converge.
    diff_p = r_p - s_p
    diff_n = r_n - s_n
    avg_diff = (diff_p + diff_n) / 2.0
    if avg_diff >= 0.12:
        return 0.0
    score = (0.12 - avg_diff) / 0.075
    return float(np.clip(score, 0, 1))


# ────────────────────────────────────────────────────────────────
# 4. DCT Histogram Analysis (JPEG artefact detection)
# ────────────────────────────────────────────────────────────────
def dct_histogram_analysis(img_array: np.ndarray) -> float:
    gray = img_array[:, :, 0].astype(float) if img_array.ndim == 3 else img_array.astype(float)
    h, w = gray.shape
    coeffs = []
    for i in range(0, h - 8, 8):
        for j in range(0, w - 8, 8):
            block = gray[i : i + 8, j : j + 8]
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


# ────────────────────────────────────────────────────────────────
# 5. Pixel Histogram Smoothness (LSB flattens PoV pairs)
# ────────────────────────────────────────────────────────────────
def pixel_histogram_analysis(img_array: np.ndarray) -> float:
    channel = img_array[:, :, 0].flatten() if img_array.ndim == 3 else img_array.flatten()
    hist = np.bincount(channel.astype(np.int32), minlength=256)[:256].astype(float)
    if hist.sum() == 0:
        return 0.0
    hist /= hist.sum()

    # Compare adjacent even/odd bin counts (PoV flatness)
    pov_diffs = []
    for v in range(0, 256, 2):
        pov_diffs.append(abs(hist[v] - hist[v + 1]))
    pov_diffs = np.array(pov_diffs)
    avg_diff = np.mean(pov_diffs)

    if avg_diff >= 0.00024:
        return 0.0
    score = (0.00024 - avg_diff) / 0.00006
    return float(np.clip(score, 0, 1))


# ────────────────────────────────────────────────────────────────
# 6. Noise Residual Analysis (median filter denoising)
# ────────────────────────────────────────────────────────────────
def _median_filter_3x3(img: np.ndarray) -> np.ndarray:
    """Simple 3×3 median filter — no scipy dependency."""
    h, w = img.shape
    out = img.copy()
    for i in range(1, h - 1):
        for j in range(1, w - 1):
            patch = img[i - 1 : i + 2, j - 1 : j + 2].flatten()
            out[i, j] = np.median(patch)
    return out


def noise_residual_analysis(img_array: np.ndarray) -> float:
    # Calculate LSB correlation scaler on full-resolution image channel first
    channel = img_array[:, :, 0].astype(int) if img_array.ndim == 3 else img_array.astype(int)
    lsb1 = channel & 1
    lsb2 = (channel >> 1) & 1
    if channel.ndim == 2:
        same1_h = np.mean(lsb1[:, 1:] == lsb1[:, :-1])
        same2_h = np.mean(lsb2[:, 1:] == lsb2[:, :-1])
    else:
        same1_h = np.mean(lsb1[1:] == lsb1[:-1])
        same2_h = np.mean(lsb2[1:] == lsb2[:-1])
    diff_sc = same2_h - same1_h
    scaler = 1.0
    if diff_sc > 0.01:
        scaler = max(0.0, 1.0 - (diff_sc - 0.01) / 0.03)

    gray = img_array[:, :, 0].astype(float) if img_array.ndim == 3 else img_array.astype(float)

    # Down-sample for speed (keep max 128×128)
    h, w = gray.shape
    if max(h, w) > 128:
        factor = max(h, w) / 128
        new_h = max(2, int(h / factor))
        new_w = max(2, int(w / factor))
        # Simple nearest-neighbour downsample
        rows = np.linspace(0, h - 1, new_h, dtype=int)
        cols = np.linspace(0, w - 1, new_w, dtype=int)
        gray = gray[np.ix_(rows, cols)]

    denoised = _median_filter_3x3(gray)
    residual = gray - denoised

    # LSB embedding affects the LSB plane specifically
    # Extract LSB plane from residual
    lsb_plane = (residual.astype(int) & 1).astype(float)
    
    # Calculate variance of LSB plane
    # Clean images have structured LSB patterns, stego has random uniform LSB
    lsb_variance = np.var(lsb_plane)
    
    # Also check the absolute residual energy
    res_abs = np.abs(residual.flatten())
    residual_energy = np.mean(res_abs)
    
    # Combine both metrics
    # High residual energy + high LSB variance = likely stego
    # For clean images: residual_energy ~0.5-1.5, lsb_variance ~0.25
    # For stego images: residual_energy ~2.0-4.0, lsb_variance ~0.5
    
    energy_score = max(0.0, (residual_energy - 3.5) / 5.0)
    variance_score = max(0.0, (lsb_variance - 0.248) / 0.01)
    
    # Weighted combination
    score = 0.5 * energy_score + 0.5 * variance_score
    
    return float(np.clip(score * scaler, 0, 1))


# ────────────────────────────────────────────────────────────────
# 7. Benford's Law (first-digit distribution of DCT coefficients)
# ────────────────────────────────────────────────────────────────
def benford_law_analysis(img_array: np.ndarray) -> float:
    gray = img_array[:, :, 0].astype(float) if img_array.ndim == 3 else img_array.astype(float)
    h, w = gray.shape
    all_coeffs = []
    for i in range(0, h - 8, 8):
        for j in range(0, w - 8, 8):
            block = gray[i : i + 8, j : j + 8]
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


# ────────────────────────────────────────────────────────────────
# Aggregation
# ────────────────────────────────────────────────────────────────
ALGORITHM_WEIGHTS = {
    "chi_square": 0.35,  # Increased - shows good LSB discrimination
    "sample_pair": 0.15,
    "rs_analysis": 0.20,
    "dct_histogram": 0.05,  # Decreased - less discriminatory
    "pixel_histogram": 0.05,  # Decreased - not discriminatory for synthetic images
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
    confidence = max(scores.values())
    algorithm_detected = max(scores, key=lambda k: scores[k]) if confidence > 0.35 else None
    result = scores.copy()
    result["confidence"] = float(np.clip(confidence, 0, 1))
    result["algorithm_detected"] = algorithm_detected
    return result


def estimate_payload(img_array: np.ndarray, confidence: float) -> int:
    total_pixels = (
        img_array.shape[0] * img_array.shape[1] * img_array.shape[2]
        if img_array.ndim == 3
        else img_array.size
    )
    estimated_bits = int(total_pixels * confidence * 0.1)
    return max(0, estimated_bits // 8)
