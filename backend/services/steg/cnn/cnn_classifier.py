"""
ShieldNet — Pipeline B: Steganalysis CNN Inference
EfficientNet-B0 + MLP late-fusion for image and video steg classification.
Falls back to statistical-only scoring if model file is absent.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

import numpy as np

logger = logging.getLogger("shieldnet.steg.cnn")

_MODEL_PATH = Path("models/steg_cnn.pth")
_model = None
_transforms = None
_MODEL_LOADED: bool = False


def _try_load_model() -> bool:
    global _model, _transforms, _MODEL_LOADED
    if _MODEL_LOADED:
        return True
    if not _MODEL_PATH.exists():
        logger.warning(
            f"[CNN] Model not found at {_MODEL_PATH}. "
            "Falling back to statistical-only scoring. "
            "Run backend/services/steg/cnn/train_cnn.py to train."
        )
        return False
    try:
        import torch
        import torchvision.models as tv_models
        import torchvision.transforms as T
        import torch.nn as nn

        backbone = tv_models.efficientnet_b0(weights=None)
        backbone.classifier[1] = nn.Linear(1280, 2)

        checkpoint = torch.load(_MODEL_PATH, map_location="cpu")
        # Support both raw state_dict and {'model': state_dict, 'transforms': ...}
        if isinstance(checkpoint, dict) and "model" in checkpoint:
            backbone.load_state_dict(checkpoint["model"])
        else:
            backbone.load_state_dict(checkpoint)

        backbone.eval()
        _model = backbone

        _transforms = T.Compose([
            T.ToPILImage(),
            T.Resize((224, 224)),
            T.ToTensor(),
            T.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
        ])
        _MODEL_LOADED = True
        logger.info(f"[CNN] EfficientNet-B0 loaded from {_MODEL_PATH}")
        return True
    except Exception as e:
        logger.warning(f"[CNN] Failed to load model: {e}. Using statistical fallback.")
        return False


def _statistical_fallback(statistical_scores: dict) -> dict:
    """Average of all 7 algorithm scores when CNN is unavailable."""
    if not statistical_scores:
        return {"confidence": 0.5, "is_steganographic": False,
                "algorithm_detected": "statistical_only", "method": "fallback"}
    vals = list(statistical_scores.values())
    confidence = float(np.mean(vals))
    top_algo = max(statistical_scores, key=statistical_scores.get)
    return {
        "confidence": round(confidence, 4),
        "is_steganographic": confidence >= 0.70,
        "algorithm_detected": top_algo,
        "method": "statistical_fallback",
    }


def _run_efficientnet(img_array: np.ndarray) -> float:
    """Run EfficientNet-B0 on a single image array, return P(steganographic)."""
    import torch
    if img_array is None or img_array.size == 0:
        return 0.5
    # Ensure RGB uint8
    if img_array.dtype != np.uint8:
        img_array = (np.clip(img_array, 0, 1) * 255).astype(np.uint8)
    if len(img_array.shape) == 2:
        img_array = np.stack([img_array] * 3, axis=-1)
    elif img_array.shape[2] == 4:
        img_array = img_array[:, :, :3]

    tensor = _transforms(img_array).unsqueeze(0)
    with torch.no_grad():
        logits = _model(tensor)
        prob = torch.softmax(logits, dim=1)[0, 1].item()
    return prob


def _mlp_fuse(cnn_score: float, stat_scores: dict) -> float:
    """Simple late-fusion: weighted average of CNN score and top statistical score."""
    if not stat_scores:
        return cnn_score
    stat_mean = float(np.mean(list(stat_scores.values())))
    # CNN gets 60% weight, statistical mean 40%
    return 0.6 * cnn_score + 0.4 * stat_mean


def classify_image(img_array: np.ndarray, statistical_scores: dict) -> dict:
    """
    Classify a single image.
    Uses EfficientNet-B0 + MLP late-fusion if model is available,
    otherwise returns statistical mean as fallback.
    """
    if not _try_load_model():
        return _statistical_fallback(statistical_scores)

    try:
        cnn_score = _run_efficientnet(img_array)
        fused = _mlp_fuse(cnn_score, statistical_scores)
        top_algo = (max(statistical_scores, key=statistical_scores.get)
                    if statistical_scores else "cnn")
        return {
            "confidence": round(fused, 4),
            "is_steganographic": fused >= 0.70,
            "algorithm_detected": top_algo,
            "method": "efficientnet_b0_fused",
            "cnn_score": round(cnn_score, 4),
            "stat_score": round(float(np.mean(list(statistical_scores.values()))) if statistical_scores else 0.0, 4),
        }
    except Exception as e:
        logger.warning(f"[CNN] classify_image error: {e}. Falling back.")
        return _statistical_fallback(statistical_scores)


def classify_video_frames(
    frame_arrays: list,
    statistical_scores: dict,
    anomalous_frames: Optional[list] = None,
) -> dict:
    """
    Classify video by building a 3×3 montage of the 9 most anomalous frames,
    then running EfficientNet-B0 on the montage.
    Falls back to statistical mean if model unavailable.
    """
    if not _try_load_model():
        return _statistical_fallback(statistical_scores)

    if not frame_arrays:
        return _statistical_fallback(statistical_scores)

    try:
        import cv2

        # Pick up to 9 most anomalous frames
        if anomalous_frames and len(anomalous_frames) > 0:
            indices = anomalous_frames[:9]
            frames = [frame_arrays[i] for i in indices if i < len(frame_arrays)]
        else:
            step = max(1, len(frame_arrays) // 9)
            frames = frame_arrays[::step][:9]

        # Pad to exactly 9 frames
        while len(frames) < 9:
            frames.append(frames[-1] if frames else np.zeros((224, 224, 3), dtype=np.uint8))

        # Resize each frame to 224×224 and build 3×3 montage (672×672)
        tile_size = 224
        tiles = []
        for f in frames[:9]:
            if f is None or f.size == 0:
                tile = np.zeros((tile_size, tile_size, 3), dtype=np.uint8)
            else:
                tile = cv2.resize(f, (tile_size, tile_size))
                if len(tile.shape) == 2:
                    tile = cv2.cvtColor(tile, cv2.COLOR_GRAY2RGB)
                elif tile.shape[2] == 4:
                    tile = tile[:, :, :3]
                if tile.dtype != np.uint8:
                    tile = (np.clip(tile, 0, 1) * 255).astype(np.uint8)
            tiles.append(tile)

        row0 = np.concatenate(tiles[0:3], axis=1)
        row1 = np.concatenate(tiles[3:6], axis=1)
        row2 = np.concatenate(tiles[6:9], axis=1)
        montage = np.concatenate([row0, row1, row2], axis=0)

        cnn_score = _run_efficientnet(montage)
        fused = _mlp_fuse(cnn_score, statistical_scores)
        top_algo = (max(statistical_scores, key=statistical_scores.get)
                    if statistical_scores else "inter_frame_lsb")

        return {
            "confidence": round(fused, 4),
            "is_steganographic": fused >= 0.70,
            "algorithm_detected": top_algo,
            "method": "efficientnet_b0_montage",
            "cnn_score": round(cnn_score, 4),
            "frames_in_montage": len(frames),
        }
    except Exception as e:
        logger.warning(f"[CNN] classify_video_frames error: {e}. Falling back.")
        return _statistical_fallback(statistical_scores)


def _load_model():
    _try_load_model()
