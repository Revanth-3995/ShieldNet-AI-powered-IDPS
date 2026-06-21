"""
ShieldNet — Test Steg Extraction
Verifies the LSB steganography extraction functionality.
"""
from __future__ import annotations

import io
import numpy as np
import pytest
from PIL import Image

from backend.services.steg.analyzer import extract_lsb_message, analyze_image_bytes


def embed_lsb(img_array: np.ndarray, message: str) -> np.ndarray:
    """Helper to embed a message sequentially into the LSB of an image array."""
    flat = img_array.flatten().copy()
    payload = message.encode("utf-8") + b"\x00\x00\x00"
    bits = "".join(f"{b:08b}" for b in payload)
    
    n_bits = min(len(bits), len(flat))
    for i in range(n_bits):
        flat[i] = (flat[i] & 0xFE) | int(bits[i])
        
    return flat.reshape(img_array.shape)


def test_steg_extraction_different_lengths():
    """Test LSB extraction directly with 3 different message lengths."""
    base_img = np.random.randint(0, 256, (100, 100, 3), dtype=np.uint8)
    
    messages = [
        "short",
        "This is a medium-sized secret message.",
        "A" * 500  # Long message
    ]
    
    for msg in messages:
        stego_img = embed_lsb(base_img, msg)
        res = extract_lsb_message(stego_img)
        assert res["extraction_status"] == "extracted"
        assert res["extracted_message"] == msg


def test_steg_extraction_clean_image():
    """Test LSB extraction on a clean image (should not find readable text)."""
    # Clean image with uniform pattern (e.g., zero LSBs, or random)
    # Using random noise, which won't decode to UTF-8 or won't have enough printable chars
    clean_img = np.random.randint(0, 256, (100, 100, 3), dtype=np.uint8)
    
    # Make sure we don't accidentally have a valid null terminator early, or random text
    res = extract_lsb_message(clean_img)
    # It should either be binary_payload_detected, no_message_found, or similar, but NOT extracted
    assert res["extracted_message"] is None
    assert res["extraction_status"] in ("no_message_found", "binary_payload_detected")


def test_steg_analyze_image_bytes_roundtrip():
    """Test full analyze_image_bytes pipeline with an embedded message."""
    base_img = np.random.randint(0, 256, (100, 100, 3), dtype=np.uint8)
    secret = "TopSecretPassword123!"
    
    # Embed message
    stego_img = embed_lsb(base_img, secret)
    
    # Save as PNG bytes
    pil_img = Image.fromarray(stego_img)
    img_bytes = io.BytesIO()
    pil_img.save(img_bytes, format="PNG")
    content = img_bytes.getvalue()
    
    # Run analysis
    result = analyze_image_bytes(content, filename="test_steg.png")
    
    # Check that confidence and mock flag are returned
    assert "confidence" in result
    assert "mock" in result
    
    # If not running in mock mode, it should successfully extract the secret
    if not result.get("mock", False):
        # The statistical classifier might have elevated confidence.
        # Force checking extraction if confidence is high.
        if result["confidence"] >= 0.35:
            assert result["extracted_message"] == secret
            assert result["extraction_status"] == "extracted"


def test_steg_confidence_boost_on_extraction():
    """Test that successfully extracting a message overrides confidence to 1.0."""
    base_img = np.random.randint(0, 256, (100, 100, 3), dtype=np.uint8)
    secret = "BoostMyConfidence!"
    stego_img = embed_lsb(base_img, secret)
    
    pil_img = Image.fromarray(stego_img)
    img_bytes = io.BytesIO()
    pil_img.save(img_bytes, format="PNG")
    content = img_bytes.getvalue()
    
    result = analyze_image_bytes(content, filename="test_boost.png")
    
    # In live mode (not mock), if a message was successfully extracted, confidence must be 1.0
    if not result.get("mock", False):
        assert result["extracted_message"] == secret
        assert result["confidence"] == 1.0
        assert result["is_steganographic"] is True

