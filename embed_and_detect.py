#!/usr/bin/env python3
"""
ShieldNet — Embed & Detect CLI
Reusable tool for live demos: embeds a message via LSB, saves the stego
image, uploads it for real analysis, and verifies extraction.

Usage:
  python embed_and_detect.py --message "secret text"
  python embed_and_detect.py --message "exfil data" --cover photo.png --out stego.png
  python embed_and_detect.py --message "test123" --api http://192.168.1.5:8000
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile

import numpy as np
import requests
from PIL import Image


def make_cover_image(size: int = 256) -> np.ndarray:
    """Generate a natural-looking noise image."""
    rng = np.random.RandomState(42)
    x = np.linspace(0, 4 * np.pi, size)
    y = np.linspace(0, 4 * np.pi, size)
    xx, yy = np.meshgrid(x, y)
    r = ((np.sin(xx) * 0.5 + 0.5) * 200 + rng.normal(0, 8, (size, size))).clip(0, 255)
    g = ((np.cos(yy) * 0.5 + 0.5) * 180 + rng.normal(0, 8, (size, size))).clip(0, 255)
    b = ((np.sin(xx + yy) * 0.5 + 0.5) * 160 + rng.normal(0, 8, (size, size))).clip(0, 255)
    return np.stack([r, g, b], axis=-1).astype(np.uint8)


def embed_lsb(img_array: np.ndarray, message: str) -> np.ndarray:
    """Embed message via LSB with null-terminator."""
    payload = message.encode("utf-8") + b"\x00\x00\x00"
    bits = "".join(f"{b:08b}" for b in payload)
    flat = img_array.flatten().copy()
    if len(bits) > len(flat):
        print(f"[!] Message too long ({len(bits)} bits) for image ({len(flat)} channels)")
        sys.exit(1)
    for i, bit in enumerate(bits):
        flat[i] = (flat[i] & 0xFE) | int(bit)
    return flat.reshape(img_array.shape)


def main():
    parser = argparse.ArgumentParser(
        description="ShieldNet — Embed a message in an image and verify detection+extraction"
    )
    parser.add_argument(
        "--message", "-m",
        default="CLASSIFIED: ShieldNet covert channel test — AES256-CBC-f8a2",
        help="Message to embed (default: sample secret)"
    )
    parser.add_argument(
        "--cover", "-c",
        default=None,
        help="Path to cover image (omit to generate a random noise PNG)"
    )
    parser.add_argument(
        "--out", "-o",
        default="stego_output.png",
        help="Where to save the stego image (default: stego_output.png)"
    )
    parser.add_argument(
        "--api",
        default="http://127.0.0.1:8000",
        help="ShieldNet API base URL (default: http://127.0.0.1:8000)"
    )
    args = parser.parse_args()

    message = args.message
    out_path = args.out

    # 1. Load or generate cover image
    if args.cover:
        if not os.path.exists(args.cover):
            print(f"[!] Cover image not found: {args.cover}")
            sys.exit(1)
        cover = np.array(Image.open(args.cover).convert("RGB"))
        print(f"[*] Cover image: {args.cover}  ({cover.shape[1]}x{cover.shape[0]})")
    else:
        cover = make_cover_image(256)
        print(f"[*] Cover image: generated 256x256 noise PNG")

    # 2. Embed
    print(f"[*] Message ({len(message)} chars): {message}")
    stego = embed_lsb(cover, message)
    Image.fromarray(stego).save(out_path)
    print(f"[*] Stego image saved to: {out_path}  ({os.path.getsize(out_path)} bytes)")

    # 3. Upload to ShieldNet
    print(f"[*] Uploading to {args.api}/api/steg/upload ...")
    try:
        with open(out_path, "rb") as f:
            resp = requests.post(
                f"{args.api}/api/steg/upload",
                files={"file": (os.path.basename(out_path), f, "image/png")},
                timeout=30,
            )
        if resp.status_code != 200:
            print(f"[!] API returned {resp.status_code}: {resp.text[:200]}")
            sys.exit(1)
        result = resp.json()
    except requests.ConnectionError:
        print(f"[!] Cannot connect to {args.api}. Is the backend running?")
        sys.exit(1)

    # 4. Print results
    confidence = result.get("confidence", 0)
    recovered = result.get("extracted_message")
    ext_status = result.get("extraction_status", "unknown")
    ext_method = result.get("extraction_method", "unknown")
    is_steg = result.get("is_steganographic", False)

    match = recovered is not None and recovered.strip() == message.strip()

    print()
    print("=" * 60)
    print(f"  Message sent       : {message}")
    print(f"  Message recovered  : {recovered or '(none)'}")
    print(f"  Match              : {match}")
    print(f"  Detection confidence: {confidence:.4f}")
    print(f"  Is steganographic  : {is_steg}")
    print(f"  Extraction method  : {ext_method}")
    print(f"  Extraction status  : {ext_status}")
    print(f"  Algorithm detected : {result.get('algorithm_detected', 'none')}")
    print(f"  Incident created   : {result.get('incident_created', False)}")
    print("=" * 60)

    if match:
        print(">>> PASS: Message embedded, detected, and extracted successfully!")
    elif recovered:
        print(f">>> PARTIAL: Message extracted but doesn't match exactly.")
    else:
        print(f">>> DETECTION ONLY: Confidence={confidence:.3f}, no message extracted ({ext_status}).")

    sys.exit(0 if match else 1)


if __name__ == "__main__":
    main()
