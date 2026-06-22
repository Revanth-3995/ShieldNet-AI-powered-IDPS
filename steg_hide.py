#!/usr/bin/env python3
"""
ShieldNet Demo — Image Steganography: Embed → Detect → Extract
Run: python steg_hide.py

Embeds a real LSB payload in a generated PNG, uploads it to the ShieldNet
/api/steg/upload endpoint for real statistical analysis, and prints the
recovered message alongside the detection confidence.
"""
import sys
import os
import tempfile

import requests

API = "http://127.0.0.1:8000"
ATTACKER_IP = "172.16.0.88"
PAYLOAD = (
    "CLASSIFIED: Q3 customer database dump — "
    "847,293 records — encryption key: AES256-CBC-f8a2..."
)


def make_cover_image() -> str:
    """Create a 256×256 random-noise PNG via Pillow."""
    try:
        from PIL import Image
        import numpy as np

        arr = np.random.randint(100, 200, (256, 256, 3), dtype="uint8")
        path = tempfile.mktemp(suffix=".png")
        Image.fromarray(arr).save(path)
        return path
    except ImportError:
        print("[!] Pillow is required. Install with: pip install Pillow")
        sys.exit(1)


import time
from concurrent.futures import ThreadPoolExecutor
import numpy as np
from PIL import Image


def load_image(image_path: str):
    """Load image from disk."""
    img = Image.open(image_path).convert("RGB")
    return np.array(img, dtype="uint8")


def prepare_payload_bits(payload: str):
    """Prepare payload bits using fast numpy vectorization."""
    payload_bytes = payload.encode("utf-8") + b"\x00\x00\x00"
    byte_array = np.frombuffer(payload_bytes, dtype=np.uint8)
    return np.unpackbits(byte_array)


def embed_lsb(img_array: np.ndarray, bits_array: np.ndarray) -> np.ndarray:
    """Embed payload via vectorized plain LSB substitution."""
    flat = img_array.flatten()
    if len(bits_array) > len(flat):
        raise ValueError(f"Payload too large ({len(bits_array)} bits) for image ({len(flat)} pixels)")

    # Vectorized bitwise operations (avoids slow Python loops)
    flat[:len(bits_array)] = (flat[:len(bits_array)] & 0xFE) | bits_array
    return flat.reshape(img_array.shape)


def save_image(img_array: np.ndarray, out_path: str):
    """Save image to disk."""
    Image.fromarray(img_array).save(out_path)
    return True


def verify_extraction(img_array: np.ndarray) -> str:
    """Extract and verify the hidden message locally using vectorization."""
    flat = img_array.flatten()
    lsb_bits = flat & 1

    # Pack bits to bytes
    valid_bits = len(lsb_bits) - (len(lsb_bits) % 8)
    byte_vals = np.packbits(lsb_bits[:valid_bits])

    # Vectorized search for 3 consecutive null bytes
    zero_indices = np.where(byte_vals == 0)[0]
    if len(zero_indices) >= 3:
        diffs = np.diff(zero_indices)
        run_starts = np.where((diffs[:-1] == 1) & (diffs[1:] == 1))[0]
        if len(run_starts) > 0:
            end_idx = zero_indices[run_starts[0]]
            byte_vals = byte_vals[:end_idx]

    raw = byte_vals.tobytes()
    try:
        return raw.decode("utf-8").rstrip("\x00")
    except UnicodeDecodeError:
        return ""


def main():
    print()
    print("=" * 60)
    print("  ShieldNet Demo - Steganography: Embed -> Detect -> Extract")
    print("=" * 60)

    total_start = time.perf_counter()

    # 1. Create cover image
    cover = make_cover_image()
    steg_path = tempfile.mktemp(suffix=".png")

    print(f"\n[1/3] Embedding hidden payload in image (Concurrent & Vectorized)...")
    print(f"  Cover image : {cover}")
    print(f"  Payload     : '{PAYLOAD[:60]}...'")

    embed_start = time.perf_counter()
    # Using ThreadPoolExecutor to run tasks concurrently
    with ThreadPoolExecutor(max_workers=5) as executor:
        # Thread 1 -> Load image
        future_img = executor.submit(load_image, cover)

        # Thread 2 -> Prepare payload bits
        future_bits = executor.submit(prepare_payload_bits, PAYLOAD)

        # Thread 3 -> Embed message into image (Wait for 1 & 2)
        try:
            img_array = future_img.result()
            bits_array = future_bits.result()

            future_embed = executor.submit(embed_lsb, img_array, bits_array)
            stego_array = future_embed.result()

            # Execute Thread 4 and Thread 5 simultaneously
            # Thread 4 -> Save stego image
            future_save = executor.submit(save_image, stego_array, steg_path)
            # Thread 5 -> Verify extraction
            future_verify = executor.submit(verify_extraction, stego_array)

            future_save.result()
            local_extracted = future_verify.result()

            if local_extracted.strip() != PAYLOAD.strip():
                print("[!] Local extraction verification failed.")
                ok = False
            else:
                ok = True
        except ValueError as e:
            print(f"[!] Embedding failed: {e}")
            ok = False

    embed_time = time.perf_counter() - embed_start

    if not ok:
        print("[!] Embedding pipeline failed.")
        os.unlink(cover)
        sys.exit(1)

    print(f"  Stego image : {steg_path}")
    print(f"  LSB embedding: done ({os.path.getsize(steg_path)} bytes)")
    print(f"  Execution time (Embedding Pipeline): {embed_time:.4f} sec (Expected speedup: Huge due to vectorization & threads)")

    # 2. Upload to ShieldNet for real analysis
    print(f"\n[2/3] Uploading to ShieldNet for analysis...")
    api_start = time.perf_counter()
    try:
        with open(steg_path, "rb") as f:
            resp = requests.post(
                f"{API}/api/steg/upload",
                files={"file": ("quarterly_report.png", f, "image/png")},
                data={"source_ip": ATTACKER_IP},
                timeout=30,
            )
        result = resp.json()
    except Exception as e:
        print(f"  [!] Backend not reachable: {e}")
        os.unlink(cover)
        os.unlink(steg_path)
        sys.exit(1)
    api_time = time.perf_counter() - api_start

    # 3. Print results
    confidence = result.get("confidence", 0)
    is_steg = result.get("is_steganographic", False)
    algo = result.get("algorithm_detected") or "none"
    extracted = result.get("extracted_message")
    ext_status = result.get("extraction_status", "unknown")
    ext_method = result.get("extraction_method", "unknown")
    incident_id = result.get("incident_id")

    print(f"\n[3/3] Detection Results:")
    print(f"  {'='*50}")
    print(f"  Detection confidence : {confidence:.3f}  ({confidence*100:.1f}%)")
    print(f"  Is steganographic    : {is_steg}")
    print(f"  Algorithm detected   : {algo}")
    print(f"  Extraction status    : {ext_status}")
    print(f"  Extraction method    : {ext_method}")
    print(f"  Incident ID          : {incident_id}")
    print(f"  {'='*50}")

    print(f"\n  Message Comparison:")
    print(f"    Sent     : {PAYLOAD}")
    if extracted:
        print(f"    Recovered: {extracted}")
        match = extracted.strip() == PAYLOAD.strip()
        tag = "MATCH" if match else "MISMATCH"
        print(f"    Result   : {tag}")
    else:
        print(f"    Recovered: (none — {ext_status})")
        match = False

    # Cleanup
    os.unlink(cover)
    os.unlink(steg_path)

    print(f"\n{'='*60}")
    if match:
        print("  >>> PASS: Hidden message successfully embedded, detected, and extracted!")
    else:
        print("  >>> Detection completed. Check dashboard for full forensic details.")
    print(f"  Source IP {ATTACKER_IP} - check Panel 4 (Image Steg) on dashboard.")
    print(f"{'='*60}\n")

    sys.exit(0 if match else 1)


if __name__ == "__main__":
    main()
