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


def embed_lsb(image_path: str, payload: str, out_path: str) -> bool:
    """Embed payload via plain LSB substitution with null-terminator."""
    import numpy as np
    from PIL import Image

    img = Image.open(image_path).convert("RGB")
    a = np.array(img, dtype="uint8")
    bits = "".join(f"{b:08b}" for b in (payload.encode("utf-8") + b"\x00\x00\x00"))
    flat = a.flatten()
    if len(bits) > len(flat):
        print(f"[!] Payload too large ({len(bits)} bits) for image ({len(flat)} pixels)")
        return False
    for i, bit in enumerate(bits):
        flat[i] = (flat[i] & 0xFE) | int(bit)
    Image.fromarray(flat.reshape(a.shape)).save(out_path)
    return True


def main():
    print()
    print("=" * 60)
    print("  ShieldNet Demo - Steganography: Embed -> Detect -> Extract")
    print("=" * 60)

    # 1. Create cover image
    cover = make_cover_image()
    steg_path = tempfile.mktemp(suffix=".png")

    print(f"\n[1/3] Embedding hidden payload in image...")
    print(f"  Cover image : {cover}")
    print(f"  Payload     : '{PAYLOAD[:60]}...'")

    ok = embed_lsb(cover, PAYLOAD, steg_path)
    if not ok:
        print("[!] Embedding failed.")
        os.unlink(cover)
        sys.exit(1)
    print(f"  Stego image : {steg_path}")
    print(f"  LSB embedding: done ({os.path.getsize(steg_path)} bytes)")

    # 2. Upload to ShieldNet for real analysis
    print(f"\n[2/3] Uploading to ShieldNet for analysis...")
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
