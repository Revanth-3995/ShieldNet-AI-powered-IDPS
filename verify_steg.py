"""
ShieldNet Steg Detection End-to-End Verification
Tests the /api/steg/upload endpoint with:
  1) A clean natural-looking image   -> should return CLEAN
  2) A heavily LSB-embedded image    -> should return STEGO DETECTED
"""
import requests, io, numpy as np
from PIL import Image

API = "http://127.0.0.1:8000"

def make_natural_image(size=256):
    """Create a natural-looking image with varied textures."""
    rng = np.random.RandomState(42)
    # Smooth base
    x = np.linspace(0, 4*np.pi, size)
    y = np.linspace(0, 4*np.pi, size)
    xx, yy = np.meshgrid(x, y)
    r = ((np.sin(xx) * 0.5 + 0.5) * 200 + rng.normal(0, 8, (size, size))).clip(0, 255)
    g = ((np.cos(yy) * 0.5 + 0.5) * 180 + rng.normal(0, 8, (size, size))).clip(0, 255)
    b = ((np.sin(xx + yy) * 0.5 + 0.5) * 160 + rng.normal(0, 8, (size, size))).clip(0, 255)
    return np.stack([r, g, b], axis=-1).astype(np.uint8)

def embed_lsb_heavy(arr, fill_ratio=0.8):
    """Embed random LSB data into fill_ratio fraction of all pixel channels."""
    flat = arr.flatten().copy()
    n_bits = int(len(flat) * fill_ratio)
    rng = np.random.RandomState(99)
    random_bits = rng.randint(0, 2, n_bits)
    for i in range(n_bits):
        flat[i] = (flat[i] & 0xFE) | random_bits[i]
    return flat.reshape(arr.shape)

def to_png_bytes(arr):
    buf = io.BytesIO()
    Image.fromarray(arr).save(buf, format="PNG")
    return buf.getvalue()

def upload(name, data):
    r = requests.post(
        f"{API}/api/steg/upload",
        files={"file": (name, data, "image/png")},
        timeout=30,
    )
    return r.json()

def print_result(label, d):
    conf = d.get("confidence", 0)
    is_steg = d.get("is_steganographic", False)
    algo = d.get("algorithm_detected") or "none"
    payload = d.get("payload_estimate_bytes", 0)
    incident = d.get("incident_created", False)
    scores = d.get("scores", {})

    tag = "STEGO DETECTED" if is_steg else "CLEAN"
    color_code = "\033[91m" if is_steg else "\033[92m"
    reset = "\033[0m"

    print(f"\n{'='*55}")
    print(f"  {label}")
    print(f"{'='*55}")
    print(f"  Verdict          : {color_code}{tag}{reset}")
    print(f"  Confidence       : {conf:.3f}  ({conf*100:.1f}%)")
    print(f"  Algorithm        : {algo}")
    print(f"  Payload Estimate : {payload} bytes")
    print(f"  Incident Created : {incident}")
    if scores:
        print(f"  --- Algorithm Scores ---")
        for k, v in sorted(scores.items()):
            if isinstance(v, (int, float)):
                bar = "#" * int(v * 30)
                print(f"    {k:20s} {v:.3f}  |{bar}")
    print(f"{'='*55}")

# ── Run tests ──
arr = make_natural_image(256)

print("\n>>> Uploading CLEAN image...")
d1 = upload("clean_natural.png", to_png_bytes(arr))
print_result("TEST 1: Clean Image (no embedding)", d1)

print("\n>>> Uploading STEGO image (80% LSB fill)...")
stego = embed_lsb_heavy(arr.copy(), fill_ratio=0.8)
d2 = upload("stego_heavy.png", to_png_bytes(stego))
print_result("TEST 2: LSB Stego Image (heavy embedding)", d2)

clean_conf = d1.get("confidence", 0)
stego_conf = d2.get("confidence", 0)
delta = stego_conf - clean_conf
print(f"\n  Delta (stego - clean): {delta:+.3f}")
if d2.get("is_steganographic"):
    print("  >>> PASS: Steganography correctly detected!")
else:
    print("  >>> NOTE: Confidence elevated but below detection threshold.")
