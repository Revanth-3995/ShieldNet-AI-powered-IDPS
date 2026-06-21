"""Quick end-to-end test for the ShieldNet Steg Detection API."""
import requests
import io
import numpy as np
from PIL import Image

API = "http://127.0.0.1:8000"

def make_gradient_image(size=300):
    arr = np.zeros((size, size, 3), dtype=np.uint8)
    for i in range(size):
        arr[i, :, 0] = int(i * 255 / size)
        arr[i, :, 1] = int((size - i) * 255 / size)
        arr[i, :, 2] = 128
    return arr

def embed_lsb(arr, payload_str):
    payload = (payload_str * 100).encode()
    bits = "".join(f"{b:08b}" for b in payload)
    flat = arr.flatten()
    for i, bit in enumerate(bits[: len(flat)]):
        flat[i] = (flat[i] & 0xFE) | int(bit)
    return flat.reshape(arr.shape)

def img_to_bytes(arr):
    img = Image.fromarray(arr.astype(np.uint8))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()

def upload_and_analyze(name, data):
    r = requests.post(
        f"{API}/api/steg/upload",
        files={"file": (name, data, "image/png")},
        timeout=30,
    )
    return r.json()

print("=" * 55)
print("  ShieldNet Steg Detection API Test")
print("=" * 55)

arr = make_gradient_image(300)

# -- Clean Image --
clean_bytes = img_to_bytes(arr)
d = upload_and_analyze("clean_test.png", clean_bytes)
print("\n[CLEAN IMAGE]")
print(f"  Status             : {d.get('status')}")
print(f"  Confidence         : {d.get('confidence', 0):.3f}")
print(f"  Is Steganographic  : {d.get('is_steganographic')}")
print(f"  Algorithm Detected : {d.get('algorithm_detected')}")
print(f"  Payload Estimate   : {d.get('payload_estimate_bytes', 0)} bytes")
print(f"  Incident Created   : {d.get('incident_created', False)}")

# -- Stego Image --
stego_arr = embed_lsb(arr.copy(), "CLASSIFIED EXFIL PAYLOAD")
stego_bytes = img_to_bytes(stego_arr)
d2 = upload_and_analyze("stego_test.png", stego_bytes)
print("\n[STEGO IMAGE — LSB embedded]")
print(f"  Status             : {d2.get('status')}")
print(f"  Confidence         : {d2.get('confidence', 0):.3f}")
print(f"  Is Steganographic  : {d2.get('is_steganographic')}")
print(f"  Algorithm Detected : {d2.get('algorithm_detected')}")
print(f"  Payload Estimate   : {d2.get('payload_estimate_bytes', 0)} bytes")
print(f"  Incident Created   : {d2.get('incident_created', False)}")

scores = d2.get("scores") or {}
if scores:
    print("\n  Statistical Algorithm Scores:")
    for k, v in scores.items():
        if isinstance(v, (int, float)):
            bar = "█" * int(v * 20)
            print(f"    {k:20s} {v:.3f}  {bar}")

print("\n" + "=" * 55)
print("  Confidence Delta (stego - clean):", round(d2.get("confidence", 0) - d.get("confidence", 0), 3))
print("=" * 55)
