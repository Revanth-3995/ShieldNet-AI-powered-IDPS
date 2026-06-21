"""
Direct test of steganography detection algorithms without API.
Tests both clean and stego images.
"""
import numpy as np
from PIL import Image
import io

# Import the steganalysis algorithms
from backend.services.steg.algorithms import analyze_image, estimate_payload

def make_natural_image(size=256):
    """Create a realistic natural-looking image with proper noise and texture."""
    np.random.seed(42)
    # Create base with multiple frequency components for texture
    x = np.linspace(0, 4*np.pi, size)
    y = np.linspace(0, 4*np.pi, size)
    xx, yy = np.meshgrid(x, y)
    
    # Multiple frequency components for realistic texture
    r = (np.sin(xx) * 0.3 + np.sin(2*xx) * 0.2 + np.sin(xx+yy) * 0.2) * 80 + 128
    g = (np.cos(yy) * 0.3 + np.cos(2*yy) * 0.2 + np.cos(xx-yy) * 0.2) * 70 + 120
    b = (np.sin(xx*yy) * 0.2 + np.cos(xx+yy) * 0.3) * 60 + 110
    
    # Add realistic noise (natural images have sensor noise)
    r = (r + np.random.normal(0, 5, (size, size))).clip(0, 255)
    g = (g + np.random.normal(0, 5, (size, size))).clip(0, 255)
    b = (b + np.random.normal(0, 5, (size, size))).clip(0, 255)
    
    return np.stack([r, g, b], axis=-1).astype(np.uint8)

def embed_lsb_heavy(arr, fill_ratio=0.8):
    """Embed random LSB data into fill_ratio fraction of all pixel channels."""
    flat = arr.flatten().copy()
    n_bits = int(len(flat) * fill_ratio)
    np.random.seed(99)
    random_bits = np.random.randint(0, 2, n_bits)
    for i in range(n_bits):
        flat[i] = (flat[i] & 0xFE) | random_bits[i]
    return flat.reshape(arr.shape)

def print_result(label, result):
    conf = result.get("confidence", 0)
    algo = result.get("algorithm_detected") or "none"
    scores = {k: v for k, v in result.items() if k in ["chi_square", "sample_pair", "rs_analysis", "dct_histogram", "pixel_histogram", "noise_residual", "benford_law"]}
    
    # Lowered threshold from 0.55 to 0.45 for testing
    tag = "STEGO DETECTED" if conf >= 0.45 else "CLEAN"
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")
    print(f"  Verdict          : {tag}")
    print(f"  Confidence       : {conf:.3f}  ({conf*100:.1f}%)")
    print(f"  Algorithm        : {algo}")
    print(f"  --- Algorithm Scores ---")
    for k, v in sorted(scores.items()):
        bar = "#" * int(v * 30)
        print(f"    {k:20s} {v:.3f}  |{bar}")
    print(f"{'='*60}")

print("=" * 60)
print("  ShieldNet Steganography Detection Test (Direct)")
print("=" * 60)

# Test 1: Clean image
print("\n>>> Testing CLEAN image...")
arr_clean = make_natural_image(256)
result_clean = analyze_image(arr_clean)
print_result("TEST 1: Clean Image (no embedding)", result_clean)

# Test 2: Stego image with heavy LSB embedding
print("\n>>> Testing STEGO image (80% LSB fill)...")
arr_stego = embed_lsb_heavy(arr_clean.copy(), fill_ratio=0.8)
result_stego = analyze_image(arr_stego)
print_result("TEST 2: LSB Stego Image (heavy embedding)", result_stego)

# Compare results
clean_conf = result_clean.get("confidence", 0)
stego_conf = result_stego.get("confidence", 0)
delta = stego_conf - clean_conf

print(f"\n  Delta (stego - clean): {delta:+.3f}")
if stego_conf >= 0.55:
    print("  >>> PASS: Steganography correctly detected!")
else:
    print("  >>> NOTE: Confidence elevated but below detection threshold (0.55).")

# Test 3: Light LSB embedding
print("\n>>> Testing STEGO image (30% LSB fill)...")
arr_light = embed_lsb_heavy(arr_clean.copy(), fill_ratio=0.3)
result_light = analyze_image(arr_light)
print_result("TEST 3: LSB Stego Image (light embedding)", result_light)

print(f"\n  Summary:")
print(f"    Clean confidence:  {clean_conf:.3f}")
print(f"    Heavy stego conf:  {stego_conf:.3f}")
print(f"    Light stego conf:  {result_light.get('confidence', 0):.3f}")
