"""
ShieldNet — Synthetic Steganography Dataset Generator
Generates clean and steganographic images for CNN training.
Run: python backend/utils/testing/generate_steg_dataset.py
"""
from __future__ import annotations

import argparse
import random
from pathlib import Path

import numpy as np

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("Pillow not available. Install with: pip install Pillow")
    exit(1)


def generate_natural_image(size: int = 256, seed: int = None) -> np.ndarray:
    """Generate a natural-looking image with varied textures."""
    if seed is not None:
        np.random.seed(seed)
    
    # Create smooth gradients with noise
    x = np.linspace(0, 4 * np.pi, size)
    y = np.linspace(0, 4 * np.pi, size)
    xx, yy = np.meshgrid(x, y)
    
    # Red channel: sinusoidal pattern
    r = ((np.sin(xx) * 0.5 + 0.5) * 200 + np.random.normal(0, 8, (size, size))).clip(0, 255)
    # Green channel: cosinusoidal pattern
    g = ((np.cos(yy) * 0.5 + 0.5) * 180 + np.random.normal(0, 8, (size, size))).clip(0, 255)
    # Blue channel: combined pattern
    b = ((np.sin(xx + yy) * 0.5 + 0.5) * 160 + np.random.normal(0, 8, (size, size))).clip(0, 255)
    
    return np.stack([r, g, b], axis=-1).astype(np.uint8)


def embed_lsb(img_array: np.ndarray, payload: str, fill_ratio: float = 0.8) -> np.ndarray:
    """Embed payload using LSB steganography."""
    flat = img_array.flatten().copy()
    
    # Convert payload to bits
    payload_bytes = (payload.encode() + b"\x00\x00\x00") * max(1, int(len(flat) * fill_ratio / 24))
    bits = "".join(f"{b:08b}" for b in payload_bytes)
    
    # Embed bits into LSB of pixels
    n_bits = min(len(bits), int(len(flat) * fill_ratio))
    for i in range(n_bits):
        flat[i] = (flat[i] & 0xFE) | int(bits[i % len(bits)])
    
    return flat.reshape(img_array.shape)


def embed_lsb_random(img_array: np.ndarray, fill_ratio: float = 0.8) -> np.ndarray:
    """Embed random LSB data (simulates encrypted payload)."""
    flat = img_array.flatten().copy()
    n_bits = int(len(flat) * fill_ratio)
    random_bits = np.random.randint(0, 2, n_bits)
    for i in range(n_bits):
        flat[i] = (flat[i] & 0xFE) | random_bits[i]
    return flat.reshape(img_array.shape)


def generate_dataset(
    output_dir: Path,
    n_clean: int = 500,
    n_steg: int = 500,
    img_size: int = 256,
    steg_methods: list = ["lsb_text", "lsb_random"]
):
    """Generate synthetic steganography dataset."""
    output_dir.mkdir(parents=True, exist_ok=True)
    clean_dir = output_dir / "clean"
    steg_dir = output_dir / "steg"
    clean_dir.mkdir(exist_ok=True)
    steg_dir.mkdir(exist_ok=True)
    
    print(f"[*] Generating {n_clean} clean images...")
    for i in range(n_clean):
        img = generate_natural_image(img_size, seed=i)
        img_pil = Image.fromarray(img)
        img_pil.save(clean_dir / f"clean_{i:05d}.png")
        if (i + 1) % 50 == 0:
            print(f"    Generated {i + 1}/{n_clean} clean images")
    
    print(f"[*] Generating {n_steg} steganographic images...")
    steg_per_method = n_steg // len(steg_methods)
    
    for method_idx, method in enumerate(steg_methods):
        start_idx = method_idx * steg_per_method
        end_idx = start_idx + steg_per_method if method_idx < len(steg_methods) - 1 else n_steg
        
        for i in range(start_idx, end_idx):
            img = generate_natural_image(img_size, seed=i + n_clean)
            
            if method == "lsb_text":
                # Embed text payload
                payload = f"SECRET_DATA_{i}_CLASSIFIED"
                steg_img = embed_lsb(img, payload, fill_ratio=0.7)
            elif method == "lsb_random":
                # Embed random bits (simulates encryption)
                steg_img = embed_lsb_random(img, fill_ratio=0.8)
            else:
                steg_img = embed_lsb_random(img, fill_ratio=0.7)
            
            img_pil = Image.fromarray(steg_img)
            img_pil.save(steg_dir / f"steg_{method}_{i:05d}.png")
            
            if (i + 1) % 50 == 0:
                print(f"    Generated {i + 1}/{n_steg} steg images")
    
    print(f"\n[SUCCESS] Dataset generation complete!")
    print(f"    Clean images: {len(list(clean_dir.glob('*.png')))}")
    print(f"    Steg images: {len(list(steg_dir.glob('*.png')))}")
    print(f"    Output directory: {output_dir}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate synthetic steganography dataset for CNN training"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("data/steg_dataset"),
        help="Output directory for dataset (default: data/steg_dataset)"
    )
    parser.add_argument(
        "--n-clean",
        type=int,
        default=500,
        help="Number of clean images to generate (default: 500)"
    )
    parser.add_argument(
        "--n-steg",
        type=int,
        default=500,
        help="Number of steganographic images to generate (default: 500)"
    )
    parser.add_argument(
        "--img-size",
        type=int,
        default=256,
        help="Image size in pixels (default: 256)"
    )
    parser.add_argument(
        "--methods",
        nargs="+",
        default=["lsb_text", "lsb_random"],
        choices=["lsb_text", "lsb_random"],
        help="Steganography methods to use (default: lsb_text lsb_random)"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("  ShieldNet Synthetic Steganography Dataset Generator")
    print("=" * 60)
    print(f"  Output directory: {args.output_dir}")
    print(f"  Clean images: {args.n_clean}")
    print(f"  Steg images: {args.n_steg}")
    print(f"  Image size: {args.img_size}x{args.img_size}")
    print(f"  Methods: {', '.join(args.methods)}")
    print("=" * 60)
    
    generate_dataset(
        output_dir=args.output_dir,
        n_clean=args.n_clean,
        n_steg=args.n_steg,
        img_size=args.img_size,
        steg_methods=args.methods
    )


if __name__ == "__main__":
    main()
