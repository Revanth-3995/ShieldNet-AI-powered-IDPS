#!/usr/bin/env python3
"""Generate a synthetic training dataset for the steg CNN."""
import os, sys, random
from pathlib import Path

CLEAN_DIR = Path("data/clean")
STEG_DIR = Path("data/steg")
N_IMAGES = 1000
SIZE = (128, 128)

def main():
    CLEAN_DIR.mkdir(parents=True, exist_ok=True)
    STEG_DIR.mkdir(parents=True, exist_ok=True)

    try:
        import numpy as np
        from PIL import Image
    except ImportError:
        print("Install Pillow and numpy: pip install Pillow numpy")
        sys.exit(1)

    print(f"Generating {N_IMAGES} clean images...")
    for i in range(N_IMAGES):
        arr = np.random.randint(0, 255, (*SIZE, 3), dtype="uint8")
        # Add some structure so it resembles natural images
        for _ in range(random.randint(3, 8)):
            x1, y1 = random.randint(0,SIZE[0]-1), random.randint(0,SIZE[1]-1)
            x2, y2 = random.randint(0,SIZE[0]-1), random.randint(0,SIZE[1]-1)
            color = [random.randint(50,200) for _ in range(3)]
            arr[min(x1,x2):max(x1,x2), min(y1,y2):max(y1,y2)] = color
        Image.fromarray(arr).save(CLEAN_DIR / f"clean_{i:04d}.png")
        if (i+1) % 100 == 0: print(f"  {i+1}/{N_IMAGES}")

    print(f"Generating {N_IMAGES} LSB-embedded steg images...")
    payload = "STOLEN_DATA:" + "X" * 500
    payload_bytes = payload.encode() + b"\x00\x00\x00"
    bits = "".join(f"{b:08b}" for b in payload_bytes)

    for i in range(N_IMAGES):
        src = CLEAN_DIR / f"clean_{i:04d}.png"
        img = Image.open(src).convert("RGB")
        arr = np.array(img, dtype="uint8")
        flat = arr.flatten()
        for j, bit in enumerate(bits[:len(flat)]):
            flat[j] = (flat[j] & 0xFE) | int(bit)
        Image.fromarray(flat.reshape(arr.shape)).save(STEG_DIR / f"steg_{i:04d}.png")
        if (i+1) % 100 == 0: print(f"  {i+1}/{N_IMAGES}")

    print(f"\nDone! {N_IMAGES} clean images in data/clean/")
    print(f"      {N_IMAGES} steg images in data/steg/")
    print(f"\nNext: python -m backend.services.steg.cnn.train_cnn \\")
    print(f"        --clean-dir ./data/clean --steg-dir ./data/steg \\")
    print(f"        --epochs 15 --output models/steg_cnn.pth")

if __name__ == "__main__":
    main()
