"""
ShieldNet — Steganalysis Attack Simulator
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

import numpy as np


def lsb_embed_image(image_path: str, payload: str, output_path: str) -> None:
    try:
        from PIL import Image
    except ImportError:
        print("Pillow required: pip install Pillow")
        sys.exit(1)

    img = Image.open(image_path).convert("RGB")
    arr = np.array(img, dtype=np.uint8)
    payload_bytes = payload.encode("utf-8") + b"\x00\x00\x00"
    bits = "".join(f"{b:08b}" for b in payload_bytes)
    flat = arr.flatten()
    if len(bits) > len(flat):
        print(f"Payload too large ({len(bits)} bits > {len(flat)} pixels)")
        sys.exit(1)
    for i, bit in enumerate(bits):
        flat[i] = (flat[i] & 0xFE) | int(bit)
    modified = flat.reshape(arr.shape)
    Image.fromarray(modified).save(output_path)
    print(f"[+] LSB embedded '{payload[:40]}' into {output_path}")


def lsb_embed_video(video_path: str, payload: str, output_path: str) -> None:
    try:
        import cv2
    except ImportError:
        print("OpenCV required: pip install opencv-python")
        sys.exit(1)

    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        print(f"Cannot open video: {video_path}")
        sys.exit(1)
    fps = cap.get(cv2.CAP_PROP_FPS) or 25
    w = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    h = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    fourcc = cv2.VideoWriter_fourcc(*"mp4v")
    out = cv2.VideoWriter(output_path, fourcc, fps, (w, h))
    payload_bytes = payload.encode("utf-8") + b"\x00\x00\x00"
    bits = "".join(f"{b:08b}" for b in payload_bytes)
    bit_idx = 0
    frame_idx = 0
    while True:
        ret, frame = cap.read()
        if not ret:
            break
        if frame_idx == 1 and bit_idx < len(bits):  # Embed in frame 1
            flat = frame.flatten()
            for i in range(min(len(bits) - bit_idx, len(flat))):
                flat[i] = (flat[i] & 0xFE) | int(bits[bit_idx + i])
            bit_idx += min(len(bits) - bit_idx, len(flat))
            frame = flat.reshape(frame.shape)
        out.write(frame)
        frame_idx += 1
    cap.release()
    out.release()
    print(f"[+] LSB embedded '{payload[:40]}' into {output_path}")


def upload_file(file_path: str, proxy_url: str) -> None:
    import requests
    with open(file_path, "rb") as f:
        content_type = "image/jpeg" if file_path.endswith((".jpg", ".jpeg")) else \
                       "image/png" if file_path.endswith(".png") else \
                       "video/mp4" if file_path.endswith(".mp4") else "application/octet-stream"
        try:
            resp = requests.post(
                f"{proxy_url}/api/steg/upload",
                files={"file": (Path(file_path).name, f, content_type)},
                timeout=60,
            )
            print(f"[+] Upload response: {resp.status_code} {resp.text[:200]}")
        except Exception as e:
            print(f"[-] Upload failed: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(description="ShieldNet Steg Attack Simulator")
    parser.add_argument("--image", help="Path to image file to embed payload into")
    parser.add_argument("--video", help="Path to video file to embed payload into")
    parser.add_argument("--payload", default="EXFIL: test_payload_data", help="Payload string to embed")
    parser.add_argument("--api", default="http://127.0.0.1:8000", help="ShieldNet API base URL")
    args = parser.parse_args()

    if not args.image and not args.video:
        parser.print_help()
        sys.exit(1)

    with tempfile.TemporaryDirectory() as tmpdir:
        if args.image:
            ext = Path(args.image).suffix
            out = os.path.join(tmpdir, f"steg_output{ext}")
            
            # If the image doesn't exist, generate a dummy one for testing
            if not os.path.exists(args.image):
                from PIL import Image
                arr = np.random.randint(0, 256, (100, 100, 3), dtype=np.uint8)
                Image.fromarray(arr).save(args.image)
                print(f"Generated dummy image at {args.image}")
                
            lsb_embed_image(args.image, args.payload, out)
            upload_file(out, args.api)
            
        elif args.video:
            ext = Path(args.video).suffix
            out = os.path.join(tmpdir, f"steg_output{ext}")
            
            if not os.path.exists(args.video):
                print(f"Video {args.video} does not exist. Please provide a valid video.")
                sys.exit(1)
                
            lsb_embed_video(args.video, args.payload, out)
            upload_file(out, args.api)


if __name__ == "__main__":
    main()
