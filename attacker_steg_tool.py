#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║         ATTACKER LSB STEGANOGRAPHY TOOL                  ║
║  Simulates how an attacker hides messages in images      ║
║  (Used in ShieldNet IDPS demo to generate stego images)  ║
╚══════════════════════════════════════════════════════════╝

This is the ATTACKER SIDE of the demo.
Run this to embed a secret message into any PNG/JPG image.
Then upload the output to ShieldNet dashboard to see it get DETECTED.

Usage (GUI):   python attacker_steg_tool.py
Usage (CLI):   python attacker_steg_tool.py --image photo.png --message "secret" --out stego.png
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

# Force UTF-8 output on Windows to handle special characters
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import numpy as np

try:
    from PIL import Image, ImageDraw, ImageFont
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


# ─────────────────────────────────────────────────────────────
# Core LSB embed / extract (attacker uses embed, ShieldNet extracts)
# ─────────────────────────────────────────────────────────────

def embed_lsb(img_array: np.ndarray, message: str) -> np.ndarray:
    """
    Embed a secret message into the LSB of every channel byte.
    Message is null-terminated with 3x '\\x00' so extraction knows where to stop.
    Visual change: < 0.4% of pixels altered by ±1 — imperceptible to human eye.
    """
    payload = message.encode("utf-8") + b"\x00\x00\x00"
    bits = "".join(f"{b:08b}" for b in payload)
    flat = img_array.flatten().copy()
    n_bits = len(bits)
    capacity = len(flat)
    if n_bits > capacity:
        raise ValueError(
            f"Message too long! Needs {n_bits} bits but image only has "
            f"{capacity} channels. Use a larger image or shorter message."
        )
    for i, bit in enumerate(bits):
        flat[i] = (flat[i] & 0xFE) | int(bit)
    return flat.reshape(img_array.shape)


def extract_lsb(img_array: np.ndarray, max_bytes: int = 8192) -> str | None:
    """
    Extract any LSB-encoded message from an image.
    Returns decoded text if found, None if no readable message.
    """
    flat = img_array.flatten()
    max_bits = min(len(flat), max_bytes * 8)
    bits = [str(flat[i] & 1) for i in range(max_bits)]
    byte_list = []
    null_count = 0
    for i in range(0, len(bits) - 7, 8):
        byte_val = int("".join(bits[i:i + 8]), 2)
        if byte_val == 0:
            null_count += 1
            if null_count >= 3:
                break
        else:
            null_count = 0
        byte_list.append(byte_val)
    if not byte_list:
        return None
    raw = bytes(byte_list)
    try:
        text = raw.decode("utf-8").rstrip("\x00")
        printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t") / max(len(text), 1)
        return text if printable > 0.7 and len(text) >= 3 else None
    except UnicodeDecodeError:
        return None


def get_capacity(img_array: np.ndarray) -> int:
    """Return max message bytes this image can hold."""
    return (img_array.size - 24) // 8  # leave room for 3-null terminator


# ─────────────────────────────────────────────────────────────
# GUI  (Tkinter)
# ─────────────────────────────────────────────────────────────

def launch_gui():
    try:
        import tkinter as tk
        from tkinter import ttk, filedialog, messagebox
        from tkinter.scrolledtext import ScrolledText
    except ImportError:
        print("[!] Tkinter not available. Use CLI mode: --image, --message, --out")
        sys.exit(1)

    if not PIL_AVAILABLE:
        messagebox.showerror("Missing Dependency", "Pillow is required.\nRun: pip install Pillow")
        sys.exit(1)

    # ── Root window ──────────────────────────────────────────
    root = tk.Tk()
    root.title("⚔️  Attacker LSB Steganography Tool  |  ShieldNet Demo")
    root.geometry("780x700")
    root.resizable(True, True)
    root.configure(bg="#0d1117")

    # Colour palette
    BG         = "#0d1117"
    PANEL      = "#161b22"
    BORDER     = "#30363d"
    RED        = "#ff3333"
    RED_DARK   = "#aa0000"
    GREEN      = "#39d353"
    YELLOW     = "#e3b341"
    TEXT       = "#e6edf3"
    MUTED      = "#8b949e"
    ENTRY_BG   = "#21262d"
    ACCENT     = "#ff4444"

    state = {
        "cover_path": None,
        "cover_img":  None,
    }

    # ── Styles ───────────────────────────────────────────────
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("TFrame", background=BG)
    style.configure("Panel.TFrame", background=PANEL)
    style.configure("TLabel", background=BG, foreground=TEXT, font=("Consolas", 10))
    style.configure("Header.TLabel", background=BG, foreground=RED,
                    font=("Consolas", 14, "bold"))
    style.configure("Muted.TLabel", background=PANEL, foreground=MUTED,
                    font=("Consolas", 9))
    style.configure("Status.TLabel", background=BG, foreground=MUTED,
                    font=("Consolas", 9, "italic"))
    style.configure("Red.TButton", background=RED_DARK, foreground=TEXT,
                    font=("Consolas", 11, "bold"), padding=8)
    style.map("Red.TButton",
              background=[("active", RED), ("pressed", "#880000")])
    style.configure("TProgressbar", troughcolor=PANEL, background=GREEN, thickness=6)

    # ── Header ───────────────────────────────────────────────
    hdr = tk.Frame(root, bg=RED_DARK, pady=14)
    hdr.pack(fill="x")

    tk.Label(hdr, text="⚔️  ATTACKER LSB STEGANOGRAPHY TOOL",
             bg=RED_DARK, fg="white", font=("Consolas", 16, "bold")).pack()
    tk.Label(hdr, text="Embed a covert message into any image — then upload to ShieldNet to trigger detection",
             bg=RED_DARK, fg="#ffcccc", font=("Consolas", 9)).pack()

    # ── Main content ─────────────────────────────────────────
    content = ttk.Frame(root, padding=16)
    content.pack(fill="both", expand=True)
    content.configure(style="TFrame")

    # ── Step 1: Choose Image ──────────────────────────────────
    def section(parent, title, step_num):
        f = tk.Frame(parent, bg=PANEL, relief="flat", bd=0, pady=10, padx=12)
        f.pack(fill="x", pady=(0, 10))
        tk.Label(f, text=f"  STEP {step_num}  ", bg=ACCENT, fg="white",
                 font=("Consolas", 8, "bold"), padx=4).pack(side="left", anchor="n", pady=2)
        tk.Label(f, text=f" {title}", bg=PANEL, fg=TEXT,
                 font=("Consolas", 11, "bold")).pack(side="left", anchor="n", pady=2)
        sep = tk.Frame(f, bg=BORDER, height=1)
        sep.pack(fill="x", pady=(6, 0))
        body = tk.Frame(f, bg=PANEL)
        body.pack(fill="x", pady=(8, 0))
        return body

    # Step 1
    s1 = section(content, "Choose your cover image  (PNG / JPG / BMP)", 1)

    img_path_var = tk.StringVar(value="No image selected")
    img_info_var = tk.StringVar(value="")

    img_row = tk.Frame(s1, bg=PANEL)
    img_row.pack(fill="x")

    img_lbl = tk.Label(img_row, textvariable=img_path_var, bg=ENTRY_BG, fg=MUTED,
                       font=("Consolas", 9), anchor="w", padx=8, pady=6, width=55)
    img_lbl.pack(side="left", fill="x", expand=True)

    def choose_image():
        path = filedialog.askopenfilename(
            title="Select a cover image",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp *.webp *.tiff"),
                       ("All files", "*.*")]
        )
        if not path:
            return
        try:
            img = Image.open(path).convert("RGB")
            arr = np.array(img)
            cap = get_capacity(arr)
            state["cover_path"] = path
            state["cover_img"]  = arr
            img_path_var.set(os.path.basename(path))
            img_lbl.config(fg=GREEN)
            img_info_var.set(
                f"  ✓  {img.width}×{img.height} px  |  {os.path.getsize(path)//1024} KB  |  "
                f"Capacity: {cap} bytes  ({cap*8:,} bits)"
            )
            update_capacity_bar()
            status_var.set(f"Cover image loaded: {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open image:\n{e}")

    tk.Button(img_row, text=" 📂  Browse ", bg="#21262d", fg=TEXT,
              font=("Consolas", 10), relief="flat", cursor="hand2",
              activebackground=BORDER, command=choose_image).pack(side="left", padx=(6, 0))

    tk.Label(s1, textvariable=img_info_var, bg=PANEL, fg=GREEN,
             font=("Consolas", 9)).pack(anchor="w", pady=(2, 0))

    # Step 2: Secret message
    s2 = section(content, "Type your secret message to hide", 2)

    msg_frame = tk.Frame(s2, bg=PANEL)
    msg_frame.pack(fill="x")
    msg_text = ScrolledText(msg_frame, height=4, bg=ENTRY_BG, fg=TEXT,
                            insertbackground=TEXT, font=("Consolas", 10),
                            relief="flat", bd=0, wrap="word")
    msg_text.pack(fill="x")
    msg_text.insert("end", "CLASSIFIED: Exfiltrating 10,000 user credentials — AES256-CBC")

    # Live character / capacity counter
    cap_frame = tk.Frame(s2, bg=PANEL)
    cap_frame.pack(fill="x", pady=(4, 0))
    char_var  = tk.StringVar(value="Chars: 61")
    usage_var = tk.StringVar(value="")
    tk.Label(cap_frame, textvariable=char_var, bg=PANEL, fg=MUTED,
             font=("Consolas", 8)).pack(side="left")
    tk.Label(cap_frame, textvariable=usage_var, bg=PANEL, fg=YELLOW,
             font=("Consolas", 8)).pack(side="right")

    cap_bar = ttk.Progressbar(s2, style="TProgressbar", maximum=100, value=0)
    cap_bar.pack(fill="x", pady=(2, 0))

    def update_capacity_bar(*_):
        msg = msg_text.get("1.0", "end").strip()
        char_var.set(f"Chars: {len(msg)}  |  Bytes: {len(msg.encode('utf-8'))}")
        if state["cover_img"] is not None:
            cap = get_capacity(state["cover_img"])
            used = len(msg.encode("utf-8")) + 3  # +3 for null terminator
            pct  = min(100, int(used / max(cap, 1) * 100))
            cap_bar["value"] = pct
            color = GREEN if pct < 60 else (YELLOW if pct < 90 else RED)
            style.configure("TProgressbar", background=color)
            usage_var.set(f"{used:,} / {cap:,} bytes  ({pct}% of capacity)")

    msg_text.bind("<KeyRelease>", update_capacity_bar)

    # Step 3: Output path
    s3 = section(content, "Save stego image as", 3)

    out_row = tk.Frame(s3, bg=PANEL)
    out_row.pack(fill="x")

    out_var = tk.StringVar(value="stego_output.png")
    out_entry = tk.Entry(out_row, textvariable=out_var, bg=ENTRY_BG, fg=TEXT,
                         insertbackground=TEXT, font=("Consolas", 10),
                         relief="flat", bd=0)
    out_entry.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 6))

    def choose_out():
        path = filedialog.asksaveasfilename(
            title="Save stego image",
            defaultextension=".png",
            initialfile=out_var.get(),
            filetypes=[("PNG image", "*.png"), ("All files", "*.*")]
        )
        if path:
            out_var.set(path)

    tk.Button(out_row, text=" 💾  Save As ", bg="#21262d", fg=TEXT,
              font=("Consolas", 10), relief="flat", cursor="hand2",
              activebackground=BORDER, command=choose_out).pack(side="left")

    tk.Label(s3, text="  ℹ  Always save as PNG — JPEG compression will destroy the hidden bits",
             bg=PANEL, fg=MUTED, font=("Consolas", 8)).pack(anchor="w", pady=(4, 0))

    # ── Embed button ─────────────────────────────────────────
    btn_frame = tk.Frame(content, bg=BG)
    btn_frame.pack(fill="x", pady=(4, 6))

    result_var  = tk.StringVar()
    status_var  = tk.StringVar(value="Ready — choose an image and type your message")

    def do_embed():
        msg = msg_text.get("1.0", "end").strip()
        out = out_var.get().strip()

        if not msg:
            messagebox.showwarning("Empty Message", "Please type a secret message first.")
            return
        if not out:
            messagebox.showwarning("No Output Path", "Please enter an output filename.")
            return

        # Auto-generate cover if none chosen
        if state["cover_img"] is None:
            status_var.set("No cover image — generating 512×512 noise image...")
            root.update_idletasks()
            rng = np.random.RandomState(int(time.time()) % 99999)
            size = 512
            x = np.linspace(0, 4 * np.pi, size)
            y = np.linspace(0, 4 * np.pi, size)
            xx, yy = np.meshgrid(x, y)
            r = ((np.sin(xx) * 0.5 + 0.5) * 200 + rng.normal(0, 8, (size, size))).clip(0, 255)
            g = ((np.cos(yy) * 0.5 + 0.5) * 180 + rng.normal(0, 8, (size, size))).clip(0, 255)
            b = ((np.sin(xx + yy) * 0.5 + 0.5) * 160 + rng.normal(0, 8, (size, size))).clip(0, 255)
            state["cover_img"] = np.stack([r, g, b], axis=-1).astype(np.uint8)

        cover_arr = state["cover_img"]
        cap = get_capacity(cover_arr)

        if len(msg.encode("utf-8")) + 3 > cap:
            messagebox.showerror(
                "Message Too Long",
                f"Message is {len(msg.encode('utf-8'))} bytes but image only "
                f"holds {cap} bytes.\n\nUse a larger image or shorter message."
            )
            return

        status_var.set("🔒  Embedding hidden message via LSB steganography...")
        root.update_idletasks()

        try:
            stego_arr  = embed_lsb(cover_arr, msg)
            stego_img  = Image.fromarray(stego_arr)

            # Force PNG output (prevent JPEG compression destroying bits)
            if not out.lower().endswith(".png"):
                out = str(Path(out).with_suffix(".png"))
                out_var.set(out)

            stego_img.save(out)
            size_kb = os.path.getsize(out) // 1024

            # Quick verify
            recovered = extract_lsb(stego_arr)
            ok = recovered is not None and recovered.strip() == msg.strip()

            lines = [
                f"{'='*54}",
                f"  ✓  STEGANOGRAPHY SUCCESSFUL",
                f"{'='*54}",
                f"  Output file    : {os.path.basename(out)}  ({size_kb} KB)",
                f"  Message size   : {len(msg)} chars  /  {len(msg.encode())} bytes",
                f"  Hidden in      : {cover_arr.size // 1000}K channels  "
                f"({len(msg.encode())*8} bits altered)",
                f"  Pixel change   : ±1 on {len(msg.encode())*8:,} of "
                f"{cover_arr.size:,} channel values",
                f"  Visual impact  : IMPERCEPTIBLE",
                f"  Self-verify    : {'✓ Message recoverable!' if ok else '✗ Verify failed'}",
                f"{'='*54}",
                f"",
                f"  ► Now upload '{os.path.basename(out)}' to the",
                f"    ShieldNet dashboard  →  Steganalysis tab",
                f"    to see it get DETECTED and EXTRACTED!",
                f"{'='*54}",
            ]
            result_var.set("\n".join(lines))
            result_lbl.config(fg=GREEN)
            status_var.set(f"✓ Done!  {os.path.basename(out)} saved  —  Upload it to ShieldNet to test detection!")

        except Exception as e:
            result_var.set(f"✗ ERROR: {e}")
            result_lbl.config(fg=RED)
            status_var.set(f"Error: {e}")

    embed_btn = tk.Button(
        btn_frame,
        text=" ⚔️   EMBED SECRET MESSAGE   ⚔️ ",
        bg=RED_DARK, fg="white",
        font=("Consolas", 13, "bold"),
        relief="flat", cursor="hand2",
        activebackground=RED,
        pady=10,
        command=do_embed
    )
    embed_btn.pack(fill="x")

    # ── Result box ────────────────────────────────────────────
    result_lbl = tk.Label(content, textvariable=result_var, bg=PANEL, fg=GREEN,
                          font=("Consolas", 9), justify="left", anchor="w",
                          padx=12, pady=10)
    result_lbl.pack(fill="x")

    # ── Status bar ────────────────────────────────────────────
    status_bar = tk.Frame(root, bg="#010409", pady=4)
    status_bar.pack(fill="x", side="bottom")
    tk.Label(status_bar, textvariable=status_var, bg="#010409", fg=MUTED,
             font=("Consolas", 8), anchor="w", padx=10).pack(side="left")
    tk.Label(status_bar, text="ShieldNet IDPS Demo  |  Attacker Tool  v1.0",
             bg="#010409", fg="#444c56",
             font=("Consolas", 8), anchor="e", padx=10).pack(side="right")

    # ── Initial state ─────────────────────────────────────────
    update_capacity_bar()

    root.mainloop()


# ─────────────────────────────────────────────────────────────
# CLI mode
# ─────────────────────────────────────────────────────────────

def cli_mode():
    parser = argparse.ArgumentParser(
        description="Attacker LSB Steganography Tool — embed a secret message in an image"
    )
    parser.add_argument("--image", "-i", required=True, help="Path to cover image")
    parser.add_argument("--message", "-m", required=True, help="Secret message to embed")
    parser.add_argument("--out", "-o", default="stego_output.png",
                        help="Output path (default: stego_output.png)")
    args = parser.parse_args()

    if not PIL_AVAILABLE:
        print("[!] Pillow not installed. Run: pip install Pillow")
        sys.exit(1)

    if not os.path.exists(args.image):
        print(f"[!] Image not found: {args.image}")
        sys.exit(1)

    img = Image.open(args.image).convert("RGB")
    arr = np.array(img)
    cap = get_capacity(arr)

    print(f"\n{'='*60}")
    print(f"  [*] ATTACKER LSB STEGANOGRAPHY TOOL  (CLI MODE)")
    print(f"{'='*60}")
    print(f"  Cover image : {args.image}  ({img.width}x{img.height} px)")
    print(f"  Capacity    : {cap} bytes")
    print(f"  Message     : {args.message[:60]}{'...' if len(args.message) > 60 else ''}")
    print(f"  Msg size    : {len(args.message.encode())} bytes")

    if len(args.message.encode()) + 3 > cap:
        print(f"\n[!] Message too long! Max capacity is {cap} bytes.")
        sys.exit(1)

    out = args.out
    if not out.lower().endswith(".png"):
        out = str(Path(out).with_suffix(".png"))

    print(f"\n  Embedding... ", end="", flush=True)
    stego_arr = embed_lsb(arr, args.message)
    Image.fromarray(stego_arr).save(out)
    print(f"Done!")

    # Verify
    recovered = extract_lsb(stego_arr)
    ok = recovered is not None and recovered.strip() == args.message.strip()

    print(f"\n{'='*60}")
    print(f"  Output file  : {out}  ({os.path.getsize(out)//1024} KB)")
    print(f"  Self-verify  : {'[PASS] message recoverable' if ok else '[FAIL] verify error'}")
    print(f"{'='*60}")
    print(f"\n  >> Upload '{out}' to ShieldNet dashboard -> Steganalysis tab")
    print(f"     to trigger detection and extraction!\n")

    sys.exit(0 if ok else 1)


# ─────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # If any CLI arguments given, run CLI mode, else launch GUI
    if len(sys.argv) > 1:
        cli_mode()
    else:
        launch_gui()
