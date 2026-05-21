#!/usr/bin/env python3
"""ShieldNet Demo — Video Steganography Detection. Run: python steg_video.py"""
import sys, time, requests

API = "http://127.0.0.1:8000"
ATTACKER_IP = "172.16.0.88"  # Same IP as image demo for APT correlation

def main():
    print(f"\n[ShieldNet Demo] Simulating video steganographic upload from {ATTACKER_IP}")
    print("  Generating frame analysis results...")
    time.sleep(1)

    # Simulate 47 frames analyzed, 9 anomalous
    frame_results = []
    anomalous_frames = {5, 12, 13, 14, 28, 29, 30, 38, 44}
    for i in range(47):
        is_anomalous = i in anomalous_frames
        frame_results.append({
            "frame_idx": i,
            "timestamp_ms": i * 1000.0,
            "confidence": 0.87 if is_anomalous else round(0.05 + (i % 7) * 0.02, 3),
            "is_suspicious": is_anomalous,
            "forensic_data": {
                "chi_square": 0.85 if is_anomalous else 0.08,
                "rs_score": 0.88 if is_anomalous else 0.06,
                "dct_score": 0.79 if is_anomalous else 0.11,
            },
            "algorithm_detected": "inter_frame_lsb_spike" if is_anomalous else None,
        })

    audio_results = [{
        "channel": "stereo",
        "rs_score": 0.83,
        "echo_score": 0.76,
        "confidence": 0.81,
        "sample_range_flagged": "0–44100",
    }]

    try:
        resp = requests.post(f"{API}/api/steg/event", json={
            "source_ip": ATTACKER_IP,
            "media_type": "video",
            "confidence": 0.88,
            "filename": "product_demo_final.mp4",
            "file_size": 14_800_000,
            "algorithm_detected": "Inter-Frame LSB Consistency | Audio RS Analysis",
            "payload_estimate": 94_208,
            "frame_count": 47,
            "forensic_data": {
                "chi_square": 0.82,
                "sample_pair": 0.79,
                "rs_analysis": 0.88,
                "dct_histogram": 0.76,
                "pixel_histogram": 0.71,
                "noise_residual": 0.80,
                "benford_law": 0.68,
                "inter_frame_lsb_consistency": 0.87,
                "dct_coefficient_drift": 0.74,
                "audio_rs_score": 0.83,
                "echo_hiding_score": 0.76,
                "metadata_anomaly_score": 0.35,
            },
            "frame_results": frame_results,
            "audio_results": audio_results,
        }, timeout=10)
        print(f"  Backend response: {resp.status_code}")
    except Exception as e:
        print(f"  [!] Backend not reachable: {e}")
        sys.exit(1)

    print(f"\n[+] Video steg detection complete.")
    print(f"    → Check Panel 5 (Video Steg) — frame confidence chart shows anomalous frames.")
    print(f"    → Frames {sorted(anomalous_frames)} flagged as anomalous.")
    print(f"    → Audio channel flagged: RS score 0.83, Echo score 0.76.")
    print(f"    → Check Panel 8 for full forensic breakdown.\n")

if __name__ == "__main__":
    main()
