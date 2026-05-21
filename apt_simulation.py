#!/usr/bin/env python3
"""
ShieldNet Demo — Full APT Operation Simulation.
Runs: brute force → image steg → video steg from same IP.
Shows the correlated attack timeline in Panel 7.
Run: python apt_simulation.py
"""
import subprocess, sys, time

APT_IP = "172.16.0.88"

STEPS = [
    ("Phase 1/3: SSH Brute Force (establishing foothold)", "attack_bruteforce.py"),
    ("Phase 2/3: Image Steganographic Exfiltration", "steg_hide.py"),
    ("Phase 3/3: Video Steganographic Exfiltration", "steg_video.py"),
]

def run_step(label: str, script: str):
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")
    result = subprocess.run([sys.executable, script], capture_output=False)
    if result.returncode != 0:
        print(f"[!] {script} exited with code {result.returncode}")

def main():
    print("\n" + "="*60)
    print("  SHIELDNET — APT OPERATION SIMULATION")
    print("  Attacker IP:", APT_IP)
    print("  This simulates a full kill-chain:")
    print("  Brute Force → Image Exfil → Video Exfil")
    print("="*60)
    time.sleep(1)

    for label, script in STEPS:
        run_step(label, script)
        print(f"\n  [Pausing 4 seconds between phases...]")
        time.sleep(4)

    print("\n" + "="*60)
    print("  APT SIMULATION COMPLETE")
    print("="*60)
    print(f"\n  → Open the dashboard and click 'Timeline' in the nav.")
    print(f"  → Select IP: {APT_IP}")
    print(f"  → Panel 7 will show the full correlated attack story:")
    print(f"     SSH Brute Force → Image Steg Detected → Video Steg Detected → IP Blocked")
    print(f"\n  This is the exact pattern used by Turla APT (2017–2019)")
    print(f"  who hid C2 commands in Instagram image uploads.\n")

if __name__ == "__main__":
    main()
