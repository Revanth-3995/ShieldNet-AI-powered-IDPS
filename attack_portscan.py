#!/usr/bin/env python3
"""ShieldNet Demo — Port Scan Simulation. Run: python attack_portscan.py"""
import sys, time, requests

API = "http://127.0.0.1:8000"
ATTACKER_IP = "203.0.113.42"

def main():
    print("\n[ShieldNet Demo] Simulating port scan from", ATTACKER_IP)
    print("Scanning ports 1–1024 on target...")

    for i, port in enumerate(range(1, 51), 1):
        try:
            requests.post(f"{API}/api/idps/event", json={
                "source_ip": ATTACKER_IP,
                "dst_ip": "192.168.1.1",
                "src_port": 54321 + i,
                "dst_port": port,
                "protocol": "TCP",
                "packet_count": 1,
                "attack_type": "PortScan",
                "confidence": 0.95,
                "severity": "high",
                "explanation": f"Port sweep: {i} unique ports contacted. Rule: PortSweep triggered.",
                "rule_triggered": "PortSweep",
            }, timeout=5)
        except Exception as e:
            print(f"  [!] Backend not reachable: {e}")
            sys.exit(1)
        if i % 10 == 0:
            print(f"  Scanned {i * 20} ports...")
        time.sleep(0.05)

    print("\n[+] Port scan simulation complete.")
    print("    → Check Panel 3 (Network IDPS) on the dashboard.")
    print(f"    → Source IP {ATTACKER_IP} should now be blocked.\n")

if __name__ == "__main__":
    main()
