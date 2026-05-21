#!/usr/bin/env python3
"""ShieldNet Demo — SSH Brute Force Simulation. Run: python attack_bruteforce.py"""
import sys, time, requests

API = "http://127.0.0.1:8000"
ATTACKER_IP = "172.16.0.88"

CREDENTIALS = [
    ("root","123456"),("admin","password"),("root","toor"),("admin","admin"),
    ("user","user"),("root","root"),("admin","1234"),("test","test"),
    ("root","alpine"),("ubuntu","ubuntu"),("pi","raspberry"),("admin",""),
    ("root","pass"),("deploy","deploy"),("guest","guest"),("oracle","oracle"),
    ("postgres","postgres"),("mysql","mysql"),("ftp","ftp"),("backup","backup"),
    ("root","admin"),("admin","123"),("root","1234"),("user","password"),("admin","root"),
]

def main():
    print(f"\n[ShieldNet Demo] Simulating SSH brute force from {ATTACKER_IP}")
    print("Trying 25 credential pairs against port 22...\n")

    for i, (user, pwd) in enumerate(CREDENTIALS, 1):
        cred_str = f"{user}:{pwd}"
        try:
            # Report to honeypot log
            requests.post(f"{API}/api/honeypot/log", json={
                "src_ip": ATTACKER_IP,
                "port": 22,
                "service": "ssh",
                "payload": f"SSH-2.0-OpenSSH_8.2p1 Ubuntu LOGIN {user}",
                "credentials_attempted": cred_str,
                "session_duration": 0.3,
                "mitre_ttp": "T1110 - Brute Force",
            }, timeout=5)
            # Report to IDPS
            requests.post(f"{API}/api/idps/event", json={
                "source_ip": ATTACKER_IP,
                "dst_ip": "192.168.1.1",
                "src_port": 49000 + i,
                "dst_port": 22,
                "protocol": "TCP",
                "packet_count": 3,
                "attack_type": "BruteForce",
                "confidence": min(0.50 + i * 0.018, 0.95),
                "severity": "critical" if i >= 20 else "high",
                "explanation": f"SSH brute force: {i} failed auth attempts. Creds tried: {cred_str}",
                "rule_triggered": "SSHBruteForce",
            }, timeout=5)
        except Exception as e:
            print(f"  [!] Backend not reachable: {e}")
            sys.exit(1)
        print(f"  Attempt {i:2d}: {cred_str:<25} → FAILED")
        time.sleep(0.3)

    print(f"\n[+] Brute force simulation complete (25 attempts).")
    print(f"    → Check Panel 6 (Honeypot) for logged credentials.")
    print(f"    → Check Panel 2 (Event Feed) for BruteForce alerts.")
    print(f"    → Source IP {ATTACKER_IP} should now be auto-blocked.\n")

if __name__ == "__main__":
    main()
