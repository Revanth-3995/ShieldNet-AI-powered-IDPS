"""
ShieldNet — Attack Simulation Scripts
"""
from __future__ import annotations

import argparse
import random
import time
import requests
from backend.core.logging import get_logger

logger = get_logger("shieldnet.sim")

API_BASE = "http://127.0.0.1:8000"
ATTACKER_IPS = ["192.168.1.47", "10.0.0.99", "172.16.0.5", "203.0.113.42", "198.51.100.7"]


def post_idps_event(source_ip: str, attack_type: str, confidence: float, **kwargs):
    data = {"source_ip": source_ip, "attack_type": attack_type, "confidence": confidence, **kwargs}
    try:
        r = requests.post(f"{API_BASE}/api/idps/event", json=data, timeout=5)
        logger.info(f"IDPS {attack_type} from {source_ip}: {r.status_code}")
    except Exception as e:
        logger.error(f"POST failed: {e}")


def post_steg_event(source_ip: str, media_type: str, confidence: float, algorithm: str, **kwargs):
    data = {
        "source_ip": source_ip,
        "media_type": media_type,
        "confidence": confidence,
        "filename": f"{'photo' if media_type == 'image' else 'video'}_{random.randint(1000, 9999)}.{'jpg' if media_type == 'image' else 'mp4'}",
        "file_size": random.randint(50000, 5000000),
        "algorithm_detected": algorithm,
        "payload_estimate": random.randint(500, 50000),
        "frame_count": 15 if media_type == "video" else None,
        "forensic_data": {"chi_square": random.uniform(0.3, 0.9), "sample_pair": random.uniform(0.3, 0.9)},
        "frame_results": [],
        "audio_results": [],
        **kwargs,
    }
    try:
        r = requests.post(f"{API_BASE}/api/steg/event", json=data, timeout=5)
        logger.info(f"STEG {media_type} ({algorithm}) from {source_ip}: {r.status_code}")
    except Exception as e:
        logger.error(f"POST failed: {e}")


def post_honeypot_event(source_ip: str, port: int, service: str, credentials: str = None, payload: str = None, mitre_ttp: str = None):
    params = {"src_ip": source_ip, "port": port, "service": service}
    if credentials:
        params["credentials"] = credentials
    if payload:
        params["payload"] = payload
    if mitre_ttp:
        params["mitre_ttp"] = mitre_ttp
    try:
        r = requests.post(f"{API_BASE}/api/honeypot/log", params=params, timeout=5)
        logger.info(f"HONEYPOT {service}:{port} from {source_ip}: {r.status_code}")
    except Exception as e:
        logger.error(f"POST failed: {e}")


def simulate_port_scan(ip: str = None):
    ip = ip or random.choice(ATTACKER_IPS)
    post_idps_event(ip, "PortScan", 0.94, protocol="TCP", dst_port=443, rule_triggered="PortSweep")


def simulate_ssh_bruteforce(ip: str = None):
    ip = ip or random.choice(ATTACKER_IPS)
    post_idps_event(ip, "BruteForce", 0.92, protocol="TCP", dst_port=22, rule_triggered="SSHBruteForce")
    usernames = ["root", "admin", "ubuntu", "pi", "test", "user"]
    passwords = ["123456", "password", "admin", "root", "toor", "letmein"]
    post_honeypot_event(ip, 22, "ssh", credentials=f"{random.choice(usernames)}:{random.choice(passwords)}", mitre_ttp="T1110.001")


def simulate_syn_flood(ip: str = None):
    ip = ip or random.choice(ATTACKER_IPS)
    post_idps_event(ip, "DoS", 0.96, protocol="TCP", dst_port=80, rule_triggered="SYNFlood")


def simulate_http_flood(ip: str = None):
    ip = ip or random.choice(ATTACKER_IPS)
    post_idps_event(ip, "DDoS", 0.91, protocol="TCP", dst_port=80, rule_triggered="HTTPFlood")
    post_honeypot_event(ip, 80, "http", payload=f"GET /{random.choice(['admin','wp-login.php','.env','config.php','shell.php'])} HTTP/1.1", mitre_ttp="T1190")


def simulate_sql_injection(ip: str = None):
    ip = ip or random.choice(ATTACKER_IPS)
    post_idps_event(ip, "WebAttack", 0.88, protocol="TCP", dst_port=80)
    post_honeypot_event(ip, 80, "http", payload="GET /search?q=' OR 1=1-- HTTP/1.1", mitre_ttp="T1190")


def simulate_steg_image(ip: str = None, confidence: float = None):
    ip = ip or random.choice(ATTACKER_IPS)
    confidence = confidence or round(random.uniform(0.78, 0.95), 3)
    post_steg_event(ip, "image", confidence, random.choice(["LSB-Spatial", "LSB-JPEG", "F5/OutGuess"]))


def simulate_steg_video(ip: str = None, confidence: float = None):
    ip = ip or random.choice(ATTACKER_IPS)
    confidence = confidence or round(random.uniform(0.80, 0.97), 3)
    post_steg_event(ip, "video", confidence, random.choice(["LSB-VideoFrames", "DCT-VideoCodec", "AudioLSB-EchoHiding"]))


def simulate_apt_full(ip: str = None):
    ip = ip or "192.168.1.47"
    simulate_port_scan(ip)
    post_honeypot_event(ip, 21, "ftp", credentials="anonymous:anonymous@", mitre_ttp="T1078")
    time.sleep(1)
    simulate_ssh_bruteforce(ip)
    time.sleep(1)
    post_honeypot_event(ip, 23, "telnet", credentials="admin:admin", payload="cat /etc/passwd", mitre_ttp="T1059.004")
    time.sleep(1)
    post_steg_event(ip, "image", 0.91, "LSB-JPEG")
    time.sleep(1)
    post_steg_event(ip, "video", 0.87, "AudioLSB-EchoHiding")


def simulate_all():
    for sim in [simulate_port_scan, simulate_ssh_bruteforce, simulate_syn_flood, simulate_http_flood, simulate_sql_injection, simulate_steg_image, simulate_steg_video]:
        sim()
        time.sleep(2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ShieldNet Attack Simulator")
    parser.add_argument("attack", choices=["port_scan", "ssh_brute", "syn_flood", "http_flood", "sql_inject", "steg_image", "steg_video", "apt_full", "all"])
    parser.add_argument("--ip", default=None)
    parser.add_argument("--confidence", type=float, default=None)
    args = parser.parse_args()

    sim_map = {
        "port_scan": simulate_port_scan,
        "ssh_brute": simulate_ssh_bruteforce,
        "syn_flood": simulate_syn_flood,
        "http_flood": simulate_http_flood,
        "sql_inject": simulate_sql_injection,
        "steg_image": simulate_steg_image,
        "steg_video": simulate_steg_video,
        "apt_full": simulate_apt_full,
        "all": simulate_all,
    }

    sim_fn = sim_map[args.attack]
    if args.attack in ("steg_image", "steg_video"):
        sim_fn(ip=args.ip, confidence=args.confidence)
    elif args.attack in ("apt_full", "all"):
        sim_fn()
    else:
        sim_fn(ip=args.ip)
