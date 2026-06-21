"""
ShieldNet — Suricata EVE JSON Log Sensor
==========================================
Tails Suricata's eve.json alert log in real-time and forwards detections
to ShieldNet backend. Works even if Suricata runs on a separate machine
(just mount / copy the log file).

Requirements:
  - Suricata installed: https://suricata.io/download/
  - Suricata configured to output eve.json (default in most installs)

Default log paths:
  Windows : C:\\Suricata\\log\\eve.json
  Linux   : /var/log/suricata/eve.json

Usage:
  python -m backend.sensors.suricata_sensor
  python -m backend.sensors.suricata_sensor --log /var/log/suricata/eve.json
  python -m backend.sensors.suricata_sensor --log C:\\Suricata\\log\\eve.json

Test without Suricata (inject a fake alert):
  python -m backend.sensors.suricata_sensor --test
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import threading
import requests
from datetime import datetime

API_BASE = "http://127.0.0.1:8000"
HEARTBEAT_INTERVAL = 10
POLL_INTERVAL = 0.5  # seconds between file reads

_stats = {
    "alerts_forwarded": 0,
    "active": True,
    "started_at": datetime.utcnow().isoformat(),
    "last_alert_at": None,
}

# ─────────────────────────────────────────────────────────────────────────────
# Suricata → ShieldNet category mapping
# ─────────────────────────────────────────────────────────────────────────────

CATEGORY_MAP = {
    # Suricata category → (ShieldNet attack_type, confidence)
    "attempted-recon":              ("PortScan",        0.85),
    "successful-recon-limited":     ("PortScan",        0.88),
    "successful-recon-largescale":  ("PortScan",        0.92),
    "attempted-dos":                ("DoS",             0.87),
    "successful-dos":               ("DoS",             0.96),
    "attempted-user":               ("BruteForce",      0.82),
    "unsuccessful-user":            ("BruteForce",      0.85),
    "successful-user":              ("BruteForce",      0.96),
    "attempted-admin":              ("PrivilegeEsc",    0.88),
    "successful-admin":             ("PrivilegeEsc",    0.97),
    "web-application-attack":       ("WebAttack",       0.90),
    "web-application-activity":     ("WebAttack",       0.78),
    "trojan-activity":              ("C2Communication", 0.93),
    "command-and-control":          ("C2Communication", 0.97),
    "shellcode-detect":             ("RemoteCodeExec",  0.95),
    "malware-cnc":                  ("C2Communication", 0.94),
    "policy-violation":             ("AnomPkt",         0.70),
    "protocol-command-decode":      ("WebAttack",       0.75),
    "denial-of-service":            ("DDoS",            0.92),
    "network-scan":                 ("PortScan",        0.91),
    "unusual-client-port-connection": ("AnomPkt",       0.72),
    "bad-unknown":                  ("AnomPkt",         0.65),
}

SEVERITY_MAP = {1: "critical", 2: "high", 3: "medium", 4: "low"}


def _map_alert(alert: dict) -> tuple[str, float]:
    """Map Suricata alert category/severity to ShieldNet attack_type + confidence."""
    category = alert.get("category", "").lower().replace(" ", "-").replace("_", "-")
    suricata_severity = alert.get("severity", 3)

    # Try category map first
    for key, (attack_type, confidence) in CATEGORY_MAP.items():
        if key in category:
            # Boost confidence for higher severity
            boost = {1: 0.05, 2: 0.02, 3: 0.0, 4: -0.05}.get(suricata_severity, 0)
            return attack_type, min(0.99, confidence + boost)

    # Fallback: derive from signature name
    sig = alert.get("signature", "").lower()
    if "scan" in sig:
        return "PortScan", 0.80
    if "brute" in sig or "bruteforce" in sig:
        return "BruteForce", 0.85
    if "sql" in sig or "sqli" in sig:
        return "WebAttack", 0.88
    if "flood" in sig or "dos" in sig:
        return "DoS", 0.88
    if "c2" in sig or "beacon" in sig or "command" in sig:
        return "C2Communication", 0.90

    return "AnomPkt", 0.70


def _forward_alert(event: dict):
    """Convert a Suricata EVE alert event to a ShieldNet IDPS event."""
    alert = event.get("alert", {})
    src_ip = event.get("src_ip", "unknown")
    dst_port = event.get("dest_port", 0)
    proto = event.get("proto", "TCP")
    signature = alert.get("signature", "Suricata Alert")
    category = alert.get("category", "Unknown")
    suricata_sev = alert.get("severity", 3)

    attack_type, confidence = _map_alert(alert)
    rule = f"Suricata:{alert.get('signature_id', 0)}"

    explanation = (
        f"Suricata alert: {signature}. "
        f"Category: {category}. "
        f"Severity: {SEVERITY_MAP.get(suricata_sev, 'medium')}."
    )

    try:
        r = requests.post(f"{API_BASE}/api/idps/event", json={
            "source_ip": src_ip,
            "attack_type": attack_type,
            "confidence": confidence,
            "protocol": proto,
            "dst_port": dst_port or 0,
            "rule_triggered": rule,
            "explanation": explanation,
        }, timeout=5)
        _stats["alerts_forwarded"] += 1
        _stats["last_alert_at"] = datetime.utcnow().isoformat()
        print(f"  [SURICATA] → {attack_type} from {src_ip}  «{signature[:60]}»  [{r.status_code}]")
    except Exception as e:
        print(f"  [SURICATA] POST failed: {e}")


def _heartbeat_loop():
    while _stats["active"]:
        try:
            requests.post(f"{API_BASE}/api/sensors/heartbeat", json={
                "sensor": "suricata",
                "alerts_forwarded": _stats["alerts_forwarded"],
                "last_alert_at": _stats["last_alert_at"],
            }, timeout=3)
        except Exception:
            pass
        time.sleep(HEARTBEAT_INTERVAL)


def _tail_log(log_path: str):
    """Tail the Suricata eve.json file and process new alert lines."""
    print(f"  [SURICATA] Tailing: {log_path}")

    # Seek to end so we don't re-process old events
    try:
        f = open(log_path, "r", encoding="utf-8", errors="ignore")
        f.seek(0, 2)  # seek to end
    except FileNotFoundError:
        print(f"  [SURICATA] WARNING: File not found: {log_path}")
        print("  [SURICATA] Waiting for Suricata to create the log file...")
        while not os.path.exists(log_path):
            time.sleep(2)
        f = open(log_path, "r", encoding="utf-8", errors="ignore")
        f.seek(0, 2)

    print("  [SURICATA] Monitoring for new alerts... (Press Ctrl+C to stop)")

    while _stats["active"]:
        line = f.readline()
        if not line:
            time.sleep(POLL_INTERVAL)
            continue
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
            # Only process alert events
            if event.get("event_type") == "alert":
                _forward_alert(event)
        except json.JSONDecodeError:
            pass
        except Exception as e:
            print(f"  [SURICATA] Parse error: {e}")


def _inject_test_alert(log_path: str):
    """Write a fake Suricata alert to the log file for testing."""
    import random
    test_event = {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
        "event_type": "alert",
        "src_ip": random.choice(["192.168.1.47", "10.0.0.99", "203.0.113.42"]),
        "src_port": random.randint(1024, 65535),
        "dest_ip": "192.168.0.1",
        "dest_port": 80,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": random.randint(2000000, 2999999),
            "rev": 1,
            "signature": "ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap Scripting Engine)",
            "category": "Web Application Attack",
            "severity": 2,
        }
    }
    os.makedirs(os.path.dirname(log_path), exist_ok=True) if os.path.dirname(log_path) else None
    with open(log_path, "a") as f:
        f.write(json.dumps(test_event) + "\n")
    print(f"  [SURICATA] Test alert written to {log_path}")


def run(log_path: str):
    print("=" * 60)
    print("  ShieldNet Suricata Log Sensor")
    print("=" * 60)
    print(f"  Log file  : {log_path}")
    print(f"  Backend   : {API_BASE}")
    print("  Press Ctrl+C to stop")
    print("=" * 60)

    hb = threading.Thread(target=_heartbeat_loop, daemon=True)
    hb.start()

    try:
        _tail_log(log_path)
    except KeyboardInterrupt:
        print(f"\n[SURICATA] Stopped. Alerts forwarded: {_stats['alerts_forwarded']}")
    finally:
        _stats["active"] = False


if __name__ == "__main__":
    # Default log paths by OS
    if sys.platform == "win32":
        default_log = r"C:\Suricata\log\eve.json"
    else:
        default_log = "/var/log/suricata/eve.json"

    parser = argparse.ArgumentParser(description="ShieldNet Suricata EVE Log Sensor")
    parser.add_argument("--log", default=default_log,
                        help=f"Path to Suricata eve.json (default: {default_log})")
    parser.add_argument("--api", default=API_BASE,
                        help=f"Backend API URL (default: {API_BASE})")
    parser.add_argument("--test", action="store_true",
                        help="Inject a fake test alert into the log file and monitor it")
    args = parser.parse_args()

    API_BASE = args.api

    if args.test:
        print(f"[SURICATA] Injecting test alert into {args.log}...")
        _inject_test_alert(args.log)
        print("[SURICATA] Starting sensor to pick up the test alert...")
        run(args.log)
    else:
        run(args.log)
