"""
ShieldNet — Attack Detection Proxy
"""
from __future__ import annotations

import asyncio
import re
import requests
from backend.core.logging import get_logger

logger = get_logger("shieldnet.attack_proxy")

API_BASE = "http://127.0.0.1:8000"
LISTEN_PORT = 9002

PAYLOAD_RULES = [
    {
        "pattern": re.compile(r"SCAN\s+--port", re.IGNORECASE),
        "attack_type": "PortScan",
        "confidence": 0.94,
        "rule": "PortSweep",
        "service": "ssh",
        "port": 22,
        "mitre_ttp": "T1046 - Network Service Discovery",
    },
    {
        "pattern": re.compile(r"AUTH\s+--user.*--brute", re.IGNORECASE),
        "attack_type": "BruteForce",
        "confidence": 0.92,
        "rule": "SSHBruteForce",
        "service": "ssh",
        "port": 22,
        "mitre_ttp": "T1110 - Brute Force",
        "extract_creds": True,
    },
    {
        "pattern": re.compile(r"AUTH\s+--token.*--escalate", re.IGNORECASE),
        "attack_type": "PrivilegeEscalation",
        "confidence": 0.98,
        "rule": "HoneyTokenTriggered",
        "service": "http",
        "port": 80,
        "mitre_ttp": "T1134 - Access Token Manipulation",
    },
    {
        "pattern": re.compile(r"EXEC\s+.*payload", re.IGNORECASE),
        "attack_type": "RemoteCodeExecution",
        "confidence": 0.96,
        "rule": "MaliciousExecution",
        "service": "ssh",
        "port": 22,
        "mitre_ttp": "T1059 - Command and Scripting Interpreter",
    },
    {
        "pattern": re.compile(r"PIVOT\s+--discover", re.IGNORECASE),
        "attack_type": "LateralMovement",
        "confidence": 0.90,
        "rule": "PivotDetected",
        "service": "ssh",
        "port": 22,
        "mitre_ttp": "T1021 - Remote Services",
    },
    {
        "pattern": re.compile(r"SEND\s+/c2/beacon", re.IGNORECASE),
        "attack_type": "C2Communication",
        "confidence": 0.97,
        "rule": "C2BeaconDetected",
        "service": "http",
        "port": 80,
        "mitre_ttp": "T1071 - Application Layer Protocol",
    },
    {
        "pattern": re.compile(r"GET\s+.*--tunnel", re.IGNORECASE),
        "attack_type": "DataExfiltration",
        "confidence": 0.93,
        "rule": "TunnelDetected",
        "service": "http",
        "port": 80,
        "mitre_ttp": "T1572 - Protocol Tunneling",
    },
    {
        "pattern": re.compile(r"OR\s+'1'='1'|UNION\s+SELECT|DROP\s+TABLE|--", re.IGNORECASE),
        "attack_type": "WebAttack",
        "confidence": 0.91,
        "rule": "SQLInjection",
        "service": "http",
        "port": 80,
        "mitre_ttp": "T1190 - SQL Injection Exploit",
    },
    {
        "pattern": re.compile(r"DATA\s+A{500,}", re.IGNORECASE),
        "attack_type": "AnomPkt",
        "confidence": 0.85,
        "rule": "OversizedPayload",
        "service": "http",
        "port": 80,
        "mitre_ttp": "T1005 - Data from Local System",
    },
    {
        "pattern": re.compile(r"^X$", re.IGNORECASE),
        "attack_type": "AnomPkt",
        "confidence": 0.80,
        "rule": "TinyPacketHeader",
        "service": "http",
        "port": 80,
        "mitre_ttp": "T1001 - Data Obfuscation",
    },
    {
        "pattern": re.compile(r"GET\s+/", re.IGNORECASE),
        "attack_type": "WebAttack",
        "confidence": 0.85,
        "rule": "HTTPProbe",
        "service": "http",
        "port": 80,
        "mitre_ttp": "T1190 - Exploit Public-Facing Application",
    },
]


def classify_payload(payload_str: str):
    for rule in PAYLOAD_RULES:
        if rule["pattern"].search(payload_str):
            return rule
    return None


def extract_credentials(payload_str: str):
    m = re.search(r"--user\s+(\S+).*--pass\s+(\S+)", payload_str, re.IGNORECASE)
    if m:
        return f"{m.group(1)}:{m.group(2)}"
    m = re.search(r"--token\s+(\S+)", payload_str, re.IGNORECASE)
    if m:
        return f"token:{m.group(1)}"
    return None


def post_idps(src_ip, attack_type, confidence, rule_triggered):
    try:
        data = {
            "source_ip": src_ip,
            "attack_type": attack_type,
            "confidence": confidence,
            "protocol": "TCP",
            "dst_port": LISTEN_PORT,
            "rule_triggered": rule_triggered,
        }
        r = requests.post(f"{API_BASE}/api/idps/event", json=data, timeout=5)
        logger.info(f"  → IDPS event: {attack_type} from {src_ip} [{r.status_code}]")
    except Exception as e:
        logger.error(f"  → IDPS post failed: {e}")


def post_honeypot(src_ip, port, service, payload, credentials=None, mitre_ttp=""):
    try:
        params = {
            "src_ip": src_ip,
            "port": port,
            "service": service,
            "payload": payload[:500],
            "mitre_ttp": mitre_ttp,
        }
        if credentials:
            params["credentials"] = credentials
        r = requests.post(f"{API_BASE}/api/honeypot/log", params=params, timeout=5)
        logger.info(f"  → Honeypot log: {service}:{port} from {src_ip} [{r.status_code}]")
    except Exception as e:
        logger.error(f"  → Honeypot post failed: {e}")


async def handle_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    addr = writer.get_extra_info("peername")
    src_ip = addr[0] if addr else "unknown"
    logger.info(f"[+] Connection from {src_ip}:{addr[1] if addr else '?'}")

    writer.write(b"SHIELDNET-PROXY/1.0 READY\r\n")
    await writer.drain()

    payload_count = 0
    try:
        while True:
            data = await asyncio.wait_for(reader.readline(), timeout=15)
            if not data:
                break
            line = data.decode(errors="ignore").strip()
            if not line:
                continue
            payload_count += 1
            match = classify_payload(line)
            if match:
                post_idps(src_ip, match["attack_type"], match["confidence"], match["rule"])
                creds = extract_credentials(line) if match.get("extract_creds") else extract_credentials(line)
                post_honeypot(src_ip, match["port"], match["service"], line, credentials=creds, mitre_ttp=match["mitre_ttp"])
                writer.write(f"ACK {match['attack_type']}\r\n".encode())
            else:
                writer.write(b"ACK UNKNOWN\r\n")
            await writer.drain()
    except Exception as e:
        logger.debug(f"Connection error: {e}")
    finally:
        writer.close()


async def run_proxy():
    server = await asyncio.start_server(handle_connection, "0.0.0.0", LISTEN_PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(run_proxy())
