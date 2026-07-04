"""
ShieldNet — mitmproxy HTTP Inspection Sensor
=============================================
Inspects real HTTP traffic for web attacks: SQL injection, XSS, path traversal,
command injection, suspicious user agents, and credential probes.

Usage:
  mitmdump --listen-port 8888 -s backend/sensors/mitmproxy_addon.py
  # OR interactive UI:
  mitmproxy --listen-port 8888 --scripts backend/sensors/mitmproxy_addon.py

Then configure your browser/app proxy to: 127.0.0.1:8888

For HTTPS inspection (optional):
  Install mitmproxy cert: http://mitm.it after starting proxy

Run directly (starts mitmdump automatically):
  python -m backend.sensors.mitmproxy_addon
"""
from __future__ import annotations

import re
import time
import threading
import requests as _requests
from urllib.parse import unquote, urlparse, parse_qs
from datetime import datetime

API_BASE = "http://127.0.0.1:8000"
HEARTBEAT_INTERVAL = 10

_stats = {
    "requests_seen": 0,
    "alerts_sent": 0,
    "active": True,
    "started_at": datetime.utcnow().isoformat(),
}

# ─────────────────────────────────────────────────────────────────────────────
# Attack pattern definitions
# ─────────────────────────────────────────────────────────────────────────────

SQLI_PATTERNS = [
    re.compile(r"('|\%27)\s*(or|and)\s*('|\%27|\d)", re.IGNORECASE),
    re.compile(r"union\s+(all\s+)?select", re.IGNORECASE),
    re.compile(r"drop\s+(table|database|index)", re.IGNORECASE),
    re.compile(r"(--|#|\/\*)\s*$", re.IGNORECASE),
    re.compile(r"xp_cmdshell|sp_executesql|exec\s*\(", re.IGNORECASE),
    re.compile(r"insert\s+into\s+\w+\s*\(", re.IGNORECASE),
    re.compile(r"benchmark\s*\(\d+", re.IGNORECASE),
    re.compile(r"sleep\s*\(\d+\)", re.IGNORECASE),
    re.compile(r"waitfor\s+delay", re.IGNORECASE),
    re.compile(r"1\s*=\s*1|1\s*=\s*'1'", re.IGNORECASE),
]

XSS_PATTERNS = [
    re.compile(r"<script[^>]*>", re.IGNORECASE),
    re.compile(r"</script>", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"on(load|error|click|mouseover|focus)\s*=", re.IGNORECASE),
    re.compile(r"alert\s*\(", re.IGNORECASE),
    re.compile(r"document\.(cookie|write|location)", re.IGNORECASE),
    re.compile(r"<iframe[^>]*>", re.IGNORECASE),
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"<img[^>]*\son\w+\s*=", re.IGNORECASE),
]

PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./|\.\.\\"),
    re.compile(r"/etc/(passwd|shadow|hosts|fstab)", re.IGNORECASE),
    re.compile(r"windows[/\\]win\.ini", re.IGNORECASE),
    re.compile(r"windows[/\\]system32", re.IGNORECASE),
    re.compile(r"%2e%2e[/\\]|%252e%252e", re.IGNORECASE),
    re.compile(r"boot\.ini|ntds\.dit", re.IGNORECASE),
]

CMD_INJECTION_PATTERNS = [
    re.compile(r";\s*(ls|dir|cat|id|whoami|pwd|env|uname)\b", re.IGNORECASE),
    re.compile(r"&\s*(ls|dir|cat|id|whoami|pwd|env)\b", re.IGNORECASE),
    re.compile(r"\|\s*(ls|dir|cat|id|whoami|bash|sh|cmd)\b", re.IGNORECASE),
    re.compile(r"`[^`]+`"),
    re.compile(r"\$\(.*\)"),
    re.compile(r"nc\s+-[lLe]|-e\s+/bin/(sh|bash)", re.IGNORECASE),
]

SUSPICIOUS_AGENTS = [
    re.compile(r"sqlmap", re.IGNORECASE),
    re.compile(r"nikto", re.IGNORECASE),
    re.compile(r"masscan", re.IGNORECASE),
    re.compile(r"nmap", re.IGNORECASE),
    re.compile(r"dirbuster", re.IGNORECASE),
    re.compile(r"gobuster", re.IGNORECASE),
    re.compile(r"wfuzz", re.IGNORECASE),
    re.compile(r"hydra", re.IGNORECASE),
    re.compile(r"metasploit|msfconsole", re.IGNORECASE),
    re.compile(r"python-requests/\d+.*\(scan\)", re.IGNORECASE),
    re.compile(r"zgrab|nuclei|acunetix|burpsuite|havij", re.IGNORECASE),
]

SENSITIVE_PATHS = [
    re.compile(r"/(admin|administrator|wp-admin|phpMyAdmin)", re.IGNORECASE),
    re.compile(r"/\.(env|git|svn|htaccess|htpasswd)", re.IGNORECASE),
    re.compile(r"/(shell|webshell|cmd|backdoor|c99|r57)\.(php|asp|aspx|jsp)", re.IGNORECASE),
    re.compile(r"/(config|configuration|settings)\.(php|xml|json|yml)", re.IGNORECASE),
    re.compile(r"/etc/passwd|/etc/shadow", re.IGNORECASE),
]


def _post_idps(src_ip: str, attack_type: str, confidence: float, rule: str,
               dst_port: int = 80, explanation: str = ""):
    try:
        r = _requests.post(f"{API_BASE}/api/idps/event", json={
            "source_ip": src_ip,
            "attack_type": attack_type,
            "confidence": confidence,
            "protocol": "TCP",
            "dst_port": dst_port,
            "rule_triggered": rule,
            "explanation": explanation,
        }, timeout=5)
        _stats["alerts_sent"] += 1
        print(f"  [MITM] → {attack_type} from {src_ip} [{r.status_code}]  {explanation[:60]}")
    except Exception as e:
        print(f"  [MITM] POST failed: {e}")


def _post_honeypot(src_ip: str, port: int, service: str, payload: str, credentials: str | None = None):
    try:
        _requests.post(f"{API_BASE}/api/honeypot/log", json={
            "src_ip": src_ip,
            "port": port,
            "service": service,
            "payload": payload[:500],
            "credentials_attempted": credentials,
            "mitre_ttp": "T1190 - Exploit Public-Facing Application",
        }, timeout=5)
        print(f"  [MITM] → Honeypot log: {service}:{port} from {src_ip}")
    except Exception as e:
        print(f"  [MITM] Honeypot POST failed: {e}")


def _heartbeat_loop():
    while _stats["active"]:
        try:
            _requests.post(f"{API_BASE}/api/sensors/heartbeat", json={
                "sensor": "mitmproxy",
                "requests_seen": _stats["requests_seen"],
                "alerts_sent": _stats["alerts_sent"],
            }, timeout=3)
        except Exception:
            pass
        time.sleep(HEARTBEAT_INTERVAL)


def _inspect(src_ip: str, method: str, url: str, headers: dict, body: str, port: int):
    """Run all pattern checks against a single HTTP request."""
    _stats["requests_seen"] += 1
    full_url = url
    decoded_url = unquote(full_url)
    parsed = urlparse(decoded_url)
    path = parsed.path
    query = parsed.query
    target = f"{decoded_url} {body}"

    # 1. Suspicious User-Agent
    ua = headers.get("user-agent", "")
    for pat in SUSPICIOUS_AGENTS:
        if pat.search(ua):
            _post_idps(src_ip, "WebAttack", 0.92, "SuspiciousUserAgent", port,
                       f"Scanner user-agent detected: {ua[:80]}")
            return  # One alert per request

    # 2. SQL Injection
    for pat in SQLI_PATTERNS:
        m = pat.search(target)
        if m:
            _post_idps(src_ip, "WebAttack", 0.93, "SQLInjection", port,
                       f"SQLi pattern in {method} {path}?{query[:60]}")
            _post_honeypot(src_ip, port, "http", f"{method} {full_url}", )
            return

    # 3. XSS
    for pat in XSS_PATTERNS:
        if pat.search(target):
            _post_idps(src_ip, "WebAttack", 0.88, "XSS", port,
                       f"XSS pattern in {method} {path}")
            return

    # 4. Path Traversal
    for pat in PATH_TRAVERSAL_PATTERNS:
        if pat.search(decoded_url):
            _post_idps(src_ip, "WebAttack", 0.91, "PathTraversal", port,
                       f"Path traversal in {method} {path}")
            _post_honeypot(src_ip, port, "http", f"{method} {full_url}")
            return

    # 5. Command Injection
    for pat in CMD_INJECTION_PATTERNS:
        if pat.search(target):
            _post_idps(src_ip, "WebAttack", 0.94, "CommandInjection", port,
                       f"Command injection in {method} {path}")
            return

    # 6. Sensitive path probe
    for pat in SENSITIVE_PATHS:
        if pat.search(path):
            _post_idps(src_ip, "WebAttack", 0.82, "SensitivePathProbe", port,
                       f"Probe of sensitive path: {path}")
            _post_honeypot(src_ip, port, "http", f"{method} {path}")
            return


# ─────────────────────────────────────────────────────────────────────────────
# mitmproxy Addon class — loaded by mitmproxy automatically
# ─────────────────────────────────────────────────────────────────────────────

class ShieldNetAddon:
    """
    mitmproxy addon that inspects requests and forwards detections to ShieldNet.
    """

    def __init__(self):
        print("[ShieldNet mitmproxy addon] Starting...")
        hb = threading.Thread(target=_heartbeat_loop, daemon=True)
        hb.start()

    def request(self, flow):
        """Called for every HTTP request passing through the proxy."""
        try:
            client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "unknown"
            method = flow.request.method
            url = flow.request.pretty_url
            port = flow.request.port
            headers = dict(flow.request.headers)

            # Get request body (if any)
            body = ""
            if flow.request.content:
                try:
                    body = flow.request.content.decode("utf-8", errors="ignore")[:2000]
                except Exception:
                    pass

            # Check for Basic Auth credentials → honeypot
            auth = headers.get("authorization", "")
            if auth.lower().startswith("basic "):
                import base64
                try:
                    creds = base64.b64decode(auth[6:]).decode("utf-8", errors="ignore")
                    _post_honeypot(client_ip, port, "http",
                                   f"Basic Auth attempt: {method} {url[:100]}",
                                   credentials=creds)
                except Exception:
                    pass

            _inspect(client_ip, method, url, headers, body, port)

        except Exception as e:
            print(f"[ShieldNet addon] Error: {e}")

    def response(self, flow):
        """Optionally inspect responses for data leak indicators."""
        pass


# mitmproxy looks for this name
addons = [ShieldNetAddon()]


# ─────────────────────────────────────────────────────────────────────────────
# __main__ — launch mitmdump automatically
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    import os
    import subprocess

    print("=" * 60)
    print("  ShieldNet mitmproxy HTTP Sensor")
    print("=" * 60)
    print("  Proxy port : 8888")
    print("  Backend    : " + API_BASE)
    print("  Configure your browser/app proxy: 127.0.0.1:8888")
    print("  For HTTPS : visit http://mitm.it in your browser after starting")
    print("  Press Ctrl+C to stop")
    print("=" * 60)

    addon_path = os.path.abspath(__file__)
    cmd = [
        sys.executable, "-m", "mitmproxy",
        "--listen-host", "0.0.0.0",
        "--listen-port", "8888",
        "-s", addon_path,
        "--flow-detail", "0",   # quiet mode
        "--no-web",
    ]
    # Use mitmdump for headless (no UI)
    cmd[2] = "mitmdump"
    print(f"Running: {' '.join(cmd)}\n")
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print(f"\n[MITM] Stopped. Requests: {_stats['requests_seen']}, Alerts: {_stats['alerts_sent']}")
