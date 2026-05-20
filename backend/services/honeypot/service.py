"""
ShieldNet — Honeypot Engine
Simulates SSH, HTTP, FTP, Telnet services. Logs all interactions to DB.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from datetime import datetime, timezone

from backend.core.config import settings
from backend.core.logging import get_logger
from backend.db.database import SessionLocal
from backend.db import models

logger = get_logger("shieldnet.honeypot")

SERVICES = {
    "ssh":    {"port": 2222, "banner": b"SSH-2.0-OpenSSH_7.4\r\n"},
    "http":   {"port": 8888, "banner": b"HTTP/1.1 200 OK\r\nServer: Apache/2.2.34\r\nContent-Type: text/html\r\n\r\nWelcome\r\n"},
    "ftp":    {"port": 2121, "banner": b"220 (vsFTPd 2.3.4)\r\n"},
    "telnet": {"port": 2323, "banner": b"\xff\xfb\x01\xff\xfb\x03\xff\xfd\x27Login: "},
}

# MITRE ATT&CK TTP mapping
MITRE_MAP = {
    "ssh":    "T1110",   # Brute Force
    "ftp":    "T1110",
    "telnet": "T1021",   # Remote Services
    "http":   "T1190",   # Exploit Public-Facing Application
}

SQLI_PATTERN = re.compile(
    r"(union\s+select|or\s+'1'='1|drop\s+table|xp_cmdshell|--|;\s*select)", re.IGNORECASE
)


def _extract_credentials(service: str, raw_bytes: bytes) -> list[dict]:
    """Parse username/password pairs from raw session bytes."""
    text = raw_bytes.decode("utf-8", errors="replace")
    creds = []

    if service in ("ssh", "ftp", "telnet"):
        # Look for patterns: "USER admin\r\nPASS secret" or "login: admin\r\nPassword: secret"
        user_match = re.search(r"(?:user|login|username)[:\s]+([^\r\n]+)", text, re.IGNORECASE)
        pass_match = re.search(r"(?:pass|password)[:\s]+([^\r\n]+)", text, re.IGNORECASE)
        if user_match or pass_match:
            creds.append({
                "username": user_match.group(1).strip() if user_match else "",
                "password": pass_match.group(1).strip() if pass_match else "",
            })

    elif service == "http":
        # Look for Basic Auth or form POST body
        auth_match = re.search(r"Authorization:\s*Basic\s+(\S+)", text)
        if auth_match:
            import base64
            try:
                decoded = base64.b64decode(auth_match.group(1)).decode("utf-8", errors="replace")
                if ":" in decoded:
                    u, p = decoded.split(":", 1)
                    creds.append({"username": u, "password": p})
            except Exception:
                pass
        form_match = re.search(r"(?:username|user)=([^&\s]+).*?(?:password|pass)=([^&\s]+)",
                               text, re.IGNORECASE)
        if form_match:
            creds.append({"username": form_match.group(1), "password": form_match.group(2)})

    return creds


def _classify_ttps(service: str, commands: list[str]) -> list[str]:
    """Map observed behavior to MITRE ATT&CK TTP IDs."""
    ttps = set()
    base_ttp = MITRE_MAP.get(service)
    if base_ttp:
        ttps.add(base_ttp)

    text = " ".join(commands).lower()

    if any(cmd in text for cmd in ["ls", "dir", "pwd", "whoami", "id", "uname"]):
        ttps.add("T1082")  # System Information Discovery
    if any(cmd in text for cmd in ["cat /etc/passwd", "cat /etc/shadow", "net user"]):
        ttps.add("T1003")  # OS Credential Dumping
    if any(cmd in text for cmd in ["wget", "curl", "fetch", "download"]):
        ttps.add("T1041")  # Exfiltration Over C2 Channel
    if any(cmd in text for cmd in ["bash", "sh", "cmd", "powershell", "/bin/"]):
        ttps.add("T1059")  # Command and Scripting Interpreter
    if SQLI_PATTERN.search(text):
        ttps.add("T1190")  # Exploit Public-Facing Application
    if len(commands) > 5:
        ttps.add("T1110.004")  # Credential Stuffing

    return sorted(ttps)


def _write_to_db(
    src_ip: str, src_port: int, service: str,
    credentials: list, commands: list, raw_bytes: bytes, duration: float
):
    """Write honeypot interaction to the honeypot_logs table."""
    ttps = _classify_ttps(service, commands)
    db = SessionLocal()
    try:
        log = models.HoneypotLog(
            timestamp=datetime.now(timezone.utc),
            src_ip=src_ip,
            port=src_port,
            service=service,
            payload=raw_bytes.hex(),
            credentials_attempted=json.dumps(credentials),
            session_duration=round(duration, 3),
            mitre_ttp=json.dumps(ttps),
        )
        db.add(log)
        db.commit()
        logger.info(f"[Honeypot] {service.upper()} session from {src_ip}:{src_port} "
                    f"({len(credentials)} creds, {len(commands)} cmds, TTPs: {ttps})")
    except Exception as e:
        logger.warning(f"[Honeypot] DB write error: {e}")
        db.rollback()
    finally:
        db.close()


class HoneypotSession:
    def __init__(self, reader, writer, service: str, cfg: dict):
        self.reader = reader
        self.writer = writer
        self.service = service
        self.cfg = cfg
        self.start_time = time.time()
        peername = writer.get_extra_info("peername") or ("0.0.0.0", 0)
        self.src_ip, self.src_port = peername[0], int(peername[1])
        self.credentials: list = []
        self.commands: list = []
        self.raw_bytes = bytearray()

    async def run(self):
        try:
            self.writer.write(self.cfg["banner"])
            await self.writer.drain()
            await asyncio.wait_for(self._read_loop(), timeout=30.0)
        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            logger.debug(f"[Honeypot/{self.service}] session error: {e}")
        finally:
            duration = time.time() - self.start_time
            self.credentials = _extract_credentials(self.service, bytes(self.raw_bytes))
            _write_to_db(
                self.src_ip, self.src_port, self.service,
                self.credentials, self.commands, bytes(self.raw_bytes), duration
            )
            try:
                self.writer.close()
            except Exception:
                pass

    async def _read_loop(self):
        while True:
            data = await self.reader.read(4096)
            if not data:
                break
            self.raw_bytes.extend(data)
            text = data.decode("utf-8", errors="replace").strip()
            if text:
                for line in text.splitlines():
                    line = line.strip()
                    if line:
                        self.commands.append(line)
            # Send a realistic prompt for interactive services
            if self.service == "ssh":
                self.writer.write(b"Password: ")
            elif self.service == "ftp":
                self.writer.write(b"331 Password required\r\n")
            elif self.service == "telnet":
                self.writer.write(b"Password: ")
            elif self.service == "http":
                self.writer.write(b"HTTP/1.1 401 Unauthorized\r\n\r\n")
                break
            try:
                await self.writer.drain()
            except Exception:
                break


class HoneypotServer:
    def __init__(self):
        self._servers: list = []

    async def start(self):
        for name, cfg in SERVICES.items():
            try:
                server = await asyncio.start_server(
                    lambda r, w, n=name, c=cfg: asyncio.create_task(
                        HoneypotSession(r, w, n, c).run()
                    ),
                    "0.0.0.0",
                    cfg["port"],
                )
                self._servers.append(server)
                logger.info(f"[Honeypot] {name.upper()} listening on port {cfg['port']}")
            except Exception as e:
                logger.warning(f"[Honeypot] Failed to start {name}: {e}")

    async def stop(self):
        for s in self._servers:
            s.close()
            try:
                await s.wait_closed()
            except Exception:
                pass


honeypot_server = HoneypotServer()
