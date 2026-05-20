"""
ShieldNet — Honeypot Engine
Simulates vulnerable network services to trap and log attackers.
"""
from __future__ import annotations

import asyncio
import time
from typing import Optional

import requests

from backend.core.logging import get_logger
from backend.core.config import settings

logger = get_logger("shieldnet.honeypot")

MITRE_TTPS = {
    "ssh": {"credential_attempt": "T1110 - Brute Force", "command_exec": "T1059 - Command and Scripting Interpreter"},
    "http": {"sql_injection": "T1190 - Exploit Public-Facing Application", "default": "T1046 - Network Service Discovery"},
    "ftp": {"credential": "T1110 - Brute Force"},
    "telnet": {"command_exec": "T1059 - Command and Scripting Interpreter"},
}


def classify_ttp(service: str, payload: str) -> str:
    payload_lower = payload.lower()
    if service == "ssh":
        if any(cmd in payload_lower for cmd in ["ls", "cat", "wget", "curl", "chmod", "python"]):
            return MITRE_TTPS["ssh"]["command_exec"]
        return MITRE_TTPS["ssh"]["credential_attempt"]
    if service == "http":
        if any(s in payload_lower for s in ["select", "union", "drop", "insert", "'"]):
            return MITRE_TTPS["http"]["sql_injection"]
        return MITRE_TTPS["http"]["default"]
    if service == "ftp":
        return MITRE_TTPS["ftp"]["credential"]
    if service == "telnet":
        return MITRE_TTPS["telnet"]["command_exec"]
    return "T1046 - Network Service Discovery"


def log_to_backend(src_ip: str, port: int, service: str, payload: str, credentials: Optional[str] = None, duration: float = 0.0, ttp: str = ""):
    try:
        params = {
            "src_ip": src_ip,
            "port": port,
            "service": service,
            "payload": payload[:500],
            "credentials": credentials,
            "session_duration": duration,
            "mitre_ttp": ttp,
        }
        requests.post(f"{settings.app.API_BASE_URL}/api/honeypot/log", params=params, timeout=5)
    except Exception as e:
        logger.error(f"Failed to log to backend: {e}")


async def handle_ssh(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    addr = writer.get_extra_info("peername")
    src_ip = addr[0] if addr else "unknown"
    start = time.time()
    writer.write(b"SSH-2.0-OpenSSH_7.4\r\n")
    await writer.drain()
    try:
        await asyncio.wait_for(reader.read(256), timeout=5)
        writer.write(b"login as: ")
        await writer.drain()
        username = (await asyncio.wait_for(reader.readline(), timeout=10)).decode(errors="ignore").strip()
        writer.write(f"{username}@honeypot's password: ".encode())
        await writer.drain()
        password = (await asyncio.wait_for(reader.readline(), timeout=10)).decode(errors="ignore").strip()
        creds = f"{username}:{password}"
        writer.write(b"\r\nAccess denied.\r\n")
        await writer.drain()
        ttp = classify_ttp("ssh", username + password)
        log_to_backend(src_ip, 22, "ssh", f"AUTH ATTEMPT: {username}/{password}", credentials=creds, duration=time.time() - start, ttp=ttp)
    except Exception:
        pass
    finally:
        writer.close()


async def handle_http(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    addr = writer.get_extra_info("peername")
    src_ip = addr[0] if addr else "unknown"
    start = time.time()
    try:
        request_data = await asyncio.wait_for(reader.read(4096), timeout=5)
        request_str = request_data.decode(errors="ignore")
        ttp = classify_ttp("http", request_str)
        response = (
            "HTTP/1.1 200 OK\r\nServer: Apache/2.2.34 (Unix)\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n"
            "<html><body><h1>Welcome to Admin</h1></body></html>"
        )
        writer.write(response.encode())
        await writer.drain()
        log_to_backend(src_ip, 80, "http", request_str[:500], duration=time.time() - start, ttp=ttp)
    except Exception:
        pass
    finally:
        writer.close()


async def handle_ftp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    addr = writer.get_extra_info("peername")
    src_ip = addr[0] if addr else "unknown"
    start = time.time()
    writer.write(b"220 (vsFTPd 2.3.4)\r\n")
    await writer.drain()
    username = ""
    try:
        while True:
            line = (await asyncio.wait_for(reader.readline(), timeout=10)).decode(errors="ignore").strip()
            if not line:
                break
            if line.upper().startswith("USER "):
                username = line[5:]
                writer.write(b"331 Please specify the password.\r\n")
            elif line.upper().startswith("PASS "):
                password = line[5:]
                creds = f"{username}:{password}"
                writer.write(b"530 Login incorrect.\r\n")
                await writer.drain()
                log_to_backend(src_ip, 21, "ftp", f"FTP AUTH: {line}", credentials=creds, duration=time.time() - start, ttp=classify_ttp("ftp", line))
                break
            else:
                writer.write(b"530 Please login with USER and PASS.\r\n")
            await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()


async def handle_telnet(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    addr = writer.get_extra_info("peername")
    src_ip = addr[0] if addr else "unknown"
    start = time.time()
    writer.write(b"\r\nUbuntu 18.04 LTS\r\nlogin: ")
    await writer.drain()
    try:
        username = (await asyncio.wait_for(reader.readline(), timeout=10)).decode(errors="ignore").strip()
        writer.write(b"Password: ")
        await writer.drain()
        password = (await asyncio.wait_for(reader.readline(), timeout=10)).decode(errors="ignore").strip()
        creds = f"{username}:{password}"
        writer.write(b"\r\nLogin incorrect\r\n")
        await writer.drain()
        log_to_backend(src_ip, 23, "telnet", f"CREDS:{creds}", credentials=creds, duration=time.time() - start, ttp=classify_ttp("telnet", creds))
    except Exception:
        pass
    finally:
        writer.close()


async def run_honeypot():
    services = [("SSH", 22, handle_ssh), ("HTTP", 80, handle_http), ("FTP", 21, handle_ftp), ("Telnet", 23, handle_telnet)]
    servers = []
    for name, port, handler in services:
        try:
            server = await asyncio.start_server(handler, "0.0.0.0", port)
            servers.append(server)
            logger.info(f"[Honeypot] {name} listening on port {port}")
        except PermissionError:
            fallback = port + 10000
            server = await asyncio.start_server(handler, "0.0.0.0", fallback)
            servers.append(server)
            logger.info(f"[Honeypot] {name} listening on port {fallback} (fallback)")
        except Exception as e:
            logger.error(f"[Honeypot] Failed to start {name} on {port}: {e}")

    if not servers:
        logger.error("No honeypot services started.")
        return
    await asyncio.gather(*[s.serve_forever() for s in servers])
