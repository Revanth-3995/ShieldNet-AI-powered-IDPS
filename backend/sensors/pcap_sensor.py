"""
ShieldNet — Live PCAP Sensor
============================
Sniffs real network traffic using Scapy and forwards detections to ShieldNet backend.

Requirements:
  - Npcap installed on Windows: https://npcap.com  (free, from nmap project)
  - scapy already in requirements.txt

Usage:
  python -m backend.sensors.pcap_sensor
  python -m backend.sensors.pcap_sensor --iface "Wi-Fi"
  python -m backend.sensors.pcap_sensor --iface "Ethernet" --threshold-scan 10
"""
from __future__ import annotations

import argparse
import time
import threading
import requests
from collections import defaultdict
from datetime import datetime

API_BASE = "http://127.0.0.1:8000"
HEARTBEAT_INTERVAL = 10  # seconds


def _resolve_iface_name(friendly_name: str) -> str | None:
    """On Windows, resolve a friendly interface name (e.g. 'Wi-Fi') to Scapy's NPF path."""
    try:
        import winreg, re
        from scapy.all import get_if_list
        reg = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r'SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}')
        guid_to_name = {}
        i = 0
        while True:
            try:
                guid = winreg.EnumKey(reg, i)
                try:
                    conn = winreg.OpenKey(reg, guid + r'\Connection')
                    name = winreg.QueryValueEx(conn, 'Name')[0]
                    guid_to_name[guid.upper()] = name
                except Exception:
                    pass
                i += 1
            except OSError:
                break
        for iface in get_if_list():
            m = re.search(r'\{([A-F0-9\-]+)\}', iface.upper())
            if m:
                guid = '{' + m.group(1) + '}'
                if guid_to_name.get(guid, '').lower() == friendly_name.lower():
                    return iface
    except Exception:
        pass
    return None

# ─────────────────────────────────────────────────────────────────────────────
# Flow state per source IP
# ─────────────────────────────────────────────────────────────────────────────
_flow: dict[str, dict] = defaultdict(lambda: {
    "pkt_count": 0,
    "syn_count": 0,
    "udp_count": 0,
    "dst_ports": set(),
    "udp_ports": defaultdict(int),
    "bytes": 0,
    "first_seen": time.time(),
    "last_seen": time.time(),
})

_stats = {"packets_seen": 0, "alerts_sent": 0, "active": True, "started_at": datetime.utcnow().isoformat()}
_lock = threading.Lock()

# Thresholds (adjustable via CLI)
THRESHOLD_PORTSCAN_PORTS = 15     # unique dst ports in window → PortScan
THRESHOLD_SYN_FLOOD = 50          # SYN packets in window → SYNFlood
THRESHOLD_DOS_PKTS = 200          # total pkts in window → DoS
THRESHOLD_UDP_FLOOD = 100         # UDP pkts to same port in window → UDPFlood
THRESHOLD_LARGE_PKT = 65000       # bytes in single packet → AnomPkt
WINDOW_SECONDS = 10               # sliding window duration


def _post_idps(src_ip: str, attack_type: str, confidence: float, rule: str, protocol: str = "TCP", dst_port: int = 0):
    """Forward a detection to the ShieldNet IDPS endpoint."""
    try:
        r = requests.post(f"{API_BASE}/api/idps/event", json={
            "source_ip": src_ip,
            "attack_type": attack_type,
            "confidence": confidence,
            "protocol": protocol,
            "dst_port": dst_port,
            "rule_triggered": rule,
        }, timeout=5)
        with _lock:
            _stats["alerts_sent"] += 1
        print(f"  [PCAP] → {attack_type} from {src_ip} [{r.status_code}]")
    except Exception as e:
        print(f"  [PCAP] POST failed: {e}")


def _post_heartbeat():
    """Tell the backend this sensor is alive."""
    try:
        requests.post(f"{API_BASE}/api/sensors/heartbeat", json={
            "sensor": "pcap",
            "packets_seen": _stats["packets_seen"],
            "alerts_sent": _stats["alerts_sent"],
        }, timeout=3)
    except Exception:
        pass


def _heartbeat_loop():
    while _stats["active"]:
        _post_heartbeat()
        time.sleep(HEARTBEAT_INTERVAL)


def _reset_flow(src_ip: str):
    _flow[src_ip] = {
        "pkt_count": 0,
        "syn_count": 0,
        "udp_count": 0,
        "dst_ports": set(),
        "udp_ports": defaultdict(int),
        "bytes": 0,
        "first_seen": time.time(),
        "last_seen": time.time(),
    }


def _analyze_flow(src_ip: str):
    """Check flow state for attack patterns and fire alerts."""
    f = _flow[src_ip]
    now = time.time()
    window = now - f["first_seen"]
    if window < 1:
        return

    alerts_fired = []

    # Port Scan — many unique destination ports
    if len(f["dst_ports"]) >= THRESHOLD_PORTSCAN_PORTS:
        alerts_fired.append(("PortScan", 0.94, "PortSweep", "TCP", 0))

    # SYN Flood
    if f["syn_count"] >= THRESHOLD_SYN_FLOOD:
        alerts_fired.append(("DoS", 0.96, "SYNFlood", "TCP", 80))

    # Generic DoS — high packet volume
    if f["pkt_count"] >= THRESHOLD_DOS_PKTS and not f["syn_count"] >= THRESHOLD_SYN_FLOOD:
        alerts_fired.append(("DoS", 0.88, "HighVolumeTraffic", "TCP", 0))

    # UDP Flood — many UDP packets to same port
    for port, count in f["udp_ports"].items():
        if count >= THRESHOLD_UDP_FLOOD:
            alerts_fired.append(("DDoS", 0.90, "UDPFlood", "UDP", port))
            break

    for (attack_type, confidence, rule, proto, dst_port) in alerts_fired:
        _post_idps(src_ip, attack_type, confidence, rule, proto, dst_port)

    # Reset flow after analysis to avoid duplicate alerts
    if alerts_fired:
        _reset_flow(src_ip)


def _process_packet(pkt):
    """Scapy packet callback — called for every captured packet."""
    try:
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.inet6 import IPv6

        # Extract source IP
        if IP in pkt:
            src_ip = pkt[IP].src
            pkt_len = len(pkt)
        elif IPv6 in pkt:
            src_ip = pkt[IPv6].src
            pkt_len = len(pkt)
        else:
            return

        with _lock:
            _stats["packets_seen"] += 1

        # Skip loopback and broadcast
        if src_ip.startswith("127.") or src_ip == "255.255.255.255":
            return

        f = _flow[src_ip]
        now = time.time()

        # Reset window if too old
        if now - f["first_seen"] > WINDOW_SECONDS:
            _reset_flow(src_ip)
            f = _flow[src_ip]

        f["pkt_count"] += 1
        f["bytes"] += pkt_len
        f["last_seen"] = now

        # Large packet anomaly — immediate alert
        if pkt_len >= THRESHOLD_LARGE_PKT:
            _post_idps(src_ip, "AnomPkt", 0.85, "OversizedPacket", "TCP", 0)
            return

        # TCP analysis
        if TCP in pkt:
            dst_port = pkt[TCP].dport
            f["dst_ports"].add(dst_port)
            flags = pkt[TCP].flags
            # SYN flag set, ACK not set → pure SYN
            if flags & 0x02 and not flags & 0x10:
                f["syn_count"] += 1

        # UDP analysis
        elif UDP in pkt:
            dst_port = pkt[UDP].dport
            f["udp_ports"][dst_port] += 1
            f["udp_count"] += 1

        # Analyze every 20 packets from same IP to avoid overhead
        if f["pkt_count"] % 20 == 0:
            _analyze_flow(src_ip)

    except Exception as e:
        pass  # Never crash the sniff loop


def run(iface: str | None = None):
    """Start the PCAP sensor."""
    try:
        from scapy.all import sniff, get_if_list, conf
    except ImportError:
        print("[PCAP] ERROR: scapy not installed. Run: pip install scapy")
        print("[PCAP] Also install Npcap from https://npcap.com (Windows)")
        return

    # On Windows, Scapy needs the full \Device\NPF_{GUID} path.
    # If user passed a friendly name like "Wi-Fi", resolve it to NPF path.
    resolved_iface = iface
    if iface and not iface.startswith("\\Device\\NPF") and not iface.startswith("{"):
        resolved_iface = _resolve_iface_name(iface)
        if resolved_iface:
            print(f"  [PCAP] Resolved '{iface}' → {resolved_iface}")
        else:
            print(f"  [PCAP] WARNING: Could not resolve '{iface}', using default interface")
            resolved_iface = None

    # If no interface specified, use Scapy's auto-detected default (Wi-Fi or Ethernet)
    if not resolved_iface:
        resolved_iface = str(conf.iface)

    print("=" * 60)
    print("  ShieldNet PCAP Sensor")
    print("=" * 60)
    print(f"  Interface : {resolved_iface}")
    print(f"  Backend   : {API_BASE}")
    print(f"  Thresholds: PortScan≥{THRESHOLD_PORTSCAN_PORTS}ports, SYN≥{THRESHOLD_SYN_FLOOD}, DoS≥{THRESHOLD_DOS_PKTS}pkts")
    print("  Press Ctrl+C to stop")
    print("=" * 60)

    # Start heartbeat thread
    hb_thread = threading.Thread(target=_heartbeat_loop, daemon=True)
    hb_thread.start()
    _post_heartbeat()

    try:
        sniff(
            iface=resolved_iface,
            prn=_process_packet,
            store=False,
            filter="ip or ip6",
        )
    except PermissionError:
        print("\n[PCAP] ERROR: Permission denied. Run as Administrator on Windows.")
    except OSError as e:
        print(f"\n[PCAP] ERROR: {e}")
        print("[PCAP] Try running: python -m backend.sensors.pcap_sensor --list-ifaces")
    except KeyboardInterrupt:
        print(f"\n[PCAP] Stopped. Packets seen: {_stats['packets_seen']}, Alerts: {_stats['alerts_sent']}")
    finally:
        _stats["active"] = False
        _post_heartbeat()



def list_interfaces():
    """Print available network interfaces."""
    try:
        from scapy.all import get_if_list, get_if_addr
        print("\nAvailable network interfaces:")
        for iface in get_if_list():
            try:
                addr = get_if_addr(iface)
                print(f"  {iface:40s}  {addr}")
            except Exception:
                print(f"  {iface}")
    except ImportError:
        print("ERROR: scapy not installed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ShieldNet Live PCAP Sensor")
    parser.add_argument("--iface", default=None, help="Network interface to sniff (default: auto)")
    parser.add_argument("--list-ifaces", action="store_true", help="List available interfaces and exit")
    parser.add_argument("--api", default=API_BASE, help=f"Backend API base URL (default: {API_BASE})")
    parser.add_argument("--threshold-scan", type=int, default=THRESHOLD_PORTSCAN_PORTS,
                        help=f"Unique ports threshold for port scan detection (default: {THRESHOLD_PORTSCAN_PORTS})")
    parser.add_argument("--threshold-syn", type=int, default=THRESHOLD_SYN_FLOOD,
                        help=f"SYN packet threshold for flood detection (default: {THRESHOLD_SYN_FLOOD})")
    args = parser.parse_args()

    if args.list_ifaces:
        list_interfaces()
    else:
        API_BASE = args.api
        THRESHOLD_PORTSCAN_PORTS = args.threshold_scan
        THRESHOLD_SYN_FLOOD = args.threshold_syn
        run(iface=args.iface)
