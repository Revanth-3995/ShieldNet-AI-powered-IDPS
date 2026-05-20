"""
ShieldNet — IDPS Rule Engine
Fast, heuristic-based detection layer for well-known attack patterns.
"""
from typing import Dict, Any, Optional, List
import time
from collections import defaultdict
import threading

class RuleEngine:
    def __init__(self):
        # Tracking states (IP-based)
        self.port_scan_history = defaultdict(set)
        self.syn_history = defaultdict(int)
        self.auth_attempt_history = defaultdict(int)
        self.packet_rate_history = defaultdict(list) # Stores timestamps of last N packets
        
        # Thresholds
        self.THRESHOLDS = {
            "port_scan": 30,         # Unique ports per 60s
            "syn_flood": 200,        # SYN packets without ACK
            "brute_force": 15,       # Attempts to auth ports (22, 3389, 21)
            "ddos_pps": 1500,        # Packets per second
            "max_pkt_size": 1500,    # Typical MTU
            "min_pkt_size": 20,      # IP header only
        }
        
        # Signatures
        self.SQLI_SIGNATURES = [
            "UNION SELECT", "OR '1'='1'", "DROP TABLE", "--", "SLEEP(", "BENCHMARK("
        ]
        
        self._lock = threading.Lock()

    def check_packet(self, packet_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Run fast heuristic checks on individual packet metadata and payload.
        """
        src_ip = packet_data.get("src_ip")
        dst_port = packet_data.get("dst_port")
        flags = packet_data.get("flags", "")
        protocol = packet_data.get("protocol")
        pkt_len = packet_data.get("len", 0)
        payload = packet_data.get("payload_str", "") # Extracted payload snippet
        
        now = time.time()
        
        with self._lock:
            # --- 1. Port Scanning Detection (Vertical/Horizontal) ---
            if dst_port:
                self.port_scan_history[src_ip].add(dst_port)
                if len(self.port_scan_history[src_ip]) > self.THRESHOLDS["port_scan"]:
                    return self._alert("PortScan", "Vertical Port Sweep detected", 0.95, "high")

            # --- 2. SYN Flood Heuristic ---
            if protocol == "TCP" and "S" in flags and "A" not in flags:
                self.syn_history[src_ip] += 1
                if self.syn_history[src_ip] > self.THRESHOLDS["syn_flood"]:
                    return self._alert("DoS", "SYN Flood pattern recognized", 0.90, "critical")
            
            # --- 3. Brute Force (Auth Ports) ---
            if dst_port in [22, 3389, 21, 23]: # SSH, RDP, FTP, Telnet
                self.auth_attempt_history[src_ip] += 1
                if self.auth_attempt_history[src_ip] > self.THRESHOLDS["brute_force"]:
                    return self._alert("BruteForce", "Excessive auth attempts to secure port", 0.92, "high")

            # --- 4. DDoS / Rate Limiting ---
            self.packet_rate_history[src_ip].append(now)
            # Prune older than 1s
            self.packet_rate_history[src_ip] = [t for t in self.packet_rate_history[src_ip] if now - t < 1.0]
            if len(self.packet_rate_history[src_ip]) > self.THRESHOLDS["ddos_pps"]:
                return self._alert("DDoS", "Extreme packet rate (PPS) violation", 0.98, "critical")

            # --- 5. SQL Injection (Simple Signature) ---
            if any(sig.lower() in payload.upper() for sig in self.SQLI_SIGNATURES):
                return self._alert("WebAttack", "SQL Injection signature matched", 0.88, "high")

            # --- 6. Packet Size Anomalies ---
            if pkt_len > self.THRESHOLDS["max_pkt_size"]:
                return self._alert("AnomPkt", "Oversized packet detected (Potential Jumbo Probe)", 0.60, "medium")
            if pkt_len < self.THRESHOLDS["min_pkt_size"] and pkt_len > 0:
                return self._alert("AnomPkt", "Abnormally small packet header", 0.55, "low")

        return None

    def _alert(self, attack: str, rule: str, conf: float, sev: str):
        return {
            "rule": rule,
            "attack_type": attack,
            "confidence": conf,
            "severity": sev,
            "explanation": f"Rule Triggered: {rule}"
        }

    def prune_history(self):
        """Periodically clear old history to prevent memory bloat."""
        with self._lock:
            self.port_scan_history.clear()
            self.syn_history.clear()
            self.auth_attempt_history.clear()
            self.packet_rate_history.clear()
