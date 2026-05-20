"""
ShieldNet — IDPS Flow Generator
Groups packets into bidirectional flows and tracks raw statistics.
"""
import time
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
import numpy as np

@dataclass
class Flow:
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float = field(default_factory=time.time)
    last_time: float = field(default_factory=time.time)
    
    # Forward (src -> dst)
    fwd_packets: int = 0
    fwd_bytes: int = 0
    fwd_pkt_lengths: List[int] = field(default_factory=list)
    fwd_iat: List[float] = field(default_factory=list)
    
    # Backward (dst -> src)
    bwd_packets: int = 0
    bwd_bytes: int = 0
    bwd_pkt_lengths: List[int] = field(default_factory=list)
    bwd_iat: List[float] = field(default_factory=list)
    
    # Flags
    flags: List[str] = field(default_factory=list)
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    urg_count: int = 0
    
    # Payload
    payload_samples: List[bytes] = field(default_factory=list)
    
    _last_fwd_time: float = 0.0
    _last_bwd_time: float = 0.0

    def update(self, packet_len: int, direction: str, flags: str = "", payload: bytes = b"") -> None:
        now = time.time()
        self.last_time = now
        self.flags.append(flags)
        
        # Update flags counts
        if "S" in flags: self.syn_count += 1
        if "A" in flags: self.ack_count += 1
        if "F" in flags: self.fin_count += 1
        if "R" in flags: self.rst_count += 1
        if "P" in flags: self.psh_count += 1
        if "U" in flags: self.urg_count += 1
        
        if len(self.payload_samples) < 5 and payload:
            self.payload_samples.append(payload[:128]) # Sample first few payloads

        if direction == "fwd":
            self.fwd_packets += 1
            self.fwd_bytes += packet_len
            self.fwd_pkt_lengths.append(packet_len)
            if self._last_fwd_time > 0:
                self.fwd_iat.append(now - self._last_fwd_time)
            self._last_fwd_time = now
        else:
            self.bwd_packets += 1
            self.bwd_bytes += packet_len
            self.bwd_pkt_lengths.append(packet_len)
            if self._last_bwd_time > 0:
                self.bwd_iat.append(now - self._last_bwd_time)
            self._last_bwd_time = now

    @property
    def duration(self) -> float:
        return max(self.last_time - self.start_time, 1e-6)
