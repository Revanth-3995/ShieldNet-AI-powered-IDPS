"""
ShieldNet — IDPS Modular Test
Verifies flow generation, feature extraction, and mock inference.
"""
import pytest
import asyncio
import numpy as np
from backend.services.idps.capture.flow_generator import Flow
from backend.services.idps.features.feature_schema import FeatureExtractor
from backend.services.idps.detection.rule_engine import RuleEngine

def test_flow_accumulation():
    flow = Flow("test_flow", "1.1.1.1", "2.2.2.2", 1234, 80, "TCP")
    flow.update(100, "fwd", "S")
    time_delay = 0.1
    import time
    time.sleep(time_delay)
    flow.update(200, "bwd", "SA")
    
    assert flow.fwd_packets == 1
    assert flow.bwd_packets == 1
    assert flow.fwd_bytes == 100
    assert flow.bwd_bytes == 200
    assert flow.syn_count == 2 # One S, one SA contains S
    assert flow.ack_count == 1

def test_feature_extraction():
    flow = Flow("test_feat", "1.1.1.1", "2.2.2.2", 1234, 80, "TCP")
    for i in range(5):
        flow.update(100 + i, "fwd", "A")
        flow.update(50 + i, "bwd", "A")
        
    features = FeatureExtractor.extract_all(flow)
    assert features["tot_fwd_pkts"] == 5
    assert features["tot_bwd_pkts"] == 5
    assert "flow_duration" in features
    assert "pkt_len_mean" in features
    assert features["payload_entropy"] == 0.0 # No payload sampled

def test_rule_engine():
    engine = RuleEngine()
    # Simulate port scan
    for port in range(1000, 1060):
        res = engine.check_packet({
            "src_ip": "10.0.0.1",
            "dst_port": port,
            "protocol": "TCP",
            "flags": "S"
        })
        if res:
            break
            
    assert res is not None
    

if __name__ == "__main__":
    test_flow_accumulation()
    test_feature_extraction()
    test_rule_engine()
    print("All IDPS modular tests passed!")
