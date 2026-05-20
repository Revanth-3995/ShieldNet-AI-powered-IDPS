"""
ShieldNet — IDPS Feature Engineering
Extracts statistical, timing, entropy, and behavioral features from network flows.
"""
import numpy as np
from typing import Dict, Any, List
import math
from backend.services.idps.capture.flow_generator import Flow

class FeatureExtractor:
    @staticmethod
    def extract_all(flow: Flow) -> Dict[str, Any]:
        """Extract comprehensive feature set for ML models."""
        features = {}
        
        # 1. Basic Flow Statistics
        duration = flow.duration
        total_packets = flow.fwd_packets + flow.bwd_packets
        total_bytes = flow.fwd_bytes + flow.bwd_bytes
        
        features["flow_duration"] = duration
        features["tot_fwd_pkts"] = flow.fwd_packets
        features["tot_bwd_pkts"] = flow.bwd_packets
        features["tot_len_fwd_pkts"] = flow.fwd_bytes
        features["tot_len_bwd_pkts"] = flow.bwd_bytes
        
        features["fwd_pkt_len_max"] = float(np.max(flow.fwd_pkt_lengths)) if flow.fwd_pkt_lengths else 0
        features["fwd_pkt_len_min"] = float(np.min(flow.fwd_pkt_lengths)) if flow.fwd_pkt_lengths else 0
        features["fwd_pkt_len_mean"] = float(np.mean(flow.fwd_pkt_lengths)) if flow.fwd_pkt_lengths else 0
        features["fwd_pkt_len_std"] = float(np.std(flow.fwd_pkt_lengths)) if len(flow.fwd_pkt_lengths) > 1 else 0
        
        features["bwd_pkt_len_max"] = float(np.max(flow.bwd_pkt_lengths)) if flow.bwd_pkt_lengths else 0
        features["bwd_pkt_len_min"] = float(np.min(flow.bwd_pkt_lengths)) if flow.bwd_pkt_lengths else 0
        features["bwd_pkt_len_mean"] = float(np.mean(flow.bwd_pkt_lengths)) if flow.bwd_pkt_lengths else 0
        features["bwd_pkt_len_std"] = float(np.std(flow.bwd_pkt_lengths)) if len(flow.bwd_pkt_lengths) > 1 else 0

        features["flow_byts_s"] = total_bytes / duration
        features["flow_pkts_s"] = total_packets / duration
        
        # 2. Advanced Timing Features (IAT)
        all_iat = flow.fwd_iat + flow.bwd_iat
        features["flow_iat_mean"] = float(np.mean(all_iat)) if all_iat else 0
        features["flow_iat_std"] = float(np.std(all_iat)) if len(all_iat) > 1 else 0
        features["flow_iat_max"] = float(np.max(all_iat)) if all_iat else 0
        features["flow_iat_min"] = float(np.min(all_iat)) if all_iat else 0
        
        features["fwd_iat_tot"] = sum(flow.fwd_iat)
        features["bwd_iat_tot"] = sum(flow.bwd_iat)
        features["fwd_iat_std"] = float(np.std(flow.fwd_iat)) if len(flow.fwd_iat) > 1 else 0
        features["bwd_iat_std"] = float(np.std(flow.bwd_iat)) if len(flow.bwd_iat) > 1 else 0

        # 3. Enhanced Flag Features
        features["fin_flag_cnt"] = flow.fin_count
        features["syn_flag_cnt"] = flow.syn_count
        features["rst_flag_cnt"] = flow.rst_count
        features["psh_flag_cnt"] = flow.psh_count
        features["ack_flag_cnt"] = flow.ack_count
        features["urg_flag_cnt"] = flow.urg_count
        
        # Ratios (Anomaly Indicators)
        features["syn_ack_ratio"] = flow.syn_count / max(flow.ack_count, 1)
        features["rst_syn_ratio"] = flow.rst_count / max(flow.syn_count, 1)
        
        # 4. Behavioral & Burst Metrics
        features["pkt_len_mean"] = float(np.mean(flow.fwd_pkt_lengths + flow.bwd_pkt_lengths)) if total_packets > 0 else 0
        features["pkt_size_avg"] = total_bytes / total_packets if total_packets > 0 else 0
        
        fwd_burstiness = (np.max(flow.fwd_pkt_lengths) / np.mean(flow.fwd_pkt_lengths)) if flow.fwd_packets > 0 else 1.0
        features["fwd_burstiness"] = float(fwd_burstiness)
        features["fwd_pkts_bwd_pkts_ratio"] = flow.fwd_packets / max(flow.bwd_packets, 1)
        features["fwd_bytes_bwd_bytes_ratio"] = flow.fwd_bytes / max(flow.bwd_bytes, 1)
        
        # 5. Information Theory & Entropy
        features["payload_entropy"] = FeatureExtractor._calculate_entropy(flow.payload_samples) if getattr(flow, "payload_samples", None) else 0.0
        features["dst_port_type"] = 1.0 if getattr(flow, "dst_port", 49152) < 1024 else (0.5 if getattr(flow, "dst_port", 49152) < 49151 else 0.0)
        
        # 6. Directional Asymmetry
        features["pkt_count_asymmetry"] = (flow.fwd_packets - flow.bwd_packets) / total_packets if total_packets > 0 else 0
        features["byte_count_asymmetry"] = (flow.fwd_bytes - flow.bwd_bytes) / total_bytes if total_bytes > 0 else 0

        # 7. Normalization & Log Scaling
        for key in ["flow_byts_s", "flow_pkts_s", "tot_len_fwd_pkts", "tot_len_bwd_pkts"]:
            features[f"log_{key}"] = math.log1p(features.get(key, 0))

        return features


        return features

    @staticmethod
    def _calculate_entropy(payloads: List[bytes]) -> float:
        if not payloads:
            return 0.0
        combined = b"".join(payloads)
        if not combined:
            return 0.0
        
        counts = np.bincount(np.frombuffer(combined, dtype=np.uint8), minlength=256)
        probs = counts[counts > 0] / len(combined)
        return float(-np.sum(probs * np.log2(probs)))

    @staticmethod
    def _calculate_port_entropy(port: int) -> float:
        # Simplified: likelihood of port being in ephemeral range vs common
        if port < 1024: return 0.2
        if port < 49151: return 0.5
        return 0.8
