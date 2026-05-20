"""
ShieldNet — Advanced AI-Driven IDPS Engine
Integrated behavioral analysis with Rule-ML hybrid detection.
"""
from __future__ import annotations
import asyncio
import threading
import time
from typing import Optional, Dict, Any, List
from collections import defaultdict

from backend.core.logging import get_logger
from backend.core.config import settings
from backend.db.database import SessionLocal
from backend.api.websocket.ws_manager import ws_manager
from backend.services.response.alert_bus import alert_bus, TOPIC_IDPS_DETECTION

# Modular Imports
from .capture.flow_generator import Flow
from .capture.traffic_stream import TrafficStream
from .features.flow_features import FeatureExtractor
from .models.classical_ml.xgboost_detector import XGBoostDetector
from .models.sequence_models.bilstm_detector import BiLSTMDetector
from .detection.rule_engine import RuleEngine
from .detection.attack_classifier import FusionEngine
from .response.response_manager import ResponseManager

logger = get_logger("shieldnet.idps.engine")

try:
    from scapy.all import IP, TCP, UDP, ICMP, sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available — packet capture disabled")

from .explainability.shap_analysis import ExplainabilityEngine

class IDPSEngine:
    def __init__(self):
        self.xgboost = XGBoostDetector(model_path=str(settings.ai.IDPS_MODEL_PATH))
        self.rule_engine = RuleEngine()
        self.sequence_detector = BiLSTMDetector()
        self.fusion_engine = FusionEngine()
        self.explainability = ExplainabilityEngine(model=self.xgboost)
        self.response_manager = ResponseManager(db_session_factory=SessionLocal)
        self.traffic_stream = TrafficStream(process_callback=self._process_packet_async)

        
        self.flows: Dict[tuple, Flow] = {}
        self.flow_history: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._flow_lock = threading.Lock()
        self._running = False
        
        self.stats = {
            "packets_processed": 0,
            "flows_active": 0,
            "detections": 0,
            "inference_count": 0
        }

    async def start(self):
        """Start the async components of the engine."""
        self._running = True
        await self.traffic_stream.start()
        # Start cleanup task
        asyncio.create_task(self._cleanup_loop())
        logger.info("IDPS Engine fully started.")

    def run_capture(self, iface: Optional[str] = None):
        """Start Scapy packet capture with optimized batching."""
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available. Real-time capture cannot start.")
            return
            
        logger.info(f"IDPS Engine: Starting real-time capture on {iface or 'default interface'}...")
        
        # Using sniff with a high-performance callback
        try:
            sniff(
                prn=self.traffic_stream.enqueue_packet, 
                store=False, 
                iface=iface,
                filter="ip", # BPF filter to reduce overhead
                count=0 # Infinite
            )
        except Exception as e:
            logger.error(f"Packet capture error: {e}")

    async def _process_packet_async(self, packet):
        """High-throughput packet processing pipeline."""
        if IP not in packet:
            return
            
        self.stats["packets_processed"] += 1
        
        # 1. Header Extraction (Optimized)
        ip_layer = packet[IP]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
        proto = "OTHER"
        src_port, dst_port = 0, 0
        flags = ""
        
        if TCP in packet:
            proto = "TCP"
            src_port, dst_port = int(packet[TCP].sport), int(packet[TCP].dport)
            flags = str(packet[TCP].flags)
        elif UDP in packet:
            proto = "UDP"
            src_port, dst_port = int(packet[UDP].sport), int(packet[UDP].dport)
        elif ICMP in packet:
            proto = "ICMP"

        packet_meta = {
            "src_ip": src_ip, "dst_ip": dst_ip, "src_port": src_port, "dst_port": dst_port,
            "protocol": proto, "flags": flags, "len": len(packet)
        }
        
        # 2. Heuristic Rule Check (Immediate)
        rule_hit = self.rule_engine.check_packet(packet_meta)
        if rule_hit:
            await self._handle_detection(packet_meta, rule_hit, source="rule_engine")
            return

        # 3. Flow State Management (Locked for thread-safety)
        flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
        rev_key = (dst_ip, src_ip, dst_port, src_port, proto)
        
        with self._flow_lock:
            if flow_key in self.flows:
                flow = self.flows[flow_key]
                flow.update(len(packet), "fwd", flags, bytes(ip_layer.payload)[:128])
            elif rev_key in self.flows:
                flow = self.flows[rev_key]
                flow.update(len(packet), "bwd", flags, bytes(ip_layer.payload)[:128])
            else:
                flow = Flow(f"{src_ip}_{dst_ip}", src_ip, dst_ip, src_port, dst_port, proto)
                flow.update(len(packet), "fwd", flags, bytes(ip_layer.payload)[:128])
                self.flows[flow_key] = flow

        # 4. Asynchronous ML Inference (Batch Trigger)
        total_pkts = flow.fwd_packets + flow.bwd_packets
        # Trigger ML analysis after initial handshake or every N packets
        if (total_pkts == 5) or (total_pkts > 10 and total_pkts % 20 == 0):
            asyncio.create_task(self._perform_inference(src_ip, flow))

    async def _perform_inference(self, src_ip: str, flow: Flow):
        """Offload CPU-heavy ML inference to keep packet ingestion fast."""
        try:
            start_time = time.time()
            features = FeatureExtractor.extract_all(flow)
            
            # Behavioral ML (XGBoost)
            ml_hit = self.xgboost.predict(features)
            
            # Temporal Sequence (BiLSTM)
            history = self.flow_history[src_ip]
            history.append(features)
            if len(history) > 20: history.pop(0)
            
            seq_input = self.sequence_detector.prepare_sequence(history)
            seq_hit = await self.sequence_detector.predict_sequence(seq_input)
            
            # Intelligent Fusion
            fusion = self.fusion_engine.fuse_results(
                rule_hit=None, ml_hit=ml_hit, seq_hit=seq_hit, ip=src_ip
            )
            
            latency = (time.time() - start_time) * 1000
            self.stats["inference_count"] += 1
            
            if fusion["attack_type"] != "Benign":
                self.fusion_engine.update_reputation(src_ip, fusion["confidence"])
                
                # Enrich with explainability
                explanation = self.explainability.explain_detection(features, fusion["attack_type"])
                
                await self._handle_detection(
                    {"src_ip": flow.src_ip, "dst_ip": flow.dst_ip, "protocol": flow.protocol, "dst_port": flow.dst_port},
                    {**fusion, "explanation": explanation["summary"], "explain_details": explanation},
                    source="hybrid_ai"
                )
                
            logger.debug(f"Inference latency: {latency:.2f}ms for {src_ip}")
            
        except Exception as e:
            logger.error(f"Inference pipeline error: {e}")

    async def _handle_detection(self, meta: dict, result: dict, source: str):
        """Unified alert handling and automated response."""
        self.stats["detections"] += 1
        
        detection_data = {
            "source_ip": meta.get("src_ip"),
            "dst_ip": meta.get("dst_ip"),
            "attack_type": result["attack_type"],
            "confidence": result["confidence"],
            "protocol": meta.get("protocol"),
            "dst_port": meta.get("dst_port"),
            "severity": result.get("severity", "medium"),
            "explanation": result.get("explanation"),
            "source": source,
            "timestamp": time.time()
        }

        # Response actions
        await self.response_manager.handle_detection(detection_data)
        await alert_bus.publish(TOPIC_IDPS_DETECTION, detection_data)
        
        # Broadcast to dashboard
        await ws_manager.broadcast({
            "event_type": "new_incident",
            "pipeline_badge": "IDPS",
            "incident": detection_data
        })


    async def _cleanup_loop(self):
        """Periodically remove stale flows to manage memory."""
        while self._running:
            await asyncio.sleep(60)
            now = time.time()
            with self._flow_lock:
                stale_keys = [k for k, f in self.flows.items() if now - f.last_time > 120]
                for k in stale_keys:
                    del self.flows[k]
                self.stats["flows_active"] = len(self.flows)
            logger.debug(f"IDPS cleanup: removed {len(stale_keys)} stale flows.")
