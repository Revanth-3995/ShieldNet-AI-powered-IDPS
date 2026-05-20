# ShieldNet IDPS — Full AI & Rule Parameter Set

This document provides the definitive reference for the thresholds, rules, and AI parameters used in the ShieldNet detection funnel.

---

## 1. Deterministic Rule Signatures (Heuristic Layer)

These rules trigger **instant detection** based on deterministic patterns and specific thresholds.

| Rule / Attack Type | Trigger Condition | Confidence | MITRE TTP |
| :--- | :--- | :--- | :--- |
| **Port Scan (Vertical)** | > 30 unique ports in 60s | 0.95 | T1046 (Discovery) |
| **SYN Flood** | > 200 SYN pkts without ACK | 0.90 | T1498 (DDoS) |
| **Brute Force** | > 15 attempts to Auth ports | 0.92 | T1110 (Brute Force) |
| **SQL Injection** | Match: `UNION`, `OR '1'='1'`, `--` | 0.88 | T1190 (Web Exploit) |
| **DDoS (PPS)** | > 1,500 Packets Per Second | 0.98 | T1499 (Endpoint DoS) |
| **Oversized Pkt** | Payload > 1500 bytes | 0.60 | T1005 (Data Probe) |
| **Tiny Pkt** | Packet Header < 20 bytes | 0.55 | T1001 (Obfuscation) |

---

## 2. Behavioral AI Metrics (XGBoost Engine)

Used for detecting anomalies that don't match fixed rules.

| Parameter | Normal Range | Malicious Flag | Reasoning |
| :--- | :--- | :--- | :--- |
| **Flow Duration** | 0.5s - 60s | > 30 min | Persistent C2 Tunnels |
| **Flow Bytes/s** | 100 - 50k | > 5 MB/s | Massive Exfiltration |
| **Payload Entropy** | 2.0 - 5.0 | > 7.8 | Encrypted Malware |
| **Fwd/Bwd Ratio** | ~ 1.0 | > 10.0 | Data Leakage Skew |

---

## 3. Temporal Sequence Analysis (BiLSTM + Attention)

Detects the **progression** of an attack over time.

| Metric | Trigger Condition | Reasoning |
| :--- | :--- | :--- |
| **IAT Mean** | > 10.0s | Detecting "Low & Slow" heartbeats. |
| **IAT StdDev** | < 0.001s | High-precision bot behavior. |
| **Burstiness** | > 20.0 | Sudden multi-stage exploit delivery. |

---

## 4. Response Severity Thresholds

| Confidence | Severity | Action | SOC Protocol |
| :--- | :--- | :--- | :--- |
| **0.85 - 1.0** | **CRITICAL** | **Auto-Block** | Immediate IR Ticket |
| **0.70 - 0.84** | **HIGH** | **Quarantine** | Priority Analyst Review |
| **0.40 - 0.69** | **MEDIUM** | **Watchlist** | Mirror to Honeypot |
| **< 0.10** | **BENIGN** | **Log Only** | Standard Baseline |
