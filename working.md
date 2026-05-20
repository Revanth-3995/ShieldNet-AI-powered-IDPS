# ShieldNet IDPS — Working Principles & Logic Flow

ShieldNet uses a **Defense-in-Depth** architecture that combines deterministic rules, statistical behavior analysis, and temporal pattern recognition.

---

## 1. Data Ingestion & Normalization
Traffic is ingested via the **Traffic Stream** (Scapy/Proxy). Each packet is processed in 3 steps:
1.  **Fast Path (Heuristics)**: The `RuleEngine` checks for instant red flags (SQLi regex, PPS flooding, Port sweeps).
2.  **Flow Generation**: Packets are aggregated into **Bidirectional Flows** using a 5-tuple key (Src IP, Dst IP, Src Port, Dst Port, Protocol).
3.  **Feature Extraction**: Once a flow reaches a trigger point (e.g., 5 packets), 42+ features are extracted, including Entropy, IAT moments, and log-scaled volume.

---

## 2. The Tiered Detection Funnel

### Stage 1: The Heuristic Layer (RuleEngine)
*   **Purpose**: Catching known threats with zero latency.
*   **Logic**: Uses stateful counters (e.g., tracking the number of unique ports hit by an IP) and signature matching (SQLi strings).
*   **Response**: If a high-confidence rule hits, it bypasses the AI and triggers an immediate block.

### Stage 2: The Behavioral Engine (XGBoost)
*   **Purpose**: Detecting "Unknown" or "Zero-Day" anomalies.
*   **Logic**: A gradient-boosted tree model analyzes the *statistical profile* of the flow. It looks for deviations from "Benign" traffic distributions (e.g., abnormally high entropy or directional skew).
*   **Calibration**: Uses **Isotonic Regression** to convert raw model scores into accurate real-world probabilities.

### Stage 3: The Temporal Engine (BiLSTM + Attention)
*   **Purpose**: Detecting multi-stage campaign patterns.
*   **Logic**: A sequence-based model looks at the *history* of flows from a specific IP. It recognizes the transition from **Discovery → Brute Force → Exfiltration**.
*   **Attention Mechanism**: Focuses on the most significant "pivot points" in the attack timeline.

---

## 3. Consensus & Fusion
The **Fusion Engine** acts as the final judge. It weighs the outputs:
- **Consensus High**: If both XGBoost and BiLSTM agree an attack is happening, the confidence is boosted to `CRITICAL`.
- **Doubt Handling**: If only one model flags the traffic, the system applies a "Contextual Penalty" and places the IP on a **Watchlist** rather than blocking it immediately.

---

## 4. Automated Response (The Blocker)
When a detection is confirmed:
1.  **Blocker.py** interacts with the system firewall or proxy to drop packets from the malicious IP.
2.  **Honeypot Redirection**: Medium-risk traffic is mirrored to a high-interaction honeypot to gather forensics.
3.  **Explainability**: The system generates a SHAP-based justification (e.g., *"Flagged due to high outgoing byte entropy and PPS violation"*) for the SOC analyst.
