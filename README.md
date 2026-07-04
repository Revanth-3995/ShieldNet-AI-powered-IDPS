# ShieldNet — AI-Powered Intrusion Detection & Prevention System

> A research-grade, enterprise-scale hybrid cybersecurity platform combining low-latency deterministic rules, XGBoost behavioral analysis, and BiLSTM temporal sequence detection into a unified real-time IDPS, coupled with automated steganographic covert channel interception, dual-engine steganalysis, and automated response orchestration.

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Table of Contents

1. [What is ShieldNet?](#what-is-shieldnet)
2. [Platform Architecture & Data Flows](#platform-architecture--data-flows)
3. [Pipeline A: Network IDPS Technical Specifications](#pipeline-a-network-idps-technical-specifications)
   - [Traffic Ingestion & Flow Generation](#traffic-ingestion--flow-generation)
   - [Heuristic Engine (7 Stateful Rules)](#heuristic-engine-7-stateful-rules)
   - [Feature Extractor (42+ Metrics)](#feature-extractor-42-metrics)
   - [Behavioral ML Engine (Optuna-Tuned XGBoost)](#behavioral-ml-engine-optuna-tuned-xgboost)
   - [Temporal Sequence Engine (BiLSTM + Attention)](#temporal-sequence-engine-bilstm--attention)
   - [Consensus Fusion & Adaptive Reputation](#consensus-fusion--adaptive-reputation)
   - [Explainability Engine (SHAP Explanations)](#explainability-engine-shap-explanations)
4. [Pipeline B: Steganography Interception & Steganalysis](#pipeline-b-steganography-interception--steganalysis)
   - [mitmproxy Interception Hook](#mitmproxy-interception-hook)
   - [7 Statistical Stegananalysis Algorithms](#7-statistical-stegananalysis-algorithms)
   - [EfficientNet-B0 CNN Inference](#efficientnet-b0-cnn-inference)
   - [Action & Quarantine Manager](#action--quarantine-manager)
   - [Forensic Report Schema](#forensic-report-schema)
5. [System Integrations](#system-integrations)
   - [FastAPI Backend & Async Lifespan Queue](#fastapi-backend--async-lifespan-queue)
   - [Correlation Engine](#correlation-engine)
   - [Honeypots & Active Decoy Deception](#honeypots--active-decoy-deception)
6. [Attacker Simulation & Validation Tools](#attacker-simulation--testing-tools)
   - [Attacker LSB Steganography Tool](#attacker-lsb-steganography-tool)
   - [Automated Verification Suite](#automated-verification-suite)
   - [Network Attack Simulator](#network-attack-simulator)
7. [Project Directory Structure](#project-directory-structure)
8. [Configuration & Environment](#configuration--environment)
9. [Installation & Setup](#installation--setup)
10. [Execution & Deployment Workflows](#execution--deployment-workflows)
11. [Testing & Verification](#testing--verification)

---

## 1. What is ShieldNet?

ShieldNet is a modern, defense-in-depth security appliance built to monitor network traffic and application layers. It uses a tiered funnel design to catch threats ranging from traditional brute force attacks to highly sophisticated, silent covert channels hiding data inside media files. 

By separating the inspection layers, ShieldNet matches known attack patterns in under a millisecond while offloading heavy machine learning classification and sequence correlation to non-blocking background workers.

---

## 2. Platform Architecture & Data Flows

```
                                      [ Attacker / Client ]
                                                │
                     ┌──────────────────────────┴──────────────────────────┐
                     │ (TCP/UDP Packets)                                   │ (HTTP/HTTPS Uploads)
                     ▼                                                     ▼
       ┌───────────────────────────┐                         ┌───────────────────────────┐
       │ Pipeline A: Network IDPS  │                         │ Pipeline B: Steganalysis  │
       │  - Packet Sniffer (Scapy) │                         │  - mitmproxy Interceptor  │
       └─────────────┬─────────────┘                         └─────────────┬─────────────┘
                     │                                                     │
        (Stage 1 Rule Checking)                                   (Dual-Engine Fusion)
                     │                                                     │
             [ Rule Match? ] ──Yes──┐                                      │
                     │ No           │                                      │
                     ▼              │                                      │
       ┌───────────────────────────┐│                                      │
       │    Flow Feature Extractor ││                                      │
       └─────────────┬─────────────┘│                                      │
                     ▼              │                                      │
       ┌───────────────────────────┐│                                      │
       │ XGBoost & BiLSTM Engines  ││                                      │
       └─────────────┬─────────────┘│                                      │
                     ▼              │                                      │
       ┌───────────────────────────┐│                                      │
       │      Fusion Engine        │◄┘                                     │
       └─────────────┬─────────────┘                                       │
                     │                                                     │
            (Incident Alert)                                        (Incident Alert)
                     │                                                     │
                     ▼                                                     ▼
       ┌─────────────────────────────────────────────────────────────────────────┐
       │                          FastAPI Backend Router                         │
       └────────────────────────────────────┬────────────────────────────────────┘
                     ┌──────────────────────┴──────────────────────┐
                     ▼                                             ▼
       ┌───────────────────────────┐                         ┌───────────────────────────┐
       │    Correlation Engine     │                         │    Alert Bus (Pub/Sub)    │
       └─────────────┬─────────────┘                         └─────────────┬─────────────┘
                     ▼                                                     ├───────────────────────────┐
       ┌───────────────────────────┐                                       ▼                           ▼
       │     SQLite Database       │                         ┌───────────────────────────┐┌───────────────────────────┐
       │  (detections/steg_scans)  │                         │    WebSocket Broadcast    ││     Response Manager      │
       └───────────────────────────┘                         └─────────────┬─────────────┘│ (Active IP Blocks/Quar)   │
                                                                           ▼              └───────────────────────────┘
                                                             ┌───────────────────────────┐
                                                             │ Real-Time Dashboard UI    │
                                                             └───────────────────────────┘
```

---

## 3. Pipeline A: Network IDPS Technical Specifications

### Traffic Ingestion & Flow Generation
*   **Ingestion Engine**: Employs Scapy's high-performance `sniff()` loop with native Berkeley Packet Filter (BPF) expressions (`"ip"`) to filter out layer-2 frames and optimize kernel-to-user-space ring buffer copying.
*   **Bidirectional Flow Generation**: Network packets are grouped dynamically using an IP-address-agnostic 5-tuple key: `(Min(SrcIP, DstIP), Max(SrcIP, DstIP), Min(SrcPort, DstPort), Max(SrcPort, DstPort), Protocol)`.
*   **Handshake & Ingestion Triggers**: The IDPS maintains active TCP state machines. Machine learning analysis is triggered on the **5th packet** (to capture TCP handshakes) and every **20 packets** thereafter to ensure persistent flow checking.

### Heuristic Engine (7 Stateful Rules)
The deterministic rule engine evaluates incoming packet metadata inside `RuleEngine.check_packet()` using sliding queues (`collections.deque` with configured time-to-live expirations) to maintain state.

| Rule Name | Attack Type | Trigger Metric / Formula | Confidence | MITRE ATT&CK Mapping |
| :--- | :--- | :--- | :--- | :--- |
| **Vertical Port Sweep** | PortScan | $U_{ports} > 30$ in $\Delta t \le 60\text{s}$ | 0.95 | T1046 (Discovery) |
| **SYN Flood** | DoS | $\frac{N_{SYN}}{N_{ACK}} > 200$ for a single destination | 0.90 | T1498 (DDoS) |
| **Excessive Auth Attempts** | BruteForce | $C_{attempts} > 15$ to ports $\{22, 23, 21, 3389\}$ in $\Delta t \le 120\text{s}$ | 0.92 | T1110 (Brute Force) |
| **Extreme Packet Rate (PPS)**| DDoS | $\text{PPS} = \frac{N_{packets}}{\text{duration}} > 1500$ | 0.98 | T1499 (Endpoint DoS) |
| **SQL Injection** | WebAttack | Regex signature match: `(?i)(union|select|insert|drop|alert|or\s+1=1|--|\/\*)` | 0.88 | T1190 (Web Exploit) |
| **Oversized Packet** | AnomPkt | Packet Size $> 1500$ bytes | 0.60 | T1005 (Data Probe) |
| **Abnormally Small Header** | AnomPkt | Packet Size $< 20$ bytes (and $> 0$) | 0.55 | T1001 (Obfuscation) |

### Feature Extractor (42+ Metrics)
When a flow triggers evaluation, the `FeatureExtractor` extracts exactly 42 features. Key mathematical features include:
*   **Flow Duration**: $T_{end} - T_{start}$
*   **Byte Rate**: $\text{Bytes/s} = \frac{\text{Total Bytes}}{\text{Duration}}$
*   **Packet Inter-Arrival Times (IAT)**: Evaluates Mean, Standard Deviation, Max, and Min of:
    $$\Delta t_i = t_i - t_{i-1}$$
*   **Payload Entropy**: Computes the Shannon entropy of packet payloads to identify encrypted payloads or obfuscated shellcodes:
    $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
*   **Forward/Backward Ratio**: Ratio of outgoing traffic volume to incoming responses to detect exfiltration attempts.

### Behavioral ML Engine (Optuna-Tuned XGBoost)
*   **Model Structure**: A gradient-boosted decision tree (XGBoost) classifier trained on the unified CICIDS2017 dataset.
*   **Balancing & Prep**: Raw training files are preprocessed using `SMOTE` (Synthetic Minority Over-sampling Technique) to balance extreme minority classes (such as Infiltration).
*   **Optuna Hyperparameters**:
    *   `n_estimators`: 290
    *   `max_depth`: 7
    *   `learning_rate`: 0.0234
    *   `subsample`: 0.8197
    *   `colsample_bytree`: 0.7142
*   **Probability Calibration**: Uses **Isotonic Regression** to calibrate classification scores. This ensures the output confidence maps directly to true incident probabilities rather than raw tree decision boundary scores.

### Temporal Sequence Engine (BiLSTM + Attention)
*   **Purpose**: Correlates sequential flows over time to spot progressive attack phases (e.g., discovery scanning → vulnerability exploit → command-and-control connection).
*   **Network Architecture**:
    *   *Input Layer*: Accepts a sequence of flow feature vectors (window size of 20 historical flows per source IP).
    *   *Recurrent Layer*: Bidirectional LSTM (Long Short-Term Memory) layer with 64 hidden units, processing temporal transitions forward and backward.
    *   *Attention Layer*: Computes scalar alignment scores over the sequence states, highlighting the specific packets or flows that show the transition from benign to malicious.
    *   *Linear Classifier*: Outputs predictions across sequence-based attack classes.

### Consensus Fusion & Adaptive Reputation
The `FusionEngine` resolves conflicting outputs from the detection stages using a weighted fusion matrix:
*   If a Stage 1 rule triggers, it bypasses ML pipelines and issues an immediate detection alert.
*   For ML results, the engine combines the XGBoost score ($S_{xgb}$) and the BiLSTM score ($S_{lstm}$):
    $$\text{Confidence} = w_1 \cdot S_{xgb} + w_2 \cdot S_{lstm}$$
*   **Reputation Penalty**: The engine keeps track of source IP reputations. Each high-confidence warning reduces the IP's reputation score. When the score falls below a set threshold, the engine boosts future low-confidence alerts from that IP to trigger faster blocks.

### Explainability Engine (SHAP Explanations)
*   **TreeExplainer Integration**: For tabular traffic alerts, ShieldNet uses SHAP (SHapley Additive exPlanations) values to calculate exactly how much each feature contributed to the model's classification.
*   **JSON Explanations**: The engine generates a clean JSON object outlining the top 3 features responsible for the alert (e.g., high outbound entropy, destination port mismatch, or anomalous packet size distributions). This gives security analysts immediate context on *why* the AI flagged the event.

---

## 4. Pipeline B: Steganography Interception & Steganalysis

### mitmproxy Interception Hook
`mitmproxy_addon.py` hooks into active HTTP and HTTPS request cycles. 
*   It intercepts incoming `POST` and `PUT` request streams.
*   It extracts files from `multipart/form-data` payloads or parses raw octet-streams to check for common image mime-types (`image/png`, `image/jpeg`, `image/bmp`).
*   It writes the files to `pipeline_b/uploads/` temporarily, processes them, and returns an HTTP 403 Forbidden to the sender if steganography is detected.

### 7 Statistical Stegananalysis Algorithms

ShieldNet uses a dual-engine architecture. The statistical engine runs 7 algorithms in parallel on the image array:

#### 1. Chi-Square Test
Evaluates the statistical deviance of color frequencies by checking pairs of values (PoVs) in the least significant bits. In clean images, adjacent values have natural distribution differences. Steganographic embedding flattens this distribution.
$$\chi^2 = \sum_{i=1}^{k} \frac{(O_i - E_i)^2}{E_i}$$
*Where $O_i$ represents the observed LSB values and $E_i$ represents the expected natural distribution.*

#### 2. RS (Regular-Singular) Analysis
Classifies pixel groups into Regular ($R$), Singular ($S$), or Unusable ($U$) categories using a flipping mask $M$ and its negation $-M$. By measuring how these groups respond to LSB changes, the algorithm estimates the exact percentage of modified pixels.
$$\text{Estimated Payload } (p) \approx \frac{R_M - R_{-M}}{S_M - S_{-M}}$$

#### 3. Sample Pair Analysis
Analyzes statistics of adjacent pixel pairs, counting how LSB modifications distort these relationships. It calculates the difference between even and odd pixel transitions to detect hidden payloads.

#### 4. DCT Coefficient Analysis
Inspects Discrete Cosine Transform coefficients (specifically for JPEGs and compressed media formats). Steganographic embedding alters the expected histogram distribution of these coefficients, creating distinct spikes.

#### 5. Pixel Histogram Analysis
Checks the image's color histograms. LSB steganography introduces a "smoothing" or "flattening" effect across adjacent color values (e.g., values 128 and 129 become abnormally equal in count).

#### 6. Noise Residual Analysis
ShieldNet runs a high-pass denoising filter over the image to extract its high-frequency noise profile. Natural image noise is smooth and consistent, whereas steganographic payloads introduce artificial, high-frequency noise spikes.

#### 7. Benford's Law
Natural image gradients and DCT coefficients follow a logarithmic first-digit distribution (Benford's Law). Steganographic encoding disrupts this pattern, causing the distribution to deviate from the standard logarithmic curve:
$$P(d) = \log_{10}\left(1 + \frac{1}{d}\right)$$

### EfficientNet-B0 CNN Inference
For high-accuracy verification, the system runs the image through a PyTorch implementation of **EfficientNet-B0**:
*   The model accepts inputs sized `(3, 256, 256)` and is trained on LSB-embedded cover/stego datasets.
*   Its deep feature extraction layers identify subtle spatial changes that statistical rules might miss.
*   **Late Fusion**: The final detection score combines the CNN prediction probability with the average score from the 7 statistical algorithms.

### Action & Quarantine Manager
`quarantine_manager.py` manages files flagged by the steganalysis engine.

| Confidence Range | Severity | Action | System Response |
| :--- | :--- | :--- | :--- |
| `0.00 - 0.40` | `clean` | `allow` | Let request pass through. |
| `0.40 - 0.70` | `suspicious` | `review` | Send alert to backend; log for review. |
| `0.70 - 0.85` | `likely` | `block` | Block request (HTTP 403) and send alert. |
| `0.85 - 1.00` | `critical` | `quarantine`| Block request, quarantine file, generate forensics, and alert. |

*   **Quarantine Mechanism**: Files are encrypted using AES-256 and stored in `pipeline_b/quarantine/[YYYY-MM-DD]/[filename]_[confidence].quar` to prevent accidental execution or rendering of the payload.

### Forensic Report Schema
Critical events trigger the generation of a forensic JSON report:
```json
{
  "report_id": "a1b2c3d4e5f67890",
  "filename": "exfil_data.png",
  "prediction": "steg",
  "confidence": 0.965,
  "severity": "critical",
  "file_size": 245100,
  "mime_type": "image/png",
  "source_ip": "192.168.1.52",
  "timestamp": "2026-07-04T13:45:00Z",
  "recommended_action": "IMMEDIATE ACTION: Block source IP at firewall.",
  "algorithm_detected": "chi_square",
  "payload_estimate_bytes": 1820,
  "algorithm_scores": {
    "chi_square": 0.981,
    "rs_analysis": 0.942,
    "sample_pair": 0.910,
    "benfords_law_deviation": 0.082
  },
  "method": "efficientnet_b0_fused",
  "cnn_score": 0.978,
  "stat_score": 0.944,
  "extracted_message": "CLASSIFIED_PROJECT_X_PDF_EXFIL",
  "extraction_status": "extracted_successfully"
}
```

---

## 5. System Integrations

### FastAPI Backend & Async Lifespan Queue
*   **Web Framework**: Powered by FastAPI using an asynchronous ASGI server (Uvicorn).
*   **Lifespan Events**: On startup, FastAPI initializes connection pools, loads deep learning weights into memory, and launches background tasks. On shutdown, it safely closes open database sessions, flush buffers, and terminates socket handlers.
*   **Async Event Processing**: Rather than writing directly to the database during request processing, alerts are pushed to an in-memory queue. Background workers process this queue asynchronously, keeping API response times minimal.

### Correlation Engine
The `CorrelationEngine` links network events with application-layer steganalysis results:
1. It monitors incoming events from both Pipeline A and Pipeline B.
2. When a stegalert matches a recent network scan (e.g., a port scan followed by an image upload from the same source IP within 5 minutes), it groups them into a unified incident.
3. This raises the overall incident severity to `CRITICAL` and triggers automated blocking responses.

### Honeypots & Active Decoy Deception
*   **Dynamic Honeypot Redirection**: When the system spots medium-risk IP activity, `ResponseManager` updates routing tables (using iptables rules or proxy redirects) to forward all traffic from that IP to decoy honeypots.
*   **Decoy Logs**: These honeypots mimic standard database systems (Port 3306), SSH terminals (Port 22), and web servers (Port 80). The logs record attacker commands and credentials, mapping their actions to MITRE ATT&CK techniques in the database.

---

## 6. Attacker Simulation & Testing Tools

### Attacker LSB Steganography Tool
`attacker_steg_tool.py` is a testing utility featuring both a GUI (Tkinter-based) and a CLI:
*   **Embedding Technique**: Encodes a text payload into the least significant bit (LSB) of each RGB color channel.
*   **Null-Terminator Padding**: Appends a `\x00\x00\x00` sequence to mark the end of the hidden message.
*   **CLI Usage**:
    ```bash
    python attacker_steg_tool.py --image test.png --message "Sensitive Exfil Data" --out stego_output.png
    ```

### Automated Verification Suite
`embed_and_detect.py` automates end-to-end steganography testing:
1. Generates a cover image using synthetic high-entropy noise.
2. Embeds the test payload using LSB encoding.
3. Sends the image to the `/api/steg/upload` endpoint.
4. Checks the response to verify the image was detected, blocked, and the payload correctly extracted.
```bash
python embed_and_detect.py --message "System Integration Test" --api http://127.0.0.1:8000
```

### Network Attack Simulator
`attack.py` generates realistic attack patterns to test the IDPS rules:
*   **Port Scan**: Hits multiple ports sequentially to trigger the vertical sweep rule.
*   **SYN Flood**: Sends a flood of SYN packets to trigger the DoS alert.
*   **Brute Force**: Simulates failed SSH login attempts.
*   **SQL Injection**: Sends web requests containing database exploitation payloads.
```bash
python attack.py --target 127.0.0.1 --ddos --threads 16
```

---

## 7. Project Directory Structure

```
main_el/
├── backend/                        # Central FastAPI codebase
│   ├── api/                        # REST and Websocket routers
│   │   ├── routes/                 # Specialized endpoints (steg, idps, dashboard)
│   │   └── router.py               # Root API router
│   ├── core/                       # App configuration, logging, and queues
│   ├── db/                         # SQLAlchemy models, sessions, and schemas
│   ├── sensors/                    # Active sensors (mitmproxy, Scapy, Suricata)
│   └── services/                   # Core business logic
│       ├── correlation/            # Links network IDPS and steg scan events
│       ├── honeypot/               # Simulates decoy servers and logs access
│       ├── idps/                   # Pipeline A engine
│       │   ├── capture/            # Traffic capture (flow generators)
│       │   ├── detection/          # Rules engine and ML classifier
│       │   ├── explainability/     # SHAP-based local explanations
│       │   └── training/           # ML training scripts (XGBoost, BiLSTM)
│       └── response/               # Automated firewall blocks and alert bus
├── pipeline_b/                     # Pipeline B (Steganalysis proxy)
│   ├── mitmproxy_addon.py          # mitmproxy entry point
│   ├── detector.py                 # Fusion of 7 statistical rules & CNN
│   ├── quarantine_manager.py       # Secure file isolation
│   ├── backend_client.py           # REST client to forward steg alerts
│   ├── forensics.py                # Compiles forensic JSON files
│   ├── quarantine/                 # Quarantined file repository
│   └── logs/                       # Steg audit trails and forensics reports
├── models/                         # ML Weights (idps_model.pkl, steg_cnn.pth)
├── tests/                          # Testing suite (pytest)
├── attacker_steg_tool.py           # GUI & CLI tool to create stego images
├── embed_and_detect.py             # Script to automate steg cover generation + upload
├── attack.py                       # CLI attack simulator
└── dashboard.html                  # Live real-time browser monitor
```

---

## 8. Configuration & Environment

ShieldNet uses environment variables for configuration. A template file `.env.example` is provided in the root directory. Copy `.env.example` to `.env` and configure key variables:

```ini
# Server Configuration
API_PORT=8000
API_HOST=127.0.0.1
DEBUG=true

# ML Model Paths
IDPS_MODEL_PATH=models/idps_model.pkl
BILSTM_MODEL_PATH=models/bilstm_model.pth
STEG_CNN_PATH=models/steg_cnn.pth

# Steganalysis Thresholds
STEG_SUSPICIOUS_THRESHOLD=0.40
STEG_LIKELY_THRESHOLD=0.70
STEG_CRITICAL_THRESHOLD=0.85
```

---

## 9. Installation & Setup

### 1. Clone the Repository
```bash
git clone <your-repository-url>
cd main_el
```

### 2. Configure Virtual Environment
```bash
# Create and activate environment
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### 4. Initialize Database
```bash
python -m backend.db.init_db
```

---

## 10. Execution & Deployment Workflows

For a complete demonstration, run the following components in separate terminals:

### Step 1: Start the Backend API Server
```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

### Step 2: Start the Attack Detection Proxy
```bash
python -m backend.utils.testing.attack_proxy
```

### Step 3: Run the mitmproxy Addon
```bash
mitmdump -s pipeline_b/mitmproxy_addon.py --listen-port 8080
```

### Step 4: Serve the Live Dashboard
```bash
python -m http.server 8080
```
Open **http://127.0.0.1:8080/dashboard.html** in your browser to view real-time WebSocket alerts.

---

## 11. Testing & Verification

ShieldNet includes a complete test suite powered by `pytest`.

```bash
# Run all tests
python -m pytest

# Run Pipeline B tests in verbose mode
python -m pytest tests/pipeline_b/test_pipeline_b.py -v
```
