# ShieldNet — AI-Powered Intrusion Detection & Prevention System

> Research-grade cybersecurity platform combining deterministic rules, XGBoost behavioral analysis, and BiLSTM temporal detection into a unified real-time IDPS.

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Table of Contents

- [What is ShieldNet?](#what-is-shieldnet)
- [Key Features](#key-features)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [How to Run the Project](#how-to-run-the-project)
- [ML Training Pipeline](#ml-training-pipeline)
- [Detection Architecture](#detection-architecture)
- [API Documentation](#api-documentation)
- [Demo Guide](#demo-guide)
- [Troubleshooting](#troubleshooting)
- [Tech Stack](#tech-stack)
- [Contributing](#contributing)
- [License](#license)

---

## What is ShieldNet?

ShieldNet is a full-stack AI cybersecurity platform built for detecting, classifying, and responding to network intrusions in real time. It ingests live or simulated network traffic, runs it through a three-stage detection funnel (rules → ML → sequence model), and streams results to a live dashboard via WebSocket.

The ML backbone is an **XGBoost classifier trained on CICIDS2017** — 2.8M+ samples across 6 attack classes — tuned with Optuna and calibrated with Isotonic Regression for production-grade probability outputs.

---

## Key Features

- **Three-Stage Detection Funnel**: Rule Engine → XGBoost Behavioral Analysis → BiLSTM Temporal Detection
- **Real-Time Monitoring**: Live dashboard with WebSocket streaming of detection events
- **Automated Response**: IP blocking, quarantine, and watchlist management
- **Multi-Pipeline Architecture**: Network IDPS, Steganography Detection, and Honeypot services
- **Explainability**: SHAP-based attack justification and feature importance
- **MITRE ATT&CK Mapping**: Attack techniques mapped to MITRE framework
- **Attack Simulation**: Built-in attack simulator for testing and demos
- **Cross-Dataset Support**: Trained on CICIDS2017, with support for IDS2018 and UNSW-NB15

---

## Project Structure

```
main_el/
├── backend/                        # FastAPI backend
│   ├── api/                        # REST routes + WebSocket
│   ├── core/                       # Config, logging, exceptions, queue
│   ├── db/                         # SQLAlchemy models, repositories, migrations
│   ├── services/
│   │   ├── idps/                   # Core IDPS pipeline
│   │   │   ├── capture/            # Traffic ingestion (flow_generator, traffic_stream)
│   │   │   ├── detection/          # Rule engine + attack classifier
│   │   │   ├── explainability/     # SHAP-based justifications
│   │   │   ├── features/           # Flow feature extraction (42+ features)
│   │   │   ├── models/
│   │   │   │   ├── classical_ml/   # XGBoost detector
│   │   │   │   ├── sequence_models/# BiLSTM + Attention detector
│   │   │   │   └── inference/      # Base model interface
│   │   │   ├── response/           # Automated blocking and honeypot redirection
│   │   │   └── training/           # ML training pipeline (see below)
│   │   ├── correlation/            # Cross-pipeline event linking
│   │   ├── honeypot/               # Decoy service interaction logging
│   │   └── steganalysis/           # Hidden data detection in images/video
│   ├── schemas/                    # Pydantic request/response models
│   └── utils/testing/              # attack.py, attack_proxy.py, simulate.py
├── data/datasets/cicids2017/       # Raw CICIDS2017 CSV files (8 files)
├── models/idps_model.pkl           # Trained XGBoost artifact
├── dashboard.html                  # Live monitoring dashboard
├── attack.py                       # Attack simulation launcher
└── requirements.txt
```

---

## ML Training Pipeline

Located at `backend/services/idps/training/`.

| File | Purpose |
|---|---|
| `train_xgboost.py` | Full pipeline: load → balance → tune → calibrate → save |
| `dataset_manager.py` | Loads + unifies CICIDS2017/IDS2018/UNSW-NB15, preprocesses features |
| `benchmark.py` | Evaluates saved model on held-out data |
| `feature_optimization.py` | Feature selection and schema analysis |
| `fetch_datasets.py` | Dataset download helpers |
| `train_sequence.py` | BiLSTM training pipeline |
| `validate_deployment.py` | Post-deployment sanity checks |

### Current Model Performance (Training Report)

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| Benign | 1.00 | 0.98 | 0.99 | 454,580 |
| Bot | 0.60 | 0.62 | 0.61 | 393 |
| DoS | 1.00 | 1.00 | 1.00 | 25,605 |
| Infiltration | 1.00 | 0.86 | 0.92 | 7 |
| Other | 0.85 | 0.98 | 0.91 | 53,738 |
| PortScan | 0.99 | 1.00 | 1.00 | 31,786 |
| **Overall** | **—** | **—** | **0.98** | **566,109** |

### Best Optuna Trial (Trial 6)
```
n_estimators:    290
max_depth:       7
learning_rate:   0.0234
subsample:       0.8197
colsample_bytree:0.7142
macro F1:        0.9028
```

### Known Issues (In Progress)
- **Benchmark accuracy is 0.44** — scaler/LabelEncoder mismatch between training and benchmark runs
- **benchmark.py crashes** — `classification_report` class count mismatch (4 vs 3)
- **Schema Gap** — `payload_entropy` and `dst_port_type` missing every run
- **Bot class weak** — F1=0.61 due to only 393 training samples

---

## Prerequisites

- **Python 3.9 or higher**
- **pip** (Python package manager)
- **Git** (for version control)
- **4GB+ RAM** (for ML model training)
- **10GB+ disk space** (for datasets and models)

---

## Installation

### 1. Clone the Repository

```bash
git clone <your-repository-url>
cd main_el
```

### 2. Create Virtual Environment (Recommended)

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

This will install:
- FastAPI and Uvicorn (web framework)
- Scapy (packet capture)
- SQLAlchemy (database ORM)
- XGBoost, scikit-learn, Optuna (ML pipeline)
- PyTorch (sequence models)
- SHAP (explainability)
- And other required packages

### 4. Initialize Database

```bash
python -m backend.db.init_db
```

This creates the SQLite database at `data/shieldnet.db` with all required tables.

### 5. Train the ML Model (Optional - Pre-trained Model Included)

If you want to train your own model:

```bash
python -m backend.services.idps.training.train_xgboost
```

**Note**: This takes 10-15 minutes and requires the CICIDS2017 dataset in `data/datasets/cicids2017/`.

A pre-trained model is already included at `models/idps_model.pkl`.

---

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Initialize database
```bash
python -m backend.db.init_db
```

### 3. Train the model (optional - pre-trained model included)
```bash
python -m backend.services.idps.training.train_xgboost
```

### 4. Run the backend
```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

### 5. Run the live demo
```bash
# Terminal 1 — Backend
python -m uvicorn backend.main:app --port 8000 --reload

# Terminal 2 — Attack proxy
python -m backend.utils.testing.attack_proxy

# Terminal 3 — Dashboard server
python -m http.server 8080
# Open: http://127.0.0.1:8080/dashboard.html

# Terminal 4 — Attack simulation
python attack.py --target 127.0.0.1 --ddos
```

---

## How to Run the Project

ShieldNet requires running multiple components simultaneously. Follow these steps for a complete setup:

### Step 1: Start the Backend API Server

Open **Terminal 1** and run:

```bash
cd c:\Users\REVANTH VISHNU REDDY\Desktop\main_el
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

Wait for the message: `Application startup complete`

**What this does**: Starts the FastAPI backend server that handles all API requests, WebSocket connections, and ML inference.

### Step 2: Start the Attack Detection Proxy

Open **Terminal 2** and run:

```bash
cd c:\Users\REVANTH VISHNU REDDY\Desktop\main_el
python -m backend.utils.testing.attack_proxy
```

**What this does**: Starts a proxy server on port 9002 that captures simulated attack traffic and feeds it into the IDPS pipeline.

### Step 3: Start the Dashboard Web Server

Open **Terminal 3** and run:

```bash
cd c:\Users\REVANTH VISHNU REDDY\Desktop\main_el
python -m http.server 8080
```

Then open your browser and navigate to: **http://127.0.0.1:8080/dashboard.html**

**What this does**: Serves the static HTML dashboard that connects to the backend via WebSocket for real-time monitoring.

### Step 4: Launch Attack Simulation

Open **Terminal 4** and run:

```bash
cd c:\Users\REVANTH VISHNU REDDY\Desktop\main_el

# Standard multi-stage attack
python attack.py --target 127.0.0.1 --threads 12

# High-rate DDoS flood simulation
python attack.py --target 127.0.0.1 --ddos
```

**What this does**: Simulates various attack patterns (port scans, brute force, SQL injection, DDoS) against the proxy to test the detection system.

### Alternative: Run Backend Only (No Attack Simulation)

If you just want to explore the API and dashboard without attack simulation:

```bash
# Terminal 1
python -m uvicorn backend.main:app --port 8000 --reload

# Terminal 2
python -m http.server 8080
# Open: http://127.0.0.1:8080/dashboard.html
```

### Verify Installation

Check that the backend is running:

```bash
curl http://127.0.0.1:8000/api/health
```

Expected response:
```json
{
  "status": "ok",
  "service": "ShieldNet",
  "version": "2.0.0",
  "timestamp": "2024-01-01T00:00:00.000000"
}
```

---

## Detection Architecture

```
Traffic In
    │
    ▼
┌─────────────────────────┐
│  Stage 1: Rule Engine   │  ← SQLi regex, SYN flood, PPS threshold, port sweep
│  (Deterministic)        │    → Instant block if confidence > 0.85
└────────────┬────────────┘
             │ (no rule match)
             ▼
┌─────────────────────────┐
│  Stage 2: XGBoost       │  ← 42+ flow features, Isotonic calibration
│  (Behavioral ML)        │    → Probability score per class
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  Stage 3: BiLSTM        │  ← Flow sequence history per IP
│  (Temporal Patterns)    │    → Detects scan → exploit → exfiltration chains
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  Fusion Engine          │  ← Consensus weighting, watchlist logic
│  + Automated Response   │    → Block / Quarantine / Watchlist / Log
└─────────────────────────┘
```

---

## API Documentation

Once the backend is running, access the interactive API documentation at:

**Swagger UI**: http://127.0.0.1:8000/docs
**ReDoc**: http://127.0.0.1:8000/redoc

### Main API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/health` | GET | Health check endpoint |
| `/api/idps/detections` | GET | Get all IDPS detection events |
| `/api/idps/alerts` | GET | Get alert statistics |
| `/api/idps/model-status` | GET | Get ML model status and metrics |
| `/api/honeypot/logs` | GET | Get honeypot interaction logs |
| `/api/steg/scans` | GET | Get steganography scan results |
| `/api/dashboard/stats` | GET | Get aggregated dashboard statistics |
| `/ws/live` | WebSocket | Real-time event stream |

### WebSocket Connection

Connect to the live event stream:

```javascript
const ws = new WebSocket('ws://127.0.0.1:8000/ws/live');
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Detection event:', data);
};
```

---

## Demo Guide

For a complete live demonstration, follow these steps:

### Prerequisites
- Open 4 separate terminal windows
- All terminals should navigate to: `c:\Users\REVANTH VISHNU REDDY\Desktop\main_el`

### Step-by-Step Demo

**Terminal 1 - Backend API:**
```powershell
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
Wait for: `Application startup complete`

**Terminal 2 - Attack Proxy:**
```powershell
python -m backend.utils.testing.attack_proxy
```

**Terminal 3 - Dashboard Server:**
```powershell
python -m http.server 8080
```
Open browser to: **http://127.0.0.1:8080/dashboard.html**

**Terminal 4 - Attack Simulation:**
```powershell
# Standard multi-stage attack
python attack.py --target 127.0.0.1 --threads 12

# High-rate DDoS flood simulation
python attack.py --target 127.0.0.1 --ddos
```

### What to Observe

1. **Dashboard Overview Tab**: Watch events stream in real-time
2. **Network IDPS Tab**: See hybrid AI scores from rule-based and ML-based detections
3. **Honeypot Tab**: View harvested credentials and MITRE ATT&CK mappings
4. **Control Tab**: Monitor pipeline health and attack triggers

---

## Troubleshooting

### Common Issues

**Issue**: Port 8000 already in use
```bash
# Solution: Kill the process or use a different port
python -m uvicorn backend.main:app --port 8001
```

**Issue**: Module not found errors
```bash
# Solution: Ensure you're in the project root and dependencies are installed
cd c:\Users\REVANTH VISHNU REDDY\Desktop\main_el
pip install -r requirements.txt
```

**Issue**: Database initialization fails
```bash
# Solution: Delete existing database and reinitialize
del data\shieldnet.db
python -m backend.db.init_db
```

**Issue**: Model not found
```bash
# Solution: Ensure the model file exists or train a new one
# Check: models/idps_model.pkl
# If missing: python -m backend.services.idps.training.train_xgboost
```

**Issue**: WebSocket connection fails
```bash
# Solution: Ensure backend is running and CORS is enabled
# Check backend is accessible: curl http://127.0.0.1:8000/api/health
```

### Getting Help

- Check the logs in the `logs/` directory
- Review the documentation in `backend/ARCHITECTURE.md`
- Consult the training guide in `training_README.md`
- Check the demo guide in `demo_guide.md`

---

## Docs Index

| File | Description |
|---|---|
| `backend/README.md` | Backend setup and API overview |
| `backend/ARCHITECTURE.md` | Component design and data flow |
| `backend/services/idps/training/README.md` | ML training pipeline deep-dive |
| `training_README.md` | ML training pipeline documentation |
| `demo_guide.md` | Step-by-step live demo instructions |
| `status_report.md` | Project status and future roadmap |
| `values.md` | All rule thresholds, AI parameters, MITRE mappings |
| `working.md` | Detection logic and tiered funnel explanation |

---

## Tech Stack

| Layer | Technology |
|---|---|
| API | FastAPI + Uvicorn |
| ML | XGBoost, scikit-learn, Optuna |
| Sequence Model | PyTorch BiLSTM |
| Explainability | SHAP |
| Data | CICIDS2017, IDS2018, UNSW-NB15 |
| Database | SQLite / PostgreSQL (SQLAlchemy) |
| Real-time | WebSocket (FastAPI) |
| Balancing | SMOTE (imbalanced-learn) |
| Calibration | Isotonic Regression |

---

## Contributing

Contributions are welcome! Please follow these guidelines:

### Development Setup

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes
4. Run tests: `python -m pytest`
5. Commit your changes: `git commit -m 'Add some feature'`
6. Push to the branch: `git push origin feature/your-feature-name`
7. Open a Pull Request

### Code Style

- Follow PEP 8 guidelines
- Use type hints where appropriate
- Add docstrings to functions and classes
- Keep functions focused and modular

### Testing

```bash
# Run all tests
python -m pytest

# Run specific test file
python -m pytest tests/test_idps.py

# Run with coverage
python -m pytest --cov=backend
```

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## Acknowledgments

- **CICIDS2017 Dataset**: Canadian Institute for Cybersecurity
- **XGBoost**: Distributed Gradient Boosting Library
- **FastAPI**: Modern, fast web framework for building APIs
- **MITRE ATT&CK**: Adversarial Tactics, Techniques, and Common Knowledge

---

## Contact

For questions, issues, or contributions, please open an issue on GitHub or contact the maintainers.

---

## Project Status

This is a research-grade cybersecurity platform. While it demonstrates advanced detection capabilities, it should be used for educational and research purposes only. For production deployments, additional security hardening and testing are recommended.

See `status_report.md` for current development status and roadmap.
