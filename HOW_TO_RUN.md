# ShieldNet — Complete Setup & Running Guide

> **ShieldNet** is an AI-Powered Intrusion Detection & Prevention System (IDPS) with integrated steganography detection, honeypot monitoring, and a real-time security dashboard.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Quick Start (5 Minutes)](#2-quick-start-5-minutes)
3. [Detailed Installation](#3-detailed-installation)
4. [Running the Application](#4-running-the-application)
5. [Accessing the Dashboard](#5-accessing-the-dashboard)
6. [Running Attack Simulations (Demo)](#6-running-attack-simulations-demo)
7. [Steganography Detection](#7-steganography-detection)
8. [API Reference](#8-api-reference)
9. [Environment Variables](#9-environment-variables)
10. [Architecture Overview](#10-architecture-overview)
11. [Troubleshooting](#11-troubleshooting)
12. [Project Structure](#12-project-structure)

---

## 1. Prerequisites

### Required Software

| Software | Version | Purpose |
|----------|---------|---------|
| **Python** | 3.10 – 3.13 | Core runtime |
| **pip** | Latest | Package management |
| **Git** | Any | Version control |

### Recommended (Optional)

| Software | Purpose |
|----------|---------|
| **Npcap** (Windows) / **libpcap** (Linux) | Live network packet capture |
| **CUDA GPU** | Accelerated CNN training (10× faster) |

### Verify Python Version

```bash
python --version
# Expected: Python 3.10.x / 3.11.x / 3.12.x / 3.13.x
```

---

## 2. Quick Start (5 Minutes)

For the impatient — get everything running in 4 commands:

### Windows (PowerShell)

```powershell
# 1. Clone the repository
git clone https://github.com/Revanth-3995/ShieldNet-AI-powered-IDPS.git
cd ShieldNet-AI-powered-IDPS

# 2. Create virtual environment & install dependencies
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt

# 3. Start the backend API server
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload

# 4. In a NEW terminal — serve the dashboard
cd ShieldNet-AI-powered-IDPS
.\venv\Scripts\activate
python -m http.server 8080
```

Then open **http://localhost:8080/dashboard.html** in your browser.

### Linux / macOS

```bash
# 1. Clone
git clone https://github.com/Revanth-3995/ShieldNet-AI-powered-IDPS.git
cd ShieldNet-AI-powered-IDPS

# 2. Setup
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Start backend
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload

# 4. In another terminal — serve dashboard
python3 -m http.server 8080
```

---

## 3. Detailed Installation

### Step 1 — Clone the Repository

```bash
git clone https://github.com/Revanth-3995/ShieldNet-AI-powered-IDPS.git
cd ShieldNet-AI-powered-IDPS
```

### Step 2 — Create a Virtual Environment

**Windows:**
```powershell
python -m venv venv
.\venv\Scripts\activate
```

**Linux/macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

> You should see `(venv)` or `(.venv)` in your terminal prompt.

### Step 3 — Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

**What gets installed:**

| Category | Packages |
|----------|----------|
| **Web Framework** | FastAPI, Uvicorn, Pydantic, Starlette |
| **Database** | SQLAlchemy, aiosqlite |
| **ML (IDPS)** | NumPy, Pandas, scikit-learn, XGBoost, SHAP, Optuna |
| **ML (Steg CNN)** | PyTorch, TorchVision |
| **Image/Video** | Pillow, OpenCV, scikit-image, SciPy |
| **Network** | Scapy, mitmproxy |
| **Utilities** | psutil, matplotlib, seaborn |

> **Note:** PyTorch is the largest dependency (~2 GB). If you only need network IDPS features (no steg CNN), you can skip it by installing selectively.

### Step 4 — Verify Directories Are Created

The backend auto-creates these on first run, but you can pre-create them:

```bash
mkdir -p models data logs quarantine uploads temp
```

### Step 5 — (Optional) Install Npcap for Live Packet Capture

**Windows:**
1. Download Npcap from https://npcap.com/
2. Install with **"Install Npcap in WinPcap API-compatible mode"** checked
3. Restart your terminal

**Linux:**
```bash
sudo apt install libpcap-dev   # Debian/Ubuntu
sudo yum install libpcap-devel # RHEL/CentOS
```

> Without Npcap/libpcap, ShieldNet still works using simulated traffic and the attack proxy.

---

## 4. Running the Application

ShieldNet requires **two processes** running simultaneously:

### Terminal 1 — Backend API Server

```bash
# Activate your virtual environment first
# Windows: .\venv\Scripts\activate
# Linux:   source .venv/bin/activate

python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

You should see output like:
```
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
INFO:     Started reloader process
INFO:     ShieldNet v3.0.0 started.
```

**Flags explained:**
| Flag | Purpose |
|------|---------|
| `--host 127.0.0.1` | Bind to localhost only (use `0.0.0.0` for LAN access) |
| `--port 8000` | API server port |
| `--reload` | Auto-restart on code changes (dev mode) |

### Terminal 2 — Dashboard Web Server

Open a **new terminal**, activate the venv, then:

```bash
python -m http.server 8080
```

This serves the `dashboard.html` file and any static assets on port 8080.

### (Optional) Demo Mode — Pre-seed Data

To start with sample detection events already visible on the dashboard:

```bash
# Set DEMO_MODE before starting the backend
set DEMO_MODE=true                    # Windows
export DEMO_MODE=true                 # Linux/macOS

python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

---

## 5. Accessing the Dashboard

Once both servers are running, open your browser and navigate to:

```
http://localhost:8080/dashboard.html
```

### Dashboard Tabs

| Tab | Description |
|-----|-------------|
| **Overview** | Live threat statistics, severity breakdown, recent alerts |
| **Network IDPS** | Real-time network detection events, attack classification |
| **Image Steg** | Upload images for steganography analysis |
| **Video Steg** | Upload videos for frame-by-frame steg analysis |
| **Honeypot** | Decoy service interaction logs with MITRE ATT&CK mapping |
| **Control Center** | IP blocking/unblocking, system controls |
| **Incident Log** | Full searchable log of all detection events |

### WebSocket Live Feed

The dashboard connects to the backend via WebSocket at `ws://localhost:8000/ws/live` for real-time event streaming. You'll see a green "● Connected" indicator when the connection is active.

---

## 6. Running Attack Simulations (Demo)

ShieldNet includes several attack simulation scripts for demonstration. **Run these while the backend is running** to see live detections on the dashboard.

### Simulation 1 — Full Attack Simulation (Recommended)

Simulates a mix of network attacks (DDoS, SQL Injection, Port Scan, etc.):

```bash
python -m backend.utils.testing.simulate
```

This generates events across all detection pipelines and populates the dashboard in real-time.

### Simulation 2 — APT (Advanced Persistent Threat) Simulation

Simulates a multi-stage attack campaign:

```bash
python apt_simulation.py
```

### Simulation 3 — Port Scan Attack

```bash
python attack_portscan.py
```

### Simulation 4 — Brute Force Attack

```bash
python attack_bruteforce.py
```

### Simulation 5 — General Network Attacks

```bash
python attack.py
```

### Simulation 6 — Attack Proxy (Cross-Machine Demo)

Use this to demonstrate attacks from **another laptop on the same network**:

```bash
python -m backend.utils.testing.attack_proxy
```

This opens a proxy that accepts connections from other machines and forwards the attack traffic to ShieldNet for analysis.

### Simulation 7 — Steganography Attack

Sends images with embedded hidden payloads to the steg detection API:

```bash
python -m backend.utils.testing.steg_attack
```

---

## 7. Steganography Detection

### Via Dashboard UI

1. Open the dashboard → click the **"Image Steg"** tab
2. Drag and drop an image file (PNG, JPG, BMP, WebP) into the upload zone
3. ShieldNet analyzes it with **7 statistical algorithms**:
   - Chi-Square Analysis
   - Sample Pair Analysis
   - RS Analysis
   - DCT Histogram Analysis
   - Pixel Histogram Analysis
   - Noise Residual Analysis
   - Benford's Law Analysis
4. Results show: confidence score, detected algorithm, payload estimate, and per-algorithm breakdown

### Via API (curl)

```bash
# Upload and analyze an image
curl -X POST http://localhost:8000/api/steg/upload \
  -F "file=@/path/to/suspicious_image.png"
```

**Response:**
```json
{
  "status": "completed",
  "media_type": "image",
  "filename": "suspicious_image.png",
  "confidence": 0.72,
  "is_steganographic": true,
  "algorithm_detected": "chi_square",
  "payload_estimate_bytes": 4520,
  "incident_created": true,
  "scores": {
    "chi_square": 0.835,
    "sample_pair": 0.632,
    "rs_analysis": 0.445,
    "dct_histogram": 0.081,
    "pixel_histogram": 0.839,
    "noise_residual": 0.720,
    "benford_law": 0.048
  }
}
```

### Via Python Script

```bash
# Quick verification test (creates clean + stego images and tests both)
python verify_steg.py
```

### Creating Test Stego Images

Use the built-in tool to embed hidden data in an image:

```bash
python steg_hide.py --input photo.png --message "secret text" --output stego_photo.png
```

Then upload `stego_photo.png` to ShieldNet to verify detection.

### (Optional) Training the CNN Model

For higher accuracy (statistical ~85% → CNN fusion ~96%):

```bash
# Generate synthetic training dataset
python -m backend.utils.testing.generate_steg_dataset

# Train the model
python -m backend.services.steg.cnn.train_cnn \
  --clean-dir ./data/clean \
  --steg-dir ./data/steg \
  --epochs 15 \
  --output models/steg_cnn.pth
```

> See [TRAINING_GUIDE.md](TRAINING_GUIDE.md) for more details.

---

## 8. API Reference

The FastAPI backend auto-generates interactive API docs.

### Swagger UI (Interactive)
```
http://localhost:8000/docs
```

### ReDoc (Readable)
```
http://localhost:8000/redoc
```

### Key API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/dashboard/overview` | Dashboard statistics and counts |
| `GET` | `/api/dashboard/recent` | Recent detection events |
| `GET` | `/api/idps/events` | All IDPS detection events |
| `POST` | `/api/idps/events` | Submit a new detection event |
| `GET` | `/api/steg/events` | All steganography events |
| `POST` | `/api/steg/upload` | Upload image/video for analysis |
| `GET` | `/api/honeypot/interactions` | Honeypot interaction logs |
| `GET` | `/api/dashboard/blocked-ips` | Currently blocked IPs |
| `POST` | `/api/dashboard/block-ip` | Block an IP address |
| `POST` | `/api/dashboard/unblock-ip/{ip}` | Unblock an IP address |
| `GET` | `/api/sensors/status` | Network sensor status |
| `POST` | `/api/sensors/pcap/start` | Start PCAP capture |
| `POST` | `/api/sensors/pcap/stop` | Stop PCAP capture |
| `WS` | `/ws/live` | WebSocket for real-time events |

---

## 9. Environment Variables

All settings can be overridden via environment variables. Create a `.env` file in the project root, or set them directly.

### Application

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_NAME` | `ShieldNet` | Application name |
| `APP_VERSION` | `3.0.0` | Version string |
| `APP_ENV` | `development` | `development` / `staging` / `production` |
| `APP_DEBUG` | `true` | Enable debug mode |
| `APP_HOST` | `0.0.0.0` | Bind address |
| `APP_PORT` | `8000` | API server port |
| `APP_SECRET_KEY` | `change-me-in-production` | Secret key for signing |

### Database

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite:///data/shieldnet.db` | Database connection string |
| `DB_ECHO_SQL` | `false` | Log all SQL queries |

### Detection Thresholds

| Variable | Default | Description |
|----------|---------|-------------|
| `IDPS_ML_THRESHOLD` | `0.70` | Minimum confidence for IDPS alert |
| `STEG_SUSPICIOUS_THRESHOLD` | `0.40` | Minimum confidence for steg incident |
| `STEG_LIKELY_THRESHOLD` | `0.70` | Threshold for "likely steg" classification |
| `AUTO_BLOCK_ENABLED` | `true` | Auto-block malicious IPs |
| `AUTO_BLOCK_SEVERITIES` | `high,critical` | Which severity levels trigger auto-block |

### Feature Toggles

| Variable | Default | Description |
|----------|---------|-------------|
| `FEAT_REALTIME_ALERTS` | `true` | Enable WebSocket live alerts |
| `FEAT_AUTO_BLOCK` | `true` | Enable automatic IP blocking |
| `FEAT_CORRELATION` | `true` | Enable cross-pipeline correlation |
| `FEAT_HONEYPOT` | `true` | Enable honeypot detection |
| `FEAT_STEG_QUARANTINE` | `true` | Enable steg file quarantine |

### Demo / Simulation

| Variable | Default | Description |
|----------|---------|-------------|
| `DEMO_MODE` | `false` | Seed database with demo data on startup |
| `SIM_ENABLED` | `false` | Enable background simulation loop |

### Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `INFO` | Global log level |
| `LOG_FORMAT` | `text` | `text` or `json` |
| `LOG_FILE_ENABLED` | `true` | Write logs to file |

---

## 10. Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        DASHBOARD                            │
│                   (dashboard.html:8080)                      │
│          WebSocket ◄──────────────────── REST API            │
└──────────────┬──────────────────────────────┬───────────────┘
               │ ws://localhost:8000/ws/live   │ http://localhost:8000/api
               ▼                               ▼
┌─────────────────────────────────────────────────────────────┐
│                    FastAPI Backend (:8000)                   │
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐  │
│  │   IDPS   │  │   Steg   │  │ Honeypot │  │ Correlation│  │
│  │ Pipeline │  │ Pipeline │  │  Service  │  │   Engine   │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └─────┬──────┘  │
│       │              │             │               │         │
│       └──────────────┴─────────────┴───────────────┘         │
│                          │                                   │
│                    ┌─────┴──────┐                            │
│                    │  Alert Bus │ (async pub/sub)             │
│                    └─────┬──────┘                            │
│                          │                                   │
│                    ┌─────┴──────┐                            │
│                    │  Database  │ (SQLite / PostgreSQL)       │
│                    └────────────┘                            │
└─────────────────────────────────────────────────────────────┘

         ▲ Traffic Sources
         │
    ┌────┴────────────────────────────┐
    │  • Scapy (live packet capture)  │
    │  • Attack Proxy (cross-machine) │
    │  • Simulation scripts           │
    │  • API submissions              │
    └─────────────────────────────────┘
```

### Detection Pipelines

1. **IDPS Pipeline**: Traffic → Flow Aggregation → Feature Extraction (42+ features) → Rule Engine (fast path) + XGBoost/BiLSTM (ML path) → Fusion → Response
2. **Steg Pipeline**: Image Upload → 7 Statistical Algorithms + CNN (EfficientNet-B0) → Late Fusion → Quarantine
3. **Honeypot**: Decoy services → Interaction logging → MITRE ATT&CK mapping
4. **Correlation Engine**: Cross-pipeline event linking to surface multi-stage campaigns

---

## 11. Troubleshooting

### "Module not found: backend"

**Cause:** Python can't find the `backend` package.

**Fix:** Run from the project root directory:
```bash
cd ShieldNet-AI-powered-IDPS
python -m uvicorn backend.main:app --port 8000 --reload
```

### Dashboard shows "Disconnected" or "Connection Failed"

**Cause:** Backend server isn't running or is on a different port.

**Fix:**
1. Make sure the backend is running on port 8000
2. Check the browser console for errors
3. Verify the API URL in `dashboard.html` points to `http://localhost:8000`

### "Port 8000 already in use"

**Fix:**
```bash
# Find what's using port 8000
# Windows:
netstat -ano | findstr :8000

# Linux:
lsof -i :8000

# Kill the process or use a different port:
python -m uvicorn backend.main:app --port 8001 --reload
```

### "ImportError: No module named 'torch'"

**Cause:** PyTorch not installed (large dependency, may have failed).

**Fix:**
```bash
pip install torch torchvision
```

> The steg detection works without PyTorch — it falls back to statistical-only mode.

### "Npcap/libpcap not found"

**Cause:** Live packet capture requires Npcap (Windows) or libpcap (Linux).

**Fix:** Install Npcap from https://npcap.com/ — or use attack simulations instead (they don't need Npcap).

### Dashboard loads but shows no data

**Fix:** Run a simulation to generate events:
```bash
python -m backend.utils.testing.simulate
```

Or start in demo mode:
```bash
set DEMO_MODE=true
python -m uvicorn backend.main:app --port 8000 --reload
```

### "UnicodeEncodeError" in terminal output

**Cause:** Windows terminal (cp1252) can't render Unicode characters.

**Fix:** Set UTF-8 mode:
```powershell
$env:PYTHONIOENCODING = "utf-8"
chcp 65001
```

### Database reset

To start fresh:
```bash
# Delete the database file
del data\shieldnet.db          # Windows
rm data/shieldnet.db           # Linux/macOS

# Restart the backend (it auto-creates a new database)
python -m uvicorn backend.main:app --port 8000 --reload
```

---

## 12. Project Structure

```
ShieldNet-AI-powered-IDPS/
│
├── backend/                      # FastAPI backend application
│   ├── main.py                   # Application entry point & lifespan
│   ├── api/                      # REST API layer
│   │   ├── router.py             # Main API router (assembles all sub-routers)
│   │   ├── routes/
│   │   │   ├── idps.py           # Network IDPS endpoints
│   │   │   ├── steg.py           # Steganography endpoints + upload
│   │   │   ├── honeypot.py       # Honeypot interaction endpoints
│   │   │   ├── dashboard.py      # Dashboard statistics endpoints
│   │   │   └── sensors.py        # Network sensor management
│   │   └── websocket/
│   │       └── ws_manager.py     # WebSocket connection manager
│   ├── core/                     # Core infrastructure
│   │   ├── config.py             # Centralized configuration (env vars)
│   │   ├── logging.py            # Structured logging
│   │   └── exceptions.py         # Exception hierarchy
│   ├── db/                       # Database layer
│   │   ├── database.py           # SQLAlchemy engine & session
│   │   ├── models.py             # ORM table definitions
│   │   └── repositories/         # CRUD operations
│   ├── schemas/                  # Pydantic request/response models
│   ├── sensors/                  # Network sensor integrations
│   │   ├── pcap_sensor.py        # Live packet capture (Scapy/Npcap)
│   │   ├── suricata_sensor.py    # Suricata IDS integration
│   │   └── mitmproxy_addon.py    # MITM proxy addon
│   ├── services/                 # Business logic (domain services)
│   │   ├── idps/                 # Network intrusion detection
│   │   │   ├── attack_classifier.py
│   │   │   ├── flow_generator.py
│   │   │   ├── flow_features.py
│   │   │   └── rule_engine.py
│   │   ├── steg/                 # Steganography detection
│   │   │   ├── algorithms.py     # 7 statistical algorithms
│   │   │   ├── analyzer.py       # Main analysis pipeline
│   │   │   ├── proxy.py          # Traffic inspection proxy
│   │   │   └── cnn/              # EfficientNet-B0 CNN classifier
│   │   │       ├── cnn_classifier.py
│   │   │       └── train_cnn.py
│   │   ├── honeypot/             # Honeypot decoy services
│   │   ├── correlation/          # Cross-pipeline event correlation
│   │   ├── response/             # Automated response (block/alert)
│   │   │   ├── alert_bus.py      # Async pub/sub event bus
│   │   │   └── intelligence.py   # Threat intelligence
│   │   └── video/                # Video steg analysis pipeline
│   └── utils/testing/            # Simulation & testing tools
│       ├── simulate.py           # Full attack simulation
│       ├── attack_proxy.py       # Cross-machine attack proxy
│       ├── steg_attack.py        # Steg attack simulation
│       ├── demo_seed.py          # Demo data seeder
│       └── generate_steg_dataset.py
│
├── dashboard.html                # Single-page security dashboard
├── requirements.txt              # Python dependencies
├── setup.sh                      # Linux/macOS setup script
│
├── attack.py                     # Attack simulation scripts
├── attack_bruteforce.py
├── attack_portscan.py
├── apt_simulation.py
├── steg_hide.py                  # Embed hidden data in images
├── steg_video.py                 # Video steganography tool
├── verify_steg.py                # Steg detection verification test
│
├── models/                       # Trained ML models (auto-created)
├── data/                         # Training data & database
├── logs/                         # Application logs
├── quarantine/                   # Quarantined suspicious files
├── uploads/                      # Uploaded files for analysis
│
├── ARCHITECTURE.md               # Backend architecture documentation
├── TRAINING_GUIDE.md             # CNN model training guide
└── HOW_TO_RUN.md                 # ← You are here
```

---

## Summary — The 3 Commands You Need

```bash
# Terminal 1: Backend
.\venv\Scripts\activate
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload

# Terminal 2: Dashboard
.\venv\Scripts\activate
python -m http.server 8080

# Terminal 3: Demo traffic (optional)
.\venv\Scripts\activate
python -m backend.utils.testing.simulate
```

Then open: **http://localhost:8080/dashboard.html** 🛡️
