# ShieldNet — Complete Run Guide

> Step-by-step instructions for running the full ShieldNet AI-Powered IDPS + Pipeline B Steganographic Covert Channel Detection system.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Starting the Backend](#starting-the-backend)
4. [Starting Pipeline B Proxy](#starting-pipeline-b-proxy)
5. [Testing Image Upload Detection](#testing-image-upload-detection)
6. [Viewing Logs & Artifacts](#viewing-logs--artifacts)
7. [Running the Test Suite](#running-the-test-suite)
8. [Attack Simulation](#attack-simulation)
9. [Dashboard Access](#dashboard-access)
10. [Troubleshooting](#troubleshooting)

---

## Prerequisites

| Requirement | Version | Check |
|------------|---------|-------|
| Python | 3.12+ | `python --version` |
| pip | 24.0+ | `pip --version` |
| Git | Any | `git --version` |
| curl (optional) | Any | `curl --version` |

> [!IMPORTANT]
> Python 3.12 is required. The CNN model (EfficientNet-B0) and mitmproxy require Python 3.12+.

---

## Installation

### Step 1 — Clone the Repository

```bash
git clone <repository-url>
cd ShieldNet-AI-powered-IDPS
```

### Step 2 — Create Virtual Environment

```bash
python -m venv venv
```

**Windows:**
```bash
venv\Scripts\activate
```

**Linux / macOS:**
```bash
source venv/bin/activate
```

### Step 3 — Install Runtime Dependencies

```bash
pip install -r requirements.txt
```

> [!NOTE]
> This installs ~35 packages including PyTorch, mitmproxy, FastAPI, and OpenCV.
> Installation may take 5–15 minutes depending on internet speed.

### Step 4 — Install Development Dependencies (Optional)

```bash
pip install -r requirements-dev.txt
```

### Step 5 — Verify Installation

```bash
python -c "import torch, fastapi, mitmproxy, PIL; print('All core packages OK')"
```

Expected output:
```
All core packages OK
```

---

## Starting the Backend

### Command

```bash
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

### Expected Output

```
INFO:     Started server process [12345]
INFO:     Waiting for application startup.
INFO:     [ShieldNet] Database tables created.
INFO:     [CNN] EfficientNet-B0 loaded from models/steg_cnn.pth
INFO:     [Honeypot] Decoy services starting on ports 21, 22, 23, 80...
INFO:     [AlertBus] Started — subscriptions: IDPS, STEG, IP_BLOCKED
INFO:     ShieldNet v3.0.0 started.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

> [!NOTE]
> If `models/steg_cnn.pth` is not present, the system falls back to statistical-only mode.
> All endpoints remain fully functional in fallback mode.

### Verify Backend Is Running

```bash
curl http://127.0.0.1:8000/api/steg/health
```

Expected response:
```json
{
  "mock_mode": false,
  "cnn_loaded": true,
  "algorithms_available": ["chi_square", "sample_pair", "rs_analysis", "dct_histogram", "pixel_histogram", "noise_residual", "benford_law"],
  "pil_available": true,
  "warning": null
}
```

---

## Starting Pipeline B Proxy

> [!IMPORTANT]
> Start the backend FIRST, then the proxy. The proxy sends events to the backend.

### Command (HTTP interception)

```bash
mitmdump -s pipeline_b/mitmproxy_addon.py --listen-port 8080
```

### Command (HTTPS interception)

```bash
mitmdump -s pipeline_b/mitmproxy_addon.py --listen-port 8080 --ssl-insecure
```

### Command (Verbose logging)

```bash
mitmdump -s pipeline_b/mitmproxy_addon.py --listen-port 8080 -v
```

### Expected Output

```
[Addon] ShieldNet Pipeline B addon loaded.
[Addon] Uploads directory: pipeline_b/uploads
[Addon] Logs directory:    pipeline_b/logs
Proxy server listening at http://*:8080
```

---

## Testing Image Upload Detection

### Prerequisites

Have the `stego_output.png` file in your project root (created by `steg_hide.py`).

Or create a test steg image:
```bash
python steg_hide.py
```

### Test 1 — Upload a Steganographic Image (Direct)

```bash
curl -x http://127.0.0.1:8080 \
     -H "Content-Type: image/png" \
     --data-binary @stego_output.png \
     http://httpbin.org/post \
     -w "\nHTTP Status: %{http_code}\n"
```

**Expected proxy log output:**
```
[Addon] Intercepted direct image upload: intercepted_150042.png from 127.0.0.1 (136319 bytes)
[Detector] Analyzing: pipeline_b/uploads/a1b2c3d4_stego_output.png (image/png, 136319 bytes)
[Detector] Result: prediction=steg, confidence=0.934, method=efficientnet_b0_fused
[Addon] stego_output.png | 127.0.0.1 | confidence=0.934 | severity=critical | action=quarantine
[Quarantine] QUARANTINED: stego_output.png → pipeline_b/quarantine/2026-06-21/stego_output_93pct.png
[BackendClient] Event sent successfully (attempt 1/3): HTTP 200
[Forensics] Report saved: pipeline_b/logs/forensics/20260621T150042Z_stego_output_a1b2c3d4.json
[Addon] REQUEST BLOCKED: stego_output.png | severity=critical | confidence=0.934
```

**Expected curl response (HTTP 403):**
```json
{
  "error": "ShieldNet: Steganographic content detected and blocked.",
  "filename": "intercepted_150042.png",
  "confidence": 0.934,
  "severity": "critical",
  "action": "quarantine",
  "pipeline": "B",
  "timestamp": "2026-06-21T15:00:42+00:00"
}
HTTP Status: 403
```

### Test 2 — Upload a Steganographic Image (Multipart Form)

```bash
curl -x http://127.0.0.1:8080 \
     -F "file=@stego_output.png;type=image/png" \
     http://httpbin.org/post \
     -w "\nHTTP Status: %{http_code}\n"
```

### Test 3 — Upload a Clean Image

```bash
curl -x http://127.0.0.1:8080 \
     -H "Content-Type: image/png" \
     --data-binary @test_cover.png \
     http://httpbin.org/post \
     -w "\nHTTP Status: %{http_code}\n"
```

**Expected proxy log output (clean):**
```
[Detector] Result: prediction=clean, confidence=0.082, method=efficientnet_b0_fused
[Addon] test_cover.png | 127.0.0.1 | confidence=0.082 | severity=clean | action=allow
[Addon] Request allowed: test_cover.png | severity=clean | confidence=0.082
```

**Expected curl response: HTTP 200** (request passes through to httpbin normally)

### Test 4 — Upload via ShieldNet Backend Directly

```bash
curl -X POST http://127.0.0.1:8000/api/steg/upload \
     -F "file=@stego_output.png;type=image/png" \
     -F "source_ip=192.168.1.100"
```

Expected response:
```json
{
  "status": "completed",
  "media_type": "image",
  "filename": "stego_output.png",
  "file_size": 136319,
  "confidence": 0.934,
  "is_steganographic": true,
  "algorithm_detected": "chi_square",
  "payload_estimate_bytes": 17040,
  "incident_created": true,
  "incident_id": 42
}
```

---

## Viewing Logs & Artifacts

### Detection Records — `pipeline_b/logs/detections.json`

Every quarantined file produces a JSON record appended here:

```bash
# View all detections:
type pipeline_b\logs\detections.json          # Windows
cat pipeline_b/logs/detections.json           # Linux

# Pretty-print with Python:
python -c "import json; [print(json.dumps(r, indent=2)) for r in json.load(open('pipeline_b/logs/detections.json'))[-3:]]"
```

Example record:
```json
{
  "filename": "stego_output.png",
  "timestamp": "2026-06-21T15:00:42+00:00",
  "confidence": 0.934,
  "severity": "critical",
  "prediction": "steg",
  "source_ip": "127.0.0.1",
  "quarantine_path": "pipeline_b/quarantine/2026-06-21/stego_output_93pct.png"
}
```

### Forensic Reports — `pipeline_b/logs/forensics/`

One JSON file per analyzed image:

```bash
# List recent reports:
dir pipeline_b\logs\forensics\                 # Windows
ls -la pipeline_b/logs/forensics/             # Linux

# View latest report:
python -c "
import json, glob, os
reports = sorted(glob.glob('pipeline_b/logs/forensics/*.json'))
if reports:
    print(json.dumps(json.load(open(reports[-1])), indent=2))
"
```

### Quarantined Files — `pipeline_b/quarantine/`

Files are organized by detection date:

```
pipeline_b/quarantine/
└── 2026-06-21/
    ├── stego_output_93pct.png
    ├── evil_image_87pct.jpg
    └── suspect_payload_91pct_2.webp
```

```bash
# List quarantined files:
dir /s pipeline_b\quarantine\                  # Windows
find pipeline_b/quarantine -type f            # Linux
```

### Operational Log — `pipeline_b/logs/pipeline_b.log`

```bash
# Stream live (Windows):
Get-Content pipeline_b\logs\pipeline_b.log -Wait

# Stream live (Linux):
tail -f pipeline_b/logs/pipeline_b.log
```

### Backend Database Events

```bash
curl http://127.0.0.1:8000/api/dashboard/incidents?limit=10
curl http://127.0.0.1:8000/api/steg/quarantine
curl http://127.0.0.1:8000/api/steg/health
```

---

## Running the Test Suite

### Run All Pipeline B Tests

```bash
python -m pytest tests/pipeline_b/test_pipeline_b.py -v
```

### Run with Coverage Report

```bash
python -m pytest tests/pipeline_b/test_pipeline_b.py -v --cov=pipeline_b --cov-report=term-missing
```

### Run Specific Test Class

```bash
# Test 1 — Clean image detection
python -m pytest tests/pipeline_b/test_pipeline_b.py::TestCleanImageDetection -v

# Test 2 — Steg image + quarantine + forensics
python -m pytest tests/pipeline_b/test_pipeline_b.py::TestStegImageDetection -v

# Test 3 — Multi-image batch
python -m pytest tests/pipeline_b/test_pipeline_b.py::TestMultipleImageBatch -v
```

### Expected Output

```
============================= test session starts =============================
platform win32 -- Python 3.12.10, pytest-9.1.1
collecting ... collected 17 items

TestCleanImageDetection::test_predict_returns_clean          PASSED [  5%]
TestCleanImageDetection::test_evaluate_clean_result          PASSED [ 11%]
TestCleanImageDetection::test_evaluate_all_thresholds        PASSED [ 17%]
TestCleanImageDetection::test_predict_file_not_found         PASSED [ 23%]
TestCleanImageDetection::test_predict_result_schema          PASSED [ 29%]
TestStegImageDetection::test_predict_steg_returns_steg       PASSED [ 35%]
TestStegImageDetection::test_evaluate_steg_action            PASSED [ 41%]
TestStegImageDetection::test_quarantine_file_created         PASSED [ 47%]
TestStegImageDetection::test_detection_record_saved          PASSED [ 52%]
TestStegImageDetection::test_forensic_report_generated       PASSED [ 58%]
TestStegImageDetection::test_backend_event_payload_structure PASSED [ 64%]
TestMultipleImageBatch::test_batch_no_crashes                PASSED [ 70%]
TestMultipleImageBatch::test_batch_no_missed_analyses        PASSED [ 76%]
TestMultipleImageBatch::test_batch_evaluate_all              PASSED [ 82%]
TestMultipleImageBatch::test_batch_steg_higher_confidence_than_clean PASSED [ 88%]
TestMultipleImageBatch::test_quarantine_manager_multiple     PASSED [ 94%]
TestMultipleImageBatch::test_forensic_reports_multiple       PASSED [100%]

============================= 17 passed in 16.63s =============================
```

### Run Existing Steg Tests

```bash
# Direct algorithm test (no backend needed):
python test_steg_direct.py

# API test (backend must be running):
python test_steg_api.py
```

---

## Attack Simulation

### Generate a Steg Image

```bash
# Hide a secret message in an image:
python steg_hide.py
```

This creates `stego_output.png` with a hidden payload embedded via LSB steganography.

### Run Full APT Simulation

```bash
# Simulate multi-stage attack (with backend running):
python apt_simulation.py
```

### Run Port Scan Simulation

```bash
python attack_portscan.py
```

### Run Brute Force Simulation

```bash
python attack_bruteforce.py
```

---

## Dashboard Access

Once the backend is running, open the dashboard in your browser:

```
file:///path/to/project/dashboard.html
```

Or serve it locally:

```bash
# Windows:
Start-Process dashboard.html

# Linux:
xdg-open dashboard.html
```

The dashboard connects automatically to `ws://127.0.0.1:8000/ws/live` and displays:
- Real-time incident feed (Pipeline A + B)
- Steganography detection alerts with confidence scores
- Quarantine file list
- IP block status
- Honeypot event log
- Correlation timeline

> [!NOTE]
> If using port 8000 instead of the default 8000, update the dashboard's WebSocket URL.

---

## Troubleshooting

### Backend Won't Start

```
ModuleNotFoundError: No module named 'backend'
```
**Fix:** Run from the project root directory, not from inside the `backend/` folder.
```bash
cd /path/to/ShieldNet-root
uvicorn backend.main:app --port 8000
```

---

### CNN Model Not Found

```
[CNN] Model not found at models/steg_cnn.pth. Falling back to statistical-only scoring.
```
**This is non-critical.** The system uses 7 statistical algorithms without the CNN.

To train the CNN (requires GPU recommended):
```bash
python backend/services/steg/cnn/train_cnn.py
```

---

### mitmproxy SSL Certificate Warning

```
[Errno 2] No such file or directory: 'mitmproxy-ca-cert.pem'
```
**Fix:** Run mitmproxy once standalone to generate the certificate:
```bash
mitmproxy
# Press Q to quit immediately
# Certificate is now at: ~/.mitmproxy/mitmproxy-ca-cert.pem
```

---

### Port Already In Use

```
[Errno 48] Address already in use
```

**Fix (Windows):**
```powershell
netstat -ano | findstr :8000
kill -f <PID>
```

**Fix (Linux):**
```bash
lsof -i :8000
kill -9 <PID>
```

---

### Pillow / OpenCV Import Error

```
ModuleNotFoundError: No module named 'PIL'
```
**Fix:**
```bash
pip install Pillow==10.3.0 opencv-python==4.13.0.92
```

---

### PyTorch CUDA Warning (Windows)

```
UserWarning: CUDA not available. Running on CPU.
```
**This is non-critical.** The EfficientNet model runs fine on CPU; inference takes ~50ms per image.

---

### Tests Fail with Import Error

```
ModuleNotFoundError: No module named 'pipeline_b.detector'
```
**Fix:** Run pytest from the project root directory:
```bash
cd /path/to/ShieldNet-root
python -m pytest tests/pipeline_b/test_pipeline_b.py -v
```

---

## Quick Reference

| Task | Command |
|------|---------|
| Start backend | `uvicorn backend.main:app --port 8000 --reload` |
| Start proxy | `mitmdump -s pipeline_b/mitmproxy_addon.py --listen-port 8080` |
| Run all tests | `python -m pytest tests/pipeline_b/test_pipeline_b.py -v` |
| Health check | `curl http://127.0.0.1:8000/api/steg/health` |
| Generate steg image | `python steg_hide.py` |
| View detections | `python -c "import json; print(open('pipeline_b/logs/detections.json').read())"` |
| View quarantine | `dir pipeline_b\quarantine` (Windows) / `ls pipeline_b/quarantine` (Linux) |
| Dashboard | Open `dashboard.html` in browser |
