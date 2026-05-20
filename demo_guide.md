# ShieldNet — Live Demo Guide for Teacher

## Overview
This demo shows a **real-time AI cybersecurity platform** detecting live attacks across 3 pipelines: Network IDPS, Steganography Detection, and Honeypot.

---

## Prerequisites
- Open **4 separate terminal windows** (Command Prompt or PowerShell)
- All terminals should `cd` to: `c:\Users\REVANTH VISHNU REDDY\Desktop\main_el`

---

## Step-by-Step Demo

### STEP 1 — Start the Backend API (Terminal 1)
```powershell
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
> Wait for: `Application startup complete` message.

### STEP 2 — Start the Attack Detection Proxy (Terminal 2)
```powershell
python -m backend.utils.testing.attack_proxy
```
> This proxy captures the simulated attack traffic and feeds it into the AI engine.

### STEP 3 — Open the Dashboard (Terminal 3)
```powershell
python -m http.server 8080
```
> Open browser to: **`http://127.0.0.1:8080/dashboard.html`**

### STEP 4 — Launch the Live Attack (Terminal 4)
```powershell
# Standard multi-stage attack
python attack.py --target 127.0.0.1 --threads 12

# NEW: High-rate DDoS Flood Simulation
python attack.py --target 127.0.0.1 --ddos
```
> Watch the dashboard light up with real-time detections!

---

## What to Show the Teacher

### 1. Dashboard — Overview Tab (📊)
- **Live Event Feed** — events stream in real-time as the attack runs.
- **Attack Type Breakdown** — categorizing threats into PortScan, BruteForce, SQLi, etc.

### 2. Dashboard — Network IDPS Tab (🌐)
- **Hybrid AI Scores** — See how Rule-based and ML-based detections are fused.
- **New Attack Types**: Point out **SQL Injection** and **DDoS (PPS Violation)**.

### 3. Dashboard — Honeypot Tab (🍯)
- **Credentials & TTPs** — View harvested credentials from SSH brute force attempts.
- **MITRE Mapping** — Explain how attacks map to the MITRE ATT&CK framework.

### 4. Dashboard — Control Tab (⚙️)
- **Advanced Heuristics**: Show the "Pipeline Health" and the new specific attack triggers.
- **DDoS Demo**: Run the `--ddos` command and show the PPS graph spiking.

---

## Key Talking Points (Advanced Rules)

1. **Deterministic Layer**: Fast-path detection of SQLi and Brute Force via `RuleEngine`.
2. **Rate Limiting**: Automated detection of DDoS attacks based on packet-per-second (PPS) thresholds.
3. **Behavioral AI**: XGBoost detecting "Zero-Day" anomalies in traffic entropy.
4. **Temporal Sequence**: BiLSTM tracking the progression from scanning to exfiltration.
5. **Automated Response**: Explain that high-confidence attacks automatically trigger the IP Blocker.

---

## Terminal Summary

```
┌─────────────────────────────────────────────────────────────┐
│ Terminal 1: python -m uvicorn backend.main:app --port 8000  │
│                                                             │
│ Terminal 2: python -m backend.utils.testing.attack_proxy    │
│                                                             │
│ Terminal 3: python -m http.server 8080 (Dashboard)          │
│                                                             │
│ Terminal 4: python attack.py --target 127.0.0.1 --ddos      │
└─────────────────────────────────────────────────────────────┘
```
