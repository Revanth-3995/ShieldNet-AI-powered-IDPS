# ShieldNet — System Architecture

This document describes the high-level architecture, module relationships, and data flows of the ShieldNet AI-Powered Intrusion Detection & Prevention System.

---

## 1. High-Level Architecture

ShieldNet is composed of two primary detection pipelines (Pipeline A and Pipeline B), a shared FastAPI backend, a real-time alerting bus, and a live monitoring dashboard. 

```mermaid
graph TD
    subgraph "External Entities"
        A[Attacker / Client]
    end

    subgraph "Pipeline A: Network IDPS"
        Pcap[Traffic Capture]
        Ext[Feature Extractor]
        RE[Rule Engine]
        XGB[XGBoost Classifier]
        BiLSTM[BiLSTM Temporal]
        Pcap --> Ext
        Ext --> RE
        Ext --> XGB
        Ext --> BiLSTM
    end

    subgraph "Pipeline B: Steganalysis"
        Proxy[mitmproxy Addon]
        Det[Detection Engine]
        Quar[Quarantine Manager]
        Forens[Forensic Reporter]
        Proxy --> Det
        Det --> Quar
        Det --> Forens
    end

    subgraph "ShieldNet Backend"
        API[FastAPI Router]
        DB[(SQLite / DB)]
        Corr[Correlation Engine]
        Bus[Alert Bus pub/sub]
        Resp[Automated Response]
    end

    subgraph "Frontend"
        Dash[Live Dashboard]
    end

    A -- Uploads Image --> Proxy
    A -- Network Traffic --> Pcap

    RE --> API
    XGB --> API
    BiLSTM --> API
    Proxy -- "POST /api/steg/event" --> API
    
    API --> DB
    API --> Corr
    API --> Bus
    Corr --> Bus
    Bus --> Resp
    Bus -. "WebSocket" .-> Dash
    Resp -- "Block IP" --> Proxy
```

---

## 2. Folder Structure

The project is organized into modular directories based on functionality:

```text
ShieldNet-AI-powered-IDPS/
├── backend/                      # Central FastAPI application
│   ├── api/                      # REST endpoints and WebSocket routes
│   │   └── routes/               # Modular routers (steg, idps, dashboard)
│   ├── core/                     # App configuration, logging, exceptions
│   ├── db/                       # SQLAlchemy models, sessions, and schemas
│   └── services/                 # Business logic and coordination
│       ├── correlation/          # Multi-pipeline incident linking
│       ├── honeypot/             # Decoy services management
│       ├── idps/                 # Pipeline A logic (ML, rules, capture)
│       └── response/             # Automated IP blocking and Alert Bus
├── pipeline_b/                   # Pipeline B (Steganalysis Interceptor)
│   ├── detector.py               # ML and Statistical fusion algorithms
│   ├── mitmproxy_addon.py        # Proxy interceptor logic
│   ├── quarantine_manager.py     # Secure file isolation
│   ├── backend_client.py         # Async backend communication
│   ├── forensics.py              # Incident report generation
│   ├── quarantine/               # Secure storage for detected files
│   └── logs/                     # Operational logs and forensic JSONs
├── tests/                        # Automated test suites
│   ├── pipeline_b/               # Pytest suite for Steganalysis
│   └── ...
├── models/                       # Trained ML artifacts (XGBoost, CNN, BiLSTM)
├── data/                         # Datasets (CICIDS2017, etc.)
└── dashboard.html                # Single-page UI for real-time monitoring
```

---

## 3. Pipeline B: Module Relationships

Pipeline B is heavily modularized to decouple proxy interception from heavy ML inference and backend communication.

```mermaid
classDiagram
    class mitmproxy_addon {
        +request(flow)
        -_extract_multipart_images()
        -_apply_response()
    }
    class detector {
        +predict_image(filepath)
        +evaluate_result(confidence)
    }
    class quarantine_manager {
        +quarantine_file(filepath, record)
        +save_detection_record(record)
    }
    class forensics {
        +generate_forensic_report(...)
        +save_forensic_report(report)
    }
    class backend_client {
        +send_steg_event(event)
        +send_steg_event_sync(event)
    }

    mitmproxy_addon --> detector : calls for analysis
    mitmproxy_addon --> quarantine_manager : isolates on critical
    mitmproxy_addon --> forensics : generates report
    mitmproxy_addon --> backend_client : dispatches event
```

---

## 4. Data Flow: Steganography Detection (Pipeline B)

This sequence illustrates the end-to-end data flow when an attacker uploads a steganographic image.

```mermaid
sequenceDiagram
    participant Attacker
    participant Proxy as mitmproxy Addon
    participant Det as Detection Engine
    participant Quar as Quarantine Mgr
    participant API as FastAPI Backend
    participant Dash as Dashboard

    Attacker->>Proxy: Upload image (POST)
    Proxy->>Proxy: Intercept & Save temp file
    Proxy->>Det: predict_image()
    
    rect rgb(40, 40, 50)
        Note over Det: 7 Statistical Algorithms<br/>+ EfficientNet-B0
    end
    
    Det-->>Proxy: Result (confidence: 0.93)
    Proxy->>Det: evaluate_result(0.93)
    Det-->>Proxy: Action: quarantine
    
    par Forensic & Isolation
        Proxy->>Quar: quarantine_file()
        Proxy->>Proxy: generate_forensic_report()
    and Alert Generation
        Proxy->>API: POST /api/steg/event
        API->>API: DB Insert (StegScan, Incident)
        API->>Dash: WebSocket Event
    end
    
    Proxy-->>Attacker: HTTP 403 Forbidden
```

---

## 5. Backend Communication & Correlation

When events arrive at the backend (from either Pipeline A or B), they undergo correlation and broad distribution.

```mermaid
flowchart TD
    E1[Pipeline A Event] --> API[FastAPI Entry Point]
    E2[Pipeline B Event] --> API
    
    API --> DB[(SQLite Database)]
    API --> Corr{Correlation Engine}
    
    Corr -- "Same IP / Time Window" --> CG[Correlation Group]
    CG --> DB
    
    API --> Bus[Alert Bus]
    CG --> Bus
    
    Bus --> WS[WebSocket Manager]
    WS --> Client1[Dashboard Client 1]
    WS --> Client2[Dashboard Client 2]
    
    Bus --> Block[Response Manager]
    Block -- "Adds to" --> B_IP[(Blocked IPs Table)]
```

---

## 6. Quarantine Workflow

Files flagged as `critical` by the Steganalysis pipeline are immediately isolated.

```mermaid
stateDiagram-v2
    [*] --> TempUpload: mitmproxy intercepts
    TempUpload --> Analysis: predict_image()
    
    Analysis --> Clean: confidence < 0.40
    Analysis --> Suspicious: confidence < 0.70
    Analysis --> Likely: confidence < 0.85
    Analysis --> Critical: confidence >= 0.85
    
    Clean --> Allow
    Suspicious --> Allow
    Likely --> Block
    
    Critical --> Quarantine
    
    state Quarantine {
        CopyFile: Copy to pipeline_b/quarantine/YYYY-MM-DD/
        GenReport: Generate Forensic JSON
        SaveLog: Append to detections.json
        
        CopyFile --> GenReport
        GenReport --> SaveLog
    }
    
    Quarantine --> Block
    Block --> [*]: Return HTTP 403
    Allow --> [*]: Pass-through to destination
```

---

## 7. Future Dashboard Integration

The dashboard receives real-time WebSocket events and updates the UI dynamically. Future enhancements will integrate deep forensic reporting directly into the frontend.

```mermaid
graph LR
    subgraph "Backend"
        WS[WebSocket /api/ws/live]
        API1[GET /api/steg/forensics/{id}]
        API2[GET /api/steg/quarantine]
    end

    subgraph "Dashboard UI"
        Feed[Live Incident Feed]
        HM[Confidence Heatmap]
        FQ[Forensics Modal / Viewer]
        IP[Blocked IP Manager]
    end

    WS -. "JSON Alerts" .-> Feed
    Feed --> HM
    Feed -- "Click Event" --> FQ
    FQ -- "Fetch details" --> API1
    IP -- "Poll" --> API2
```

---
