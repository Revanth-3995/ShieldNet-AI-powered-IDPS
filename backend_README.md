# ShieldNet Backend

Modular, AI-powered cybersecurity platform backend built with FastAPI.

---

## Architecture Overview

The backend follows a domain-driven modular structure with strict separation between API, logic, and data layers.

```
backend/
├── api/            # HTTP routes and WebSocket entry points
├── core/           # Infrastructure (config, logging, exceptions, queue)
├── db/             # Persistence layer (models, repositories, migrations)
├── services/       # Domain logic (IDPS, Steganalysis, Honeypot, Correlation)
├── schemas/        # Pydantic models for request/response validation
├── utils/          # Shared helpers and attack simulation scripts
└── main.py         # FastAPI app entry point
```

---

## Services

### IDPS (`services/idps/`)
The core intrusion detection pipeline. Ingests network traffic, extracts 42+ flow features, and runs them through a three-stage detection funnel: Rule Engine → XGBoost → BiLSTM. See `services/idps/training/README.md` for ML details.

### Steganalysis (`services/steg/`)
Detects hidden data embedded in images and video files using entropy and statistical analysis.

### Honeypot (`services/honeypot/`)
Logs all interactions with decoy services. Records credentials, TTPs, and maps behaviour to MITRE ATT&CK.

### Correlation (`services/correlation/`)
Links events across IDPS, Honeypot, and Steg pipelines to identify multi-stage attack campaigns.

---

## Getting Started

### Prerequisites
- Python 3.9+
- SQLite (default) or PostgreSQL

### Installation
```bash
pip install -r requirements.txt
python -m backend.db.init_db
```

### Running the App
```bash
uvicorn backend.main:app --reload
```

---

## Key Patterns

### Repository Pattern
All database access goes through repositories in `backend/db/repositories/`. Services and routes never write raw SQLAlchemy queries directly.

### Async Pipeline
FastAPI handles I/O asynchronously. CPU-intensive tasks (ML inference, feature extraction) are offloaded to a background thread pool via `ProcessingQueue` in `core/processing_queue.py`.

### Alert Bus
Inter-service communication uses an internal async pub/sub bus. When IDPS detects a threat, it publishes an alert that the Response and WebSocket layers subscribe to — no tight coupling between services.

### Real-time Dashboard
Live events are streamed via WebSocket at `/ws/live`. The `WSManager` in `api/websocket/` handles connection management and broadcasts to all connected dashboard clients.

---

## API Routes

| Prefix | File | Description |
|---|---|---|
| `/api/idps` | `routes/idps.py` | IDPS detections, alerts, model status |
| `/api/honeypot` | `routes/honeypot.py` | Honeypot interaction logs |
| `/api/steg` | `routes/steg.py` | Steganography scan results |
| `/api/dashboard` | `routes/dashboard.py` | Aggregated stats for the UI |
| `/ws/live` | `websocket/ws_manager.py` | Real-time event stream |

---

## Database

ShieldNet uses SQLAlchemy ORM with SQLite by default (`backend/db/shieldnet.db`). Switch to PostgreSQL by updating the `DATABASE_URL` in `core/config.py`.

Migrations are managed via Alembic (scripts in `db/migrations/`). To apply:
```bash
alembic upgrade head
```
