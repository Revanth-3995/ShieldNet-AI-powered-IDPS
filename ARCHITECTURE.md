# ShieldNet Backend Architecture

---

## Design Principles

1. **Separation of Concerns** — API, logic, and data layers are strictly separated. Routes never touch the database directly; services never write HTTP responses.
2. **Domain-Driven Design** — Logic is organized into self-contained domains (IDPS, Steg, Honeypot, Correlation). Each domain owns its models, repositories, and service layer.
3. **Async-First** — All I/O is async. CPU-bound work is offloaded to a thread pool so the event loop is never blocked.
4. **Pluggable AI** — New models (new architectures, new datasets) slot in by implementing the `BaseModel` interface in `models/inference/base_model.py`.

---

## Component Responsibilities

### Core (`backend/core/`)
- **Config** (`config.py`): Environment variable loading with Pydantic validation. Single source of truth for all settings.
- **Logging** (`logging.py`): Structured logging with file and console handlers. Use `get_logger("shieldnet.<module>")` everywhere.
- **Exceptions** (`exceptions.py`): Centralized exception hierarchy. FastAPI middleware converts domain exceptions to HTTP responses.
- **Processing Queue** (`processing_queue.py`): Thread pool wrapper for CPU-bound tasks. Keeps the async event loop unblocked during ML inference.

### Services (`backend/services/`)
- **IDPS**: Traffic capture → feature extraction → 3-stage detection funnel → automated response.
- **Steganalysis**: Statistical detection of hidden payloads in images and video.
- **Honeypot**: Decoy service interaction logging with MITRE ATT&CK mapping.
- **Correlation**: Cross-pipeline event linking to surface complex multi-stage campaigns.

### API (`backend/api/`)
- **Routes**: Domain-specific REST endpoints. Thin layer — validation only, delegates to services.
- **WebSocket** (`ws_manager.py`): Manages live connections and broadcasts detection events to the dashboard.
- **Router** (`router.py`): Assembles all sub-routers into the main FastAPI app.

### Database (`backend/db/`)
- **Models** (`models.py`): SQLAlchemy ORM definitions for all persisted entities.
- **Repositories** (`repositories/`): CRUD abstraction layer. All DB access goes here — never in services or routes.
- **Migrations** (`migrations/`): Alembic migration scripts for schema versioning.

---

## IDPS Internal Architecture

```
Traffic In (Scapy / Proxy)
        │
        ▼
┌───────────────────┐
│   traffic_stream  │  Raw packet ingestion
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│  flow_generator   │  Aggregates packets into 5-tuple bidirectional flows
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│  feature_schema    │  Extracts 42+ features (entropy, IAT, volume, ratios)
└────────┬──────────┘
         │
    ┌────┴─────────────────────────┐
    ▼                              ▼
┌──────────────┐         ┌──────────────────┐
│  rule_engine │         │  attack_classifier│
│ (fast path)  │         │  XGBoost + BiLSTM │
└──────┬───────┘         └────────┬─────────┘
       │                          │
       └──────────┬───────────────┘
                  ▼
         ┌─────────────────┐
         │  Fusion Engine  │  Consensus weighting
         └────────┬────────┘
                  ▼
         ┌─────────────────┐
         │response_manager │  Block / Quarantine / Watchlist
         └────────┬────────┘
                  ▼
         ┌─────────────────┐
         │   alert_bus     │  Pub/sub to WebSocket + DB
         └─────────────────┘
```

---

## Data Flow (End to End)

1. **Ingest**: Traffic enters via the proxy (`attack_proxy.py`) or live capture (`traffic_stream.py`).
2. **Fast Path**: `RuleEngine` checks for deterministic signatures (SQLi, SYN flood, PPS violations). High-confidence hits skip ML entirely.
3. **Flow Build**: `FlowGenerator` aggregates packets by 5-tuple key. At trigger threshold, flows are passed to feature extraction.
4. **Feature Extraction**: `FlowFeatures` computes 42+ statistical parameters per flow.
5. **ML Inference**: `AttackClassifier` runs XGBoost (behavioral) and BiLSTM (temporal) and fuses scores.
6. **Response**: `ResponseManager` applies block/quarantine/watchlist based on fused confidence and severity thresholds.
7. **Persistence**: Repository saves the detection event to the database.
8. **Notification**: `AlertBus` publishes the event to all internal subscribers.
9. **Broadcast**: `WSManager` streams the event to the live dashboard in real time.

---

## Async Model

ShieldNet uses a hybrid async/sync approach:

- **FastAPI** handles all I/O asynchronously (routes, WebSocket, DB queries via async SQLAlchemy).
- **CPU-bound tasks** (ML inference, feature extraction) run in a `ThreadPoolExecutor` managed by `ProcessingQueue`.
- **Inter-service events** use the `AlertBus`, an internal async pub/sub that decouples detection from response and notification.

This design allows the system to handle high-frequency traffic without the event loop ever blocking on ML inference.
