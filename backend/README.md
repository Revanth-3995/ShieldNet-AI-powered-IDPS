# ShieldNet Backend

Modular, AI-powered cybersecurity platform backend.

## Architecture Overview

The backend is built with FastAPI and follows a domain-driven modular structure:

- **`api/`**: HTTP and WebSocket entry points.
- **`core/`**: Infrastructure components (config, logging, exceptions).
- **`db/`**: Persistence layer with models, migrations, and repositories.
- **`services/`**: Domain logic (IDPS, Steganalysis, Honeypot, Correlation).
- **`schemas/`**: Pydantic models for data validation.
- **`utils/`**: Shared helpers and testing scripts.

## Getting Started

### Prerequisites
- Python 3.9+
- SQLite (default) or PostgreSQL

### Installation
1. `pip install -r requirements.txt`
2. `python -m backend.db.init_db` (to initialize database)

### Running the App
```bash
uvicorn backend.main:app --reload
```

## Repository Layer
ShieldNet uses the **Repository Pattern** to abstract database access. Services and API routes should use repositories located in `backend/db/repositories/` instead of direct SQLAlchemy queries.

## Real-time Monitoring
Live events are streamed via WebSockets at `/ws/live`. The `WSManager` in `backend/api/websocket/` handles connection management and broadcasts.
