# ShieldNet Backend Architecture

## Design Principles
1. **Separation of Concerns**: API, Logic, and Data layers are strictly separated.
2. **Domain-Driven Design**: Logic is organized into domain-specific services (IDPS, Steg, etc.).
3. **Async-First**: Heavy analysis and reporting use asynchronous patterns and internal event buses.
4. **Scalability**: Designed to easily plug in new AI models and multi-modal pipelines.

## Component Responsibilities

### Core (`backend/core/`)
- **Config**: Sourced from environment variables with pydantic-style validation.
- **Logging**: Structured logging with file and console handlers.
- **Exceptions**: Centralized exception hierarchy and FastAPI middleware.
- **Processing Queue**: In-memory queue for CPU-bound analysis tasks.

### Services (`backend/services/`)
- **IDPS**: Network traffic analysis and intrusion detection.
- **Steganalysis**: Detection of hidden data in images and video.
- **Honeypot**: Interaction logging for decoy services.
- **Correlation**: Linkage of events from multiple pipelines to identify complex attacks.
- **Response**: Automated actions like IP blocking and live notifications.

### API (`backend/api/`)
- **Routes**: Domain-specific REST endpoints.
- **WebSocket**: Real-time event streaming.
- **Router**: Unified assembly of all sub-routers.

### Database (`backend/db/`)
- **Models**: SQLAlchemy ORM definitions.
- **Repositories**: CRUD abstraction layer.
- **Migrations**: Placeholder for Alembic migration scripts.

## Data Flow
1. **Ingest**: Traffic/Media enters via Proxy or API.
2. **Detection**: Service logic analyzes data (mock or ML-based).
3. **Persistence**: `Repository` saves results to the database.
4. **Notification**: `AlertBus` publishes event to internal subscribers.
5. **Broadcast**: `WSManager` streams event to live dashboard.
6. **Response**: If severity is high, `Blocker` may trigger an automated IP block.

## Async Pipeline
ShieldNet uses a hybrid async/sync approach. FastAPI handles I/O asynchronously, while CPU-intensive tasks are offloaded to a background thread pool managed by `ProcessingQueue`. Inter-service communication is handled by the `AlertBus` (async pub/sub).
