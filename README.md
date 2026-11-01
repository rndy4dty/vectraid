# VECTRAID

**Connecting Threat Intelligence. Uncovering Attack Relationships.**

Unified Threat Intelligence & Investigation Platform.

## Quick Start

1. cd backend
2. python3.12 -m venv .venv
3. source .venv/bin/activate
4. pip install -e ".[dev]"
5. cd ..
6. make test
7. make backend-dev

## Database

VECTRAID uses PostgreSQL for persistence (Phase 11a+).

    docker compose up -d postgres
    cd backend && source .venv/bin/activate && alembic upgrade head
    docker exec -it vectraid-postgres psql -U vectraid -d vectraid -c "CREATE DATABASE vectraid_test;"

## Structure

- backend/  : Python Core Engine, modules, API
- frontend/ : Next.js dashboard
- datasets/ : Test datasets + expected results
- docs/     : Architecture, phases, API, DB
- infrastructure/ : Docker, Postgres, (Neo4j)
- scripts/  : Developer utilities

## Phase Progress

- [x] Phase 0 - Repository scaffold
- [x] Phase 1 - Core Engine
- [x] Phase 2 - IntelFusion
- [x] Phase 3 - PhishTrace
- [x] Phase 4 - MalTrace
- [x] Phase 5 - HuntScope
- [x] Phase 6 - ThreatGraph
- [x] Phase 7 - Central Investigation Engine
- [x] Phase 8 - Case Management
- [x] Phase 9 - Backend API
- [x] Phase 10 - Frontend Dashboard
- [x] Phase 11a - PostgreSQL persistence
- [ ] Phase 11b - PDF Report
- [ ] Phase 11c - Docker Compose full stack
- [ ] Phase 12 - Testing & Release
