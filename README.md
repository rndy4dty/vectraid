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

## Structure

- backend/  : Python Core Engine, modules, API
- frontend/ : Next.js dashboard
- datasets/ : Test datasets + expected results
- docs/     : Architecture, phases, API, DB
- infrastructure/ : Docker, Postgres, (Neo4j)
- scripts/  : Developer utilities

## Phase Progress

- [x] Phase 0 — Repository scaffold
- [ ] Phase 1 — Core Engine
- [ ] Phase 2 — IntelFusion
- [ ] Phase 3 — PhishTrace
- [ ] Phase 4 — MalTrace
- [ ] Phase 5 — HuntScope
- [ ] Phase 6 — ThreatGraph
- [ ] Phase 7 — Central Investigation Engine
- [ ] Phase 8 — Case Management
- [ ] Phase 9 — Backend API
- [ ] Phase 10 — Frontend Dashboard
- [ ] Phase 11 — Reporting & Integration
- [ ] Phase 12 — Testing & Release
