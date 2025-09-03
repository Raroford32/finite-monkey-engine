# Defense Agent (authorization-only)

This project provides a modular, agentic auditing engine designed for defensive analysis only.

- Authorization required; works on user-provided artifacts.
- Simulation-only; no mainnet writes or exploit PoCs.
- Modular plugin registry, orchestrator (Planner/Explorer/Verifier/Economist/Judge/Reporter).

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
uvicorn defense_agent.app.server:app --reload --port 8080
```

## Endpoints
- POST /analyze: start an authorized analysis job
- GET  /registry: list capabilities

## Safety
- Scope gating, egress allowlist, immutable audit trail.
- Reports include mitigations, not exploit details.
