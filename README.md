# Agent Release Lab

An open-source research project for evaluating how organizations govern and approve AI agent releases. The planned AI Release Approval Agent reviews fictional release candidates, checks supporting evidence, flags risks and recommends release readiness.

AI evaluates and recommends. Deterministic controls enforce. Authorized humans retain accountability.

## Implemented

- An installable Python 3.12 package with a local FastAPI service exposing `GET /health`.
- A smoke test and automated Python validation on Windows and Linux.
- Architecture and governance contracts, a research plan, and 22 labeled synthetic scenarios documented for future experiments.
- Python interfaces for strict manifest and evaluation suite registration, evidence binding and integrity checks, and classified release comparisons. The [release manifest contract](docs/RELEASE_MANIFEST.md) documents the interfaces.
- Local HTTP endpoints for the registries, release comparison, and evidence verification. See the [HTTP API](docs/API.md) for requests, responses, and database configuration.
- Deterministic eligibility, versioned policy registration, and scoped human decisions with transactional reassessment and audit history. See the [Governance API](docs/GOVERNANCE_API.md) for the local trust configuration.

## Planned capabilities

The [roadmap](docs/ROADMAP.md) covers AI-assisted review, a dashboard, and a comparative experiment runner.

## Run locally on Windows

The tested Windows setup uses Python 3.12.10 with both the Git checkout and its virtual environment in a local folder outside OneDrive. Open PowerShell at the root of that checkout and confirm that `python --version` reports Python 3.12.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m compileall -q src tests
.\.venv\Scripts\python.exe -m uvicorn agent_release_lab.main:app
```

With the server running, open `http://127.0.0.1:8000/health` to check that it returns `{"status":"ok"}`. Press Ctrl+C in PowerShell to stop the server. Runtime needs no API credentials.

## Project documents

- [Product requirements](docs/PRODUCT_REQUIREMENTS.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Release manifest](docs/RELEASE_MANIFEST.md)
- [HTTP API](docs/API.md)
- [Governance policy](docs/GOVERNANCE_POLICY.md)
- [Governance API](docs/GOVERNANCE_API.md)
- [Evaluation strategy](docs/EVALUATION_STRATEGY.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Roadmap](docs/ROADMAP.md)
- [Decisions](docs/DECISIONS.md)

## License

Agent Release Lab is licensed under the [Apache License 2.0](LICENSE).
