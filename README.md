# Agent Release Lab

An open-source research project for evaluating how organizations govern and approve AI agent releases. The planned AI Release Approval Agent reviews fictional release candidates, checks supporting evidence, flags risks and recommends release readiness.

AI evaluates and recommends. Deterministic controls enforce. Authorized humans retain accountability.

## Implemented in Phase 0

- An installable Python 3.12 package with a local FastAPI service exposing `GET /health`.
- A smoke test and automated Python validation on Windows and Linux.
- Architecture and governance contracts, a research plan, and 22 labeled synthetic scenarios documented for future experiments.

## Planned capabilities

The [roadmap](docs/ROADMAP.md) covers manifest, suite and evidence registries, deterministic governance and human approval, AI-assisted review, a dashboard, and an experiment runner.

## Run locally on Windows

The tested Windows setup uses Python 3.12.10 with both the Git checkout and its virtual environment in a local folder outside OneDrive. Open PowerShell at the root of that checkout and confirm that `python --version` reports Python 3.12.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m uvicorn agent_release_lab.main:app
```

With the server running, open `http://127.0.0.1:8000/health` to check that it returns `{"status":"ok"}`. Press Ctrl+C in PowerShell to stop the server. Runtime needs no API credentials.

## Project documents

- [Product requirements](docs/PRODUCT_REQUIREMENTS.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Release manifest](docs/RELEASE_MANIFEST.md)
- [Governance policy](docs/GOVERNANCE_POLICY.md)
- [Evaluation strategy](docs/EVALUATION_STRATEGY.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Roadmap](docs/ROADMAP.md)
- [Decisions](docs/DECISIONS.md)

## License

Agent Release Lab is licensed under the [Apache License 2.0](LICENSE).
