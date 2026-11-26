from os import environ
from pathlib import Path

from fastapi import FastAPI

from .api import configure_registry_routes
from .dashboard import configure_dashboard
from .governance.api import configure_governance_routes
from .governance.models import LocalTrust


def create_app(database_path: str | Path | None = None, *, trust: LocalTrust | None = None) -> FastAPI:
    app = FastAPI(title="Agent Release Lab")
    path = database_path if database_path is not None else environ.get(
        "AGENT_RELEASE_LAB_DB", "agent-release-lab.sqlite3"
    )
    database = Path(path).resolve()
    trust_path = environ.get("AGENT_RELEASE_LAB_TRUST")
    if trust is None:
        trust = LocalTrust.from_json(Path(trust_path).read_bytes()) if trust_path else LocalTrust()
    configure_registry_routes(app, database)
    governance, actor = configure_governance_routes(app, database, trust)
    configure_dashboard(app, governance, actor)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
