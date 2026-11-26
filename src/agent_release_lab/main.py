from os import environ
from pathlib import Path

from fastapi import FastAPI

from .api import configure_registry_routes


def create_app(database_path: str | Path | None = None) -> FastAPI:
    app = FastAPI(title="Agent Release Lab")
    path = database_path if database_path is not None else environ.get(
        "AGENT_RELEASE_LAB_DB", "agent-release-lab.sqlite3"
    )
    configure_registry_routes(app, Path(path).resolve())

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
