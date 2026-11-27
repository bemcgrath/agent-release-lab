"""Local dashboard and scoped advisory endpoints."""

import json
from functools import lru_cache
from os import environ
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .api import _json_body
from .demo import Scenario, demo
from .identity import Identifier, Record
from .reviewers.contracts import ReviewerConfig
from .reviewers.providers import ChatCompletions, FakeReviewer
from .reviewers.service import AdvisoryStore
from .reviewers.snapshot import build_snapshot, hide_artifact


WEB = Path(__file__).with_name("web")


class ReviewRequest(Record):
    assessment_id: Identifier


def assessment_detail(governance, store, actor_id: str, assessment_id: str) -> dict:
    assessment = governance.get_assessment(actor_id, assessment_id)
    snapshot = json.loads(build_snapshot(governance, assessment))
    return {
        "assessment": assessment,
        "candidate": snapshot["candidate"],
        "changes": assessment.get("comparison"),
        "controls": snapshot["controls"],
        "evidence": [hide_artifact(item) for item in snapshot["evidence"]],
        "reviews": store.list(actor_id, assessment_id),
    }


def configure_dashboard(app: FastAPI, governance, actor) -> None:
    @lru_cache(maxsize=1)
    def store() -> AdvisoryStore:
        return AdvisoryStore(governance())

    @lru_cache(maxsize=1)
    def reviewer():
        path = environ.get("AGENT_RELEASE_LAB_REVIEWER_CONFIG")
        try:
            config = ReviewerConfig.from_json(Path(path).read_bytes()) if path else ReviewerConfig()
            provider = (
                FakeReviewer() if config.provider == "fake"
                else ChatCompletions(config.endpoint, environ.get("AGENT_RELEASE_LAB_REVIEWER_TOKEN"))
            )
        except (OSError, ValueError, RecursionError) as error:
            raise HTTPException(503, "Advisory reviewer configuration unavailable") from error
        return config, provider

    @app.get("/", include_in_schema=False)
    def dashboard():
        return FileResponse(WEB / "index.html", headers={
            "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
        })

    app.mount("/dashboard-assets", StaticFiles(directory=WEB), name="dashboard-assets")

    @app.get("/v1/dashboard/agents")
    def inventory(actor_id: str = actor):
        return {"agents": governance().inventory(actor_id)}

    @app.get("/v1/dashboard/agents/{agent_id}/releases")
    def history(agent_id: Identifier, actor_id: str = actor):
        return governance().release_history(actor_id, agent_id)

    @app.get("/v1/dashboard/assessments/{assessment_id}")
    def detail(assessment_id: Identifier, actor_id: str = actor):
        return assessment_detail(governance(), store(), actor_id, assessment_id)

    @app.post("/v1/advisory/reviews")
    def run(request: Annotated[ReviewRequest, Depends(_json_body(ReviewRequest))], actor_id: str = actor):
        config, provider = reviewer()
        return store().run(actor_id, request.assessment_id, config, provider)

    @app.get("/v1/advisory/reviews")
    def reviews(assessment_id: Identifier, actor_id: str = actor):
        return {"reviews": store().list(actor_id, assessment_id)}

    @app.get("/v1/advisory/reviews/{review_id}")
    def get_review(review_id: Identifier, actor_id: str = actor):
        return store().get(actor_id, review_id)

    @app.get("/v1/demo/ledger-finch/{scenario}")
    def ledger_demo(scenario: Scenario):
        return demo(scenario, assessment_detail)
