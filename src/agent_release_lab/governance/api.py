"""Authenticated local HTTP endpoints for deterministic governance."""

from functools import lru_cache
from pathlib import Path
from typing import Annotated

import yaml
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ..api import _json_body
from ..identity import Digest, Identifier
from ..registry import Registry
from .models import (
    Activation, ApprovalRequest, AssessmentRequest, Bootstrap, EvidenceReport, LocalTrust, OwnershipAssignment,
)
from .policy import Policy
from .service import Governance, GovernanceInputError, Unauthorized


def configure_governance_routes(app: FastAPI, database_path: Path, trust: LocalTrust):
    @lru_cache(maxsize=1)
    def service() -> Governance:
        return Governance(Registry(database_path), trust)

    bearer = HTTPBearer(auto_error=False)

    def auth(credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]) -> str:
        try:
            if credentials is not None:
                return service().authenticate(credentials.credentials)
        except Unauthorized:
            pass
        raise HTTPException(401, "Valid bearer credential required", headers={"WWW-Authenticate": "Bearer"})

    actor = Depends(auth)

    @app.exception_handler(Unauthorized)
    async def forbidden(_request: Request, error: Unauthorized) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(error)})

    @app.exception_handler(GovernanceInputError)
    async def invalid(_request: Request, error: GovernanceInputError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(error)})

    async def yaml_policy(request: Request) -> Policy:
        content_type = request.headers.get("content-type", "").partition(";")[0].strip().lower()
        if content_type != "application/yaml":
            raise HTTPException(415, "Expected application/yaml")
        data = bytearray()
        async for chunk in request.stream():
            if len(data) + len(chunk) > 262144:
                raise HTTPException(413, "Policy exceeds 256 KiB")
            data.extend(chunk)
        try:
            return Policy.from_yaml(data.decode("utf-8"))
        except (ValueError, yaml.YAMLError, RecursionError) as error:
            raise HTTPException(422, "Invalid YAML policy") from error

    @app.post("/v1/governance/policies")
    def register_policy(policy: Annotated[Policy, Depends(yaml_policy)], actor_id: str = actor):
        return {"fingerprint": service().register_policy(actor_id, policy)}

    @app.get("/v1/governance/policies/{fingerprint}", dependencies=[actor])
    def get_policy(fingerprint: Digest):
        return {"fingerprint": fingerprint, "record": service().get_policy(fingerprint).model_dump(mode="json")}

    @app.put("/v1/governance/agents/{agent_id}/active-policy")
    def activate(agent_id: Identifier, request: Annotated[Activation, Depends(_json_body(Activation))],
                 actor_id: str = actor):
        return service().activate(actor_id, agent_id, request)

    @app.get("/v1/governance/agents/{agent_id}/active-policy")
    def active(agent_id: Identifier, actor_id: str = actor):
        return service().active(actor_id, agent_id)

    @app.put("/v1/governance/agents/{agent_id}/owner")
    def assign_owner(agent_id: Identifier,
                     request: Annotated[OwnershipAssignment, Depends(_json_body(OwnershipAssignment))],
                     actor_id: str = actor):
        return service().assign_owner(actor_id, agent_id, request)

    @app.get("/v1/governance/agents/{agent_id}/owner")
    def owner(agent_id: Identifier, actor_id: str = actor):
        return service().owner(actor_id, agent_id)

    @app.post("/v1/governance/agents/{agent_id}/bootstrap")
    def bootstrap(agent_id: Identifier, request: Annotated[Bootstrap, Depends(_json_body(Bootstrap))],
                  actor_id: str = actor):
        return service().bootstrap(actor_id, agent_id, request)

    @app.post("/v1/governance/evidence-reports")
    def report(request: Annotated[EvidenceReport, Depends(_json_body(EvidenceReport))]):
        return service().report_evidence(request)

    @app.post("/v1/governance/assessments")
    def assess(request: Annotated[AssessmentRequest, Depends(_json_body(AssessmentRequest))], actor_id: str = actor):
        return service().assess(actor_id, request)

    @app.get("/v1/governance/assessments/{assessment_id}")
    def get_assessment(assessment_id: Identifier, actor_id: str = actor):
        return service().get_assessment(actor_id, assessment_id)

    @app.post("/v1/governance/assessments/{assessment_id}/decisions")
    def decide(assessment_id: Identifier, request: Annotated[ApprovalRequest, Depends(_json_body(ApprovalRequest))],
               actor_id: str = actor):
        result = service().decide(actor_id, assessment_id, request)
        if result["authorization"] == "stale":
            return JSONResponse(status_code=409, content=result)
        return result

    @app.get("/v1/governance/agents/{agent_id}/audit")
    def audit(agent_id: Identifier, actor_id: str = actor, after_id: Annotated[int, Query(ge=0)] = 0):
        return {"events": service().audit(actor_id, agent_id, after_id)}

    return service, actor
