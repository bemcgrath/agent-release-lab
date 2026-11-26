"""Local HTTP access to the Phase 1 registries."""

import binascii
from base64 import b64decode, b64encode
from collections.abc import Awaitable, Callable
from dataclasses import asdict
from functools import lru_cache
from pathlib import Path
from typing import Annotated, TypeVar

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from .comparison import ManifestMetadata, compare_manifests
from .evidence import EvaluationSuite, Evidence, EvidenceMismatch
from .identity import Digest, Identifier, Record
from .manifests import Manifest
from .registry import RecordConflict, RecordIntegrityError, RecordMissing, Registry


MAX_JSON_BYTES = 8 * 1024 * 1024
RecordType = TypeVar("RecordType", bound=Record)


class EvidenceSubmission(Record):
    record: Evidence
    artifact_base64: str


class VerificationRequest(Record):
    evidence_id: Identifier
    candidate_fingerprint: Digest
    suite_fingerprint: Digest
    expected_record_fingerprint: Digest


class ComparisonRequest(Record):
    baseline_fingerprint: Digest
    candidate_fingerprint: Digest
    baseline_metadata: ManifestMetadata | None = None
    candidate_metadata: ManifestMetadata | None = None


def _json_body(model: type[RecordType]) -> Callable[[Request], Awaitable[RecordType]]:
    async def parse(request: Request) -> RecordType:
        content_type = request.headers.get("content-type", "").partition(";")[0].strip().lower()
        if content_type != "application/json":
            raise HTTPException(415, "Expected application/json")
        data = bytearray()
        async for chunk in request.stream():
            if len(data) + len(chunk) > MAX_JSON_BYTES:
                raise HTTPException(413, "JSON body exceeds 8 MiB")
            data.extend(chunk)
        try:
            return model.from_json(data.decode("utf-8"))
        except ValueError as error:
            raise HTTPException(422, "Invalid JSON record") from error

    return parse


def configure_registry_routes(app: FastAPI, database_path: Path) -> None:
    @lru_cache(maxsize=1)
    def registry() -> Registry:
        return Registry(database_path)

    error_status: dict[type[Exception], int] = {
        RecordMissing: 404,
        RecordConflict: 409,
        RecordIntegrityError: 409,
        EvidenceMismatch: 422,
    }

    async def registry_error(_request: Request, error: Exception) -> JSONResponse:
        return JSONResponse(status_code=error_status[type(error)], content={"detail": str(error)})

    for error_type in error_status:
        app.add_exception_handler(error_type, registry_error)

    @app.post("/v1/manifests")
    def register_manifest(manifest: Annotated[Manifest, Depends(_json_body(Manifest))]):
        return {"fingerprint": registry().register_manifest(manifest)}

    @app.get("/v1/manifests/{fingerprint}")
    def get_manifest(fingerprint: Digest):
        manifest = registry().get_manifest(fingerprint)
        return {"fingerprint": fingerprint, "record": manifest.model_dump(mode="json")}

    @app.post("/v1/suites")
    def register_suite(suite: Annotated[EvaluationSuite, Depends(_json_body(EvaluationSuite))]):
        if suite.schema_version != 1:
            raise HTTPException(422, "Suite registration requires schema_version 1")
        return {"fingerprint": registry().register_suite(suite)}

    @app.get("/v1/suites/{fingerprint}")
    def get_suite(fingerprint: Digest):
        suite = registry().get_suite(fingerprint)
        return {"fingerprint": fingerprint, "record": suite.model_dump(mode="json")}

    @app.post("/v1/evidence")
    def register_evidence(submission: Annotated[EvidenceSubmission, Depends(_json_body(EvidenceSubmission))]):
        if "schema_version" not in submission.record.model_fields_set:
            raise HTTPException(422, "Evidence registration requires schema_version 1")
        try:
            artifact = b64decode(submission.artifact_base64, validate=True)
        except (ValueError, binascii.Error) as error:
            raise HTTPException(422, "Invalid base64 artifact") from error
        if b64encode(artifact).decode("ascii") != submission.artifact_base64:
            raise HTTPException(422, "Invalid base64 artifact")
        fingerprint = registry().register_evidence(submission.record, artifact)
        return {"id": submission.record.id, "fingerprint": fingerprint}

    @app.get("/v1/evidence/{evidence_id:path}")
    def get_evidence(evidence_id: Identifier):
        evidence, artifact = registry().get_evidence(evidence_id)
        return {
            "fingerprint": evidence.fingerprint,
            "record": evidence.model_dump(mode="json"),
            "artifact_base64": b64encode(artifact).decode("ascii"),
        }

    @app.post("/v1/comparisons")
    def compare(request: Annotated[ComparisonRequest, Depends(_json_body(ComparisonRequest))]):
        records = registry()
        baseline = records.get_manifest(request.baseline_fingerprint)
        candidate = records.get_manifest(request.candidate_fingerprint)
        try:
            result = compare_manifests(
                baseline, candidate,
                baseline_metadata=request.baseline_metadata, candidate_metadata=request.candidate_metadata,
            )
        except ValueError as error:
            raise HTTPException(422, str(error)) from error
        return asdict(result)

    @app.post("/v1/evidence-verifications")
    def verify(request: Annotated[VerificationRequest, Depends(_json_body(VerificationRequest))]):
        evidence, _ = registry().get_verified_evidence(
            request.evidence_id,
            candidate_fingerprint=request.candidate_fingerprint,
            suite_fingerprint=request.suite_fingerprint,
            expected_record_fingerprint=request.expected_record_fingerprint,
        )
        return {"verified": True, "fingerprint": evidence.fingerprint}
