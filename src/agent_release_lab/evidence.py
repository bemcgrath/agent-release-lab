"""Independent evaluation suites and evidence bound to deployment and suite."""

import re
from datetime import datetime, timezone
from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, JsonValue, StringConstraints, field_validator

from .identity import Digest, Identifier, Record, Revision, canonical_json, sha256
from .manifests import Pin


class Dataset(Record):
    id: Identifier
    revision: Revision
    digest: Digest


class EvaluationSuite(Record):
    id: Identifier
    revision: Revision
    checks: dict[Identifier, Revision] = Field(min_length=1)
    dataset: Dataset
    runner: Pin
    scoring: dict[Identifier, JsonValue]
    thresholds: dict[Identifier, JsonValue]

    @field_validator("scoring", "thresholds")
    @classmethod
    def validate_settings(cls, settings: dict) -> dict:
        canonical_json(settings)
        return settings

    @property
    def fingerprint(self) -> str:
        return sha256(self.canonical_bytes())


class Evidence(Record):
    id: Identifier
    candidate_fingerprint: Digest
    suite_fingerprint: Digest
    check_id: Identifier
    check_revision: Revision
    dataset: Dataset
    runner: Pin
    executed_at: AwareDatetime
    result: Literal["passed", "failed", "error"]
    artifact_digest: Digest
    producer: Identifier
    source: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]

    @field_validator("executed_at", mode="before")
    @classmethod
    def require_explicit_offset(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        if not re.search(r"(?:[zZ]|[+-][0-9]{2}:?[0-9]{2})\Z", value):
            raise ValueError("Evidence timestamp requires an explicit UTC offset")
        if value.endswith("z"):
            value = value[:-1] + "Z"
        return datetime.fromisoformat(value)

    @field_validator("executed_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        return value.astimezone(timezone.utc)


class EvidenceMismatch(ValueError):
    """Evidence does not match the identity or artifact supplied for verification."""


def verify_evidence(
    evidence: Evidence, *, candidate_fingerprint: str, suite: EvaluationSuite, artifact: bytes
) -> None:
    if evidence.candidate_fingerprint != candidate_fingerprint:
        raise EvidenceMismatch("Evidence belongs to another candidate")
    if evidence.suite_fingerprint != suite.fingerprint:
        raise EvidenceMismatch("Evidence belongs to another suite revision")
    if suite.checks.get(evidence.check_id) != evidence.check_revision:
        raise EvidenceMismatch("Evidence does not match a check revision in the suite")
    if evidence.dataset != suite.dataset or evidence.runner != suite.runner:
        raise EvidenceMismatch("Evidence dataset or runner differs from the suite")
    if sha256(artifact) != evidence.artifact_digest:
        raise EvidenceMismatch("Evidence artifact digest mismatch")
