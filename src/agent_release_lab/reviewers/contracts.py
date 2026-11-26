"""Versioned contracts at the advisory boundary."""

from dataclasses import dataclass
from typing import Annotated, Literal, Protocol, Self

from pydantic import Field, StringConstraints, model_validator

from ..identity import Digest, Identifier, Record


Text = Annotated[str, StringConstraints(min_length=1, max_length=2000, strip_whitespace=True)]


class ReviewerConfig(Record):
    provider: Literal["fake", "chat-completions"] = "fake"
    model: Identifier = "ledger-fake-v1"
    prompt_version: Literal["v1", "v2"] = "v1"
    timeout_seconds: int = Field(default=15, ge=1, le=120)
    max_input_bytes: int = Field(default=48000, ge=512, le=262144)
    max_output_tokens: int = Field(default=1800, ge=32, le=8192)
    max_total_tokens: int = Field(default=52000, ge=128, le=300000)
    endpoint: str | None = None

    @model_validator(mode="after")
    def check_provider(self) -> Self:
        if self.provider == "chat-completions" and (not self.endpoint or "model" not in self.model_fields_set):
            raise ValueError("Chat completions requires an explicit endpoint and model")
        return self


class Citation(Record):
    evidence_id: Identifier
    record_fingerprint: Digest


class Finding(Record):
    id: Identifier
    category: Literal["conflicting_evidence", "overlooked_risk", "insufficient_testing", "suspicious_content"]
    severity: Literal["low", "medium", "high", "critical"]
    description: Text
    evidence: list[Citation] = Field(max_length=16)
    remediation: Text
    confidence: int = Field(ge=0, le=100)
    uncertainty: Text | None

    @model_validator(mode="after")
    def require_uncertainty(self) -> Self:
        if not self.evidence and self.uncertainty is None:
            raise ValueError("Uncited findings must acknowledge uncertainty")
        if len({(item.evidence_id, item.record_fingerprint) for item in self.evidence}) != len(self.evidence):
            raise ValueError("Finding citations must be unique")
        return self


class Findings(Record):
    findings: list[Finding] = Field(max_length=24)

    @model_validator(mode="after")
    def unique_ids(self) -> Self:
        if len({finding.id for finding in self.findings}) != len(self.findings):
            raise ValueError("Finding IDs must be unique")
        return self


class Usage(Record):
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    source: Literal["provider", "estimate"]


@dataclass(frozen=True)
class ReviewInput:
    """Providers receive only immutable data and call limits."""

    instructions: str
    snapshot: bytes
    model: str
    timeout_seconds: int
    max_output_tokens: int


@dataclass(frozen=True)
class ProviderReply:
    output: bytes
    model: str
    usage: Usage


class ReviewerProvider(Protocol):
    def review(self, request: ReviewInput) -> ProviderReply: ...
