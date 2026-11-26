"""Contracts for deterministic governance inputs and local authorization."""

import hmac
from typing import Literal, Self

from pydantic import Field, model_validator

from ..comparison import ManifestMetadata
from ..evidence import Evidence
from ..identity import Digest, Identifier, Record, canonical_json, sha256
from ..manifests import OperatingBoundaries


Tier = Literal["low", "moderate", "high"]
TIERS: tuple[Tier, ...] = ("low", "moderate", "high")
ApprovalRole = Literal["release", "security"]
Role = Literal["policy_admin", "submitter", "release", "security"]
DIMENSIONS = {
    "capabilities": ("read", "write", "external"),
    "effective_permissions": ("read_only", "bounded_write", "external_egress", "external_egress_write"),
    "data_exposure": ("synthetic", "sensitive"),
    "autonomy": ("supervised", "bounded", "autonomous"),
    "reversibility": ("reversible", "irreversible"),
    "impact": ("low", "moderate", "high"),
}


class RuntimeProfile(Record):
    capabilities: Literal["read", "write", "external"]
    effective_permissions: Literal["read_only", "bounded_write", "external_egress", "external_egress_write"]
    data_exposure: Literal["synthetic", "sensitive"]
    autonomy: Literal["supervised", "bounded", "autonomous"]
    reversibility: Literal["reversible", "irreversible"]
    impact: Tier


class RuntimeStatement(Record):
    candidate_fingerprint: Digest
    verifier: Identifier
    verified_at: str
    enforced_boundaries: OperatingBoundaries
    profile: RuntimeProfile


class RuntimeAttestation(Record):
    statement: RuntimeStatement
    signature: Digest


class EvidenceReference(Record):
    evidence_id: Identifier
    record_fingerprint: Digest


class EvidenceProof(EvidenceReference):
    signature: Digest


class EvidenceReport(EvidenceProof):
    supersedes: EvidenceReference | None = None


class OwnershipAssignment(Record):
    owner_id: Identifier
    rationale: str = Field(min_length=1, max_length=2000, pattern=r"\S")


class Bootstrap(Record):
    candidate_fingerprint: Digest
    rationale: str = Field(min_length=1, max_length=2000, pattern=r"\S")


class AssessmentRequest(Record):
    candidate_fingerprint: Digest
    runtime: RuntimeAttestation | None = None
    evidence: list[EvidenceProof] = Field(default_factory=list, max_length=128)
    metadata: ManifestMetadata | None = None

    @model_validator(mode="after")
    def unique_evidence(self) -> Self:
        if len({proof.evidence_id for proof in self.evidence}) != len(self.evidence):
            raise ValueError("Evidence IDs must be unique")
        return self


class Activation(Record):
    baseline_fingerprint: Digest
    policy_fingerprint: Digest
    baseline_metadata: ManifestMetadata = Field(default_factory=ManifestMetadata)


class ApprovalRequest(Record):
    role: ApprovalRole
    decision: Literal["approve", "decline"]
    rationale: str = Field(min_length=1, max_length=2000, pattern=r"\S")


class Actor(Record):
    id: Identifier
    token_digest: Digest
    grants: dict[Role, list[Identifier]]

    def has(self, role: Role, agent_id: str) -> bool:
        return agent_id in self.grants.get(role, [])


class LocalTrust(Record):
    actors: list[Actor] = Field(default_factory=list)
    producer_keys: dict[Identifier, Digest] = Field(default_factory=dict)
    runtime_keys: dict[Identifier, Digest] = Field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        # This is the only value persisted. Raw credentials and the preimage stay local.
        return sha256(canonical_json({
            "domain": "agent-release-lab/trust/v1",
            "actors": [
                {
                    "id": actor.id, "token_digest": actor.token_digest,
                    "grants": {role: sorted(set(agents)) for role, agents in actor.grants.items()},
                }
                for actor in sorted(self.actors, key=lambda item: item.id)
            ],
            "producer_keys": {name: sha256(bytes.fromhex(key)) for name, key in self.producer_keys.items()},
            "runtime_keys": {name: sha256(bytes.fromhex(key)) for name, key in self.runtime_keys.items()},
        }))

    @model_validator(mode="after")
    def unique_credentials(self) -> Self:
        if any(len({getattr(actor, field) for actor in self.actors}) != len(self.actors)
               for field in ("id", "token_digest")):
            raise ValueError("Actor IDs and token digests must be unique")
        keys = [*self.producer_keys.values(), *self.runtime_keys.values()]
        if len(set(keys)) != len(keys):
            raise ValueError("Producer and runtime keys must be distinct")
        return self


def evidence_signature_payload(record: Evidence) -> bytes:
    return canonical_json({
        "domain": "agent-release-lab/evidence/v1",
        "record_fingerprint": record.fingerprint,
    })


def rerun_signature_payload(record: Evidence, predecessor: EvidenceReference) -> bytes:
    return canonical_json({
        "domain": "agent-release-lab/evidence-rerun/v1",
        "record_fingerprint": record.fingerprint,
        "supersedes": predecessor.model_dump(mode="json"),
    })


def runtime_signature_payload(statement: RuntimeStatement) -> bytes:
    return canonical_json({
        "domain": "agent-release-lab/runtime/v1",
        "statement": statement.model_dump(mode="json"),
    })


def signature_matches(
    key_hex: str | None, expected_key_digest: str | None, message: bytes, signature: str
) -> bool:
    if key_hex is None or expected_key_digest is None:
        return False
    key = bytes.fromhex(key_hex)
    return hmac.compare_digest(sha256(key), expected_key_digest) and hmac.compare_digest(
        hmac.digest(key, message, "sha256").hex(), signature
    )
