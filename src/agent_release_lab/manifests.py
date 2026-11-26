"""Versioned deployment manifest contracts."""

from typing import Literal, Self

from pydantic import (
    Field, JsonValue, SerializerFunctionWrapHandler, field_validator, model_serializer, model_validator,
)

from .identity import Digest, Identifier, Record, Revision, VersionedRecord, canonical_json, sha256


class Pin(Record):
    id: Identifier
    revision: Revision | None = None
    digest: Digest | None = None

    @model_validator(mode="after")
    def require_immutable_reference(self) -> Self:
        if self.revision is None and self.digest is None:
            raise ValueError("A pin requires an immutable revision or digest")
        return self


class Tool(Record):
    interface: Pin
    executable: Pin
    configuration: Pin
    permissions: dict[Identifier, JsonValue] = Field(default_factory=dict)
    security: dict[Identifier, JsonValue] = Field(default_factory=dict)

    @field_validator("permissions", "security")
    @classmethod
    def validate_settings(cls, settings: dict) -> dict:
        canonical_json(settings)
        return settings


class Components(Record):
    model: Pin
    prompt: Pin
    harness: Pin
    tools: dict[Identifier, Tool]
    business_rules: Pin


class OperatingBoundaries(Record):
    allowed_tools: list[Identifier]
    allowed_data_sources: list[Identifier]
    allowed_destinations: list[Identifier]
    can_write: bool


class AgentScope(Record):
    purpose: Identifier
    allowed_tasks: list[Identifier] = Field(min_length=1)
    boundaries: OperatingBoundaries


class Manifest(VersionedRecord):
    schema_version: Literal[1, 2]
    agent_id: Identifier
    components: Components
    runtime: dict[Identifier, JsonValue] = Field(default_factory=dict)
    security: dict[Identifier, JsonValue] = Field(default_factory=dict)
    scope: AgentScope | None = None

    @model_validator(mode="after")
    def check_scope(self) -> Self:
        if self.schema_version == 1 and "scope" in self.model_fields_set:
            raise ValueError("Scope requires manifest schema version 2")
        if self.schema_version == 2:
            if self.scope is None:
                raise ValueError("Manifest schema version 2 requires scope")
            if set(self.scope.boundaries.allowed_tools) - self.components.tools.keys():
                raise ValueError("Scope allows tools missing from the component map")
        return self

    @model_serializer(mode="wrap")
    def serialize_version(self, handler: SerializerFunctionWrapHandler) -> dict:
        payload = handler(self)
        if self.schema_version == 1:
            payload.pop("scope", None)
        return payload

    @field_validator("runtime", "security")
    @classmethod
    def validate_settings(cls, settings: dict) -> dict:
        canonical_json(settings)
        return settings

    @property
    def fingerprint(self) -> str:
        return sha256(self.canonical_bytes())
