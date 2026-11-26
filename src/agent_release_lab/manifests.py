"""Versioned deployment manifest contracts."""

from typing import Literal, Self

from pydantic import Field, JsonValue, field_validator, model_validator

from .identity import Digest, Identifier, Record, Revision, canonical_json, sha256


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


class Manifest(Record):
    schema_version: Literal[1]
    agent_id: Identifier
    components: Components
    runtime: dict[Identifier, JsonValue] = Field(default_factory=dict)
    security: dict[Identifier, JsonValue] = Field(default_factory=dict)

    @field_validator("schema_version", mode="before")
    @classmethod
    def check_version_type(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("schema_version must be an integer")
        return value

    @field_validator("runtime", "security")
    @classmethod
    def validate_settings(cls, settings: dict) -> dict:
        canonical_json(settings)
        return settings

    @property
    def fingerprint(self) -> str:
        return sha256(self.canonical_bytes())
