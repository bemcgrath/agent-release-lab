"""Strict JSON intake and canonical encoding for version 1 records."""

import hashlib
import json
from typing import Annotated, Self

from pydantic import AfterValidator, BaseModel, ConfigDict, StringConstraints


Identifier = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,127}$")]
Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


def _reject_alias(value: str) -> str:
    reference = value.casefold().rsplit(":", 1)[-1]
    if reference in {"latest", "stable", "default", "main", "head"} or reference.startswith(
        ("refs/heads/", "refs/remotes/")
    ):
        raise ValueError("Resolve mutable aliases and branch references before registration")
    return value


Revision = Annotated[Identifier, AfterValidator(_reject_alias)]


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_number(value: str) -> None:
    raise ValueError(f"Use an integer or a decimal string instead of {value}")


def _reject_float(value: object) -> None:
    if isinstance(value, float):
        _reject_number(str(value))
    elif isinstance(value, dict):
        for item in value.values():
            _reject_float(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_float(item)


def canonical_json(value: object) -> bytes:
    _reject_float(value)
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, revalidate_instances="always")

    @classmethod
    def from_json(cls, raw: str | bytes) -> Self:
        parsed = json.loads(
            raw, object_pairs_hook=_unique_object,
            parse_float=_reject_number, parse_constant=_reject_number,
        )
        return cls.model_validate_json(canonical_json(parsed))

    def canonical_bytes(self) -> bytes:
        return canonical_json(self.model_dump(mode="json"))
