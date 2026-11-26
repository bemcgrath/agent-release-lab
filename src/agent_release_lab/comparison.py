"""Classify changes against explicit baselines using the version 1 field mapping."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from .identity import Digest, Record, canonical_json
from .manifests import Manifest, Tool


Category = Literal["behavioral", "administrative", "security", "permission", "governance"]
CLASSIFICATION_VERSION = 1
TOOL_CATEGORIES: Mapping[str, tuple[Category, ...]] = {
    "interface": ("behavioral",),
    "executable": ("behavioral",),
    "configuration": ("behavioral",),
    "permissions": ("permission", "security"),
    "security": ("security",),
}


class ManifestMetadata(Record):
    label: str | None = None
    description: str | None = None


class GovernanceSnapshot(Record):
    policy_fingerprint: Digest
    accepted_suite_fingerprints: frozenset[Digest]
    approval_requirements_fingerprint: Digest


@dataclass(frozen=True)
class Change:
    field: str
    categories: tuple[Category, ...]
    before: object
    after: object


@dataclass(frozen=True)
class ManifestComparison:
    baseline_fingerprint: str
    candidate_fingerprint: str
    changes: tuple[Change, ...]
    classification_version: int = CLASSIFICATION_VERSION


def _diff(
    before: dict, after: dict, fields: Mapping[str, tuple[Category, ...]], prefix: str = ""
) -> list[Change]:
    return [
        Change(f"{prefix}{field}", categories, before.get(field), after.get(field))
        for field, categories in fields.items()
        if canonical_json(before.get(field)) != canonical_json(after.get(field))
    ]


def _compare_tools(before: dict[str, Tool], after: dict[str, Tool]) -> list[Change]:
    changes = []
    for key in sorted(before.keys() | after.keys()):
        previous = before.get(key)
        current = after.get(key)
        changes.extend(_diff(
            previous.model_dump(mode="json", exclude_defaults=True) if previous else {},
            current.model_dump(mode="json", exclude_defaults=True) if current else {},
            TOOL_CATEGORIES,
            prefix=f"components.tools/{key}/",
        ))
    return changes


def compare_manifests(
    baseline: Manifest,
    candidate: Manifest,
    *,
    baseline_metadata: ManifestMetadata | None = None,
    candidate_metadata: ManifestMetadata | None = None,
) -> ManifestComparison:
    if baseline.agent_id != candidate.agent_id:
        raise ValueError("Baseline and candidate must describe the same agent")
    if (baseline_metadata is None) != (candidate_metadata is None):
        raise ValueError("Supply both metadata records or neither")
    changes = _diff(
        baseline.model_dump(mode="json"), candidate.model_dump(mode="json"),
        {"runtime": ("behavioral",), "security": ("security",)},
    )
    component_fields: dict[str, tuple[Category, ...]] = {
        field: ("behavioral",) for field in ("model", "prompt", "harness", "business_rules")
    }
    changes.extend(_diff(
        baseline.components.model_dump(mode="json"), candidate.components.model_dump(mode="json"),
        component_fields, prefix="components.",
    ))
    changes.extend(_compare_tools(baseline.components.tools, candidate.components.tools))
    if baseline_metadata is not None and candidate_metadata is not None:
        changes.extend(_diff(
            baseline_metadata.model_dump(), candidate_metadata.model_dump(),
            {"label": ("administrative",), "description": ("administrative",)}, prefix="metadata.",
        ))
    return ManifestComparison(baseline.fingerprint, candidate.fingerprint, tuple(changes))


def compare_governance(baseline: GovernanceSnapshot, current: GovernanceSnapshot) -> tuple[Change, ...]:
    fields: dict[str, tuple[Category, ...]] = {
        "policy_fingerprint": ("governance",),
        "accepted_suite_fingerprints": ("governance",),
        "approval_requirements_fingerprint": ("governance",),
    }
    before = baseline.model_dump()
    after = current.model_dump()
    for values in (before, after):
        values["accepted_suite_fingerprints"] = sorted(values["accepted_suite_fingerprints"])
    return tuple(_diff(before, after, fields))
