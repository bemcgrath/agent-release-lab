"""Strict YAML governance policy and deterministic rule contracts."""

import re
from typing import Literal, Self

import yaml
from pydantic import Field
from pydantic import model_validator

from ..comparison import Category
from ..identity import Digest, Identifier, Record, Revision, VersionedRecord, sha256
from .models import ApprovalRole, DIMENSIONS, TIERS, Tier


class PolicyLoader(yaml.SafeLoader):
    """YAML collections and JSON-style scalars without aliases or custom tags."""

    yaml_implicit_resolvers = {}

    def compose_node(self, parent, index):
        event = self.peek_event()
        if isinstance(event, yaml.AliasEvent) or event.anchor is not None or event.tag is not None:
            raise ValueError("YAML aliases, anchors and explicit tags are unsupported")
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key == "<<" or key in result:
                raise ValueError("YAML mapping keys must be unique strings")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


PolicyLoader.add_implicit_resolver("tag:yaml.org,2002:int", re.compile(r"^(0|-?[1-9][0-9]*)$"), "-0123456789")
PolicyLoader.add_implicit_resolver("tag:yaml.org,2002:bool", re.compile(r"^(true|false)$"), "tf")
PolicyLoader.add_implicit_resolver("tag:yaml.org,2002:null", re.compile(r"^null$"), "n")


class Control(Record):
    check_id: Identifier
    accepted_suites: dict[Digest, Revision] = Field(min_length=1)
    max_age_seconds: int = Field(gt=0, le=31536000)
    producers: list[Identifier] = Field(min_length=1)


class Policy(VersionedRecord):
    schema_version: Literal[1]
    id: Identifier
    revision: Revision
    risk_rules: dict[str, dict[str, Tier]]
    producer_keys: dict[Identifier, Digest] = Field(min_length=1)
    runtime_verifier_keys: dict[Identifier, Digest] = Field(min_length=1)
    runtime_max_age_seconds: int = Field(gt=0, le=31536000)
    controls: dict[Identifier, Control] = Field(min_length=1)
    universal_controls: list[Identifier] = Field(min_length=1)
    tier_controls: dict[Tier, list[Identifier]]
    change_controls: dict[Category, list[Identifier]]
    tier_approval_roles: dict[Tier, list[ApprovalRole]]

    @classmethod
    def from_yaml(cls, raw: str) -> Self:
        return cls.model_validate(yaml.load(raw, Loader=PolicyLoader))

    @property
    def fingerprint(self) -> str:
        return sha256(self.canonical_bytes())

    @model_validator(mode="after")
    def check_policy(self) -> Self:
        if set(self.risk_rules) != set(DIMENSIONS) or any(
            set(self.risk_rules[name]) != set(values) for name, values in DIMENSIONS.items()
        ):
            raise ValueError("Risk rules must cover every input value in all six dimensions")

        minimum_tiers = {
            "capabilities": {"write": "moderate", "external": "high"},
            "effective_permissions": {
                "bounded_write": "moderate", "external_egress": "high", "external_egress_write": "high",
            },
            "data_exposure": {"sensitive": "high"},
            "autonomy": {"autonomous": "high"},
            "reversibility": {"irreversible": "high"},
            "impact": {"moderate": "moderate", "high": "high"},
        }
        for dimension, floors in minimum_tiers.items():
            if any(TIERS.index(self.risk_rules[dimension][value]) < TIERS.index(tier)
                   for value, tier in floors.items()):
                raise ValueError("Risk rules cannot lower mandatory risk floors")

        if set(self.tier_controls) != set(TIERS) or set(self.tier_approval_roles) != set(TIERS):
            raise ValueError("Controls and approval roles must cover all three tiers")
        if "release" not in self.tier_approval_roles["low"] or "security" not in self.tier_approval_roles["high"]:
            raise ValueError("All tiers require release approval and high risk requires security approval")
        references = [self.universal_controls, *self.tier_controls.values(), *self.change_controls.values()]
        if any(set(group) - self.controls.keys() for group in references):
            raise ValueError("Policy references an unknown control")
        if any(set(control.producers) - self.producer_keys.keys() for control in self.controls.values()):
            raise ValueError("Control references an unknown producer")
        return self

    def requirements(self, tier: Tier, categories: set[Category]) -> tuple[list[str], list[str]]:
        included_tiers = TIERS[:TIERS.index(tier) + 1]
        controls = set(self.universal_controls)
        roles = set()
        for included in included_tiers:
            controls.update(self.tier_controls[included])
            roles.update(self.tier_approval_roles[included])
        for category in categories:
            controls.update(self.change_controls.get(category, []))
        return sorted(controls), sorted(roles)
