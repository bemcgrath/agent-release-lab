import json
import sqlite3

import pytest
from pydantic import ValidationError

from agent_release_lab.comparison import (
    GovernanceSnapshot, ManifestMetadata, compare_governance, compare_manifests,
)
from agent_release_lab.evidence import EvaluationSuite, Evidence, EvidenceMismatch
from agent_release_lab.identity import sha256
from agent_release_lab.manifests import Manifest
from agent_release_lab.registry import RecordConflict, RecordMissing, Registry


def pin(name: str) -> dict:
    return {"id": name, "revision": "r1"}


@pytest.fixture
def manifest_data():
    return {
        "schema_version": 1,
        "agent_id": "ledger-finch",
        "components": {
            name: pin(identifier)
            for name, identifier in (
                ("model", "model"), ("prompt", "prompt"), ("harness", "harness"),
                ("business_rules", "rules")
            )
        } | {"tools": {}},
        "runtime": {"locale": "français"},
    }


@pytest.fixture
def suite_data():
    return {
        "id": "ledger-suite",
        "revision": "r1",
        "checks": {"regression": "r1"},
        "dataset": {"id": "ledger-cases", "revision": "r1", "digest": "1" * 64},
        "runner": pin("runner"),
        "scoring": {"mode": "exact"},
        "thresholds": {"minimum": "0.95"},
    }


def test_golden_fingerprints(manifest_data, suite_data):
    manifest = Manifest.model_validate(manifest_data)
    suite = EvaluationSuite.model_validate(suite_data)
    assert manifest.fingerprint == "2dac77d5f77fd0dfbc489a4bdc4985028c881bd611a539aa642079ae6f8cb0b7"
    assert suite.fingerprint == "49ab9c725ef7f83d7ec6f44b53b837453565b5f4cca1e4214637baf4255088f1"
    assert Manifest.from_json(json.dumps(manifest_data, indent=2, sort_keys=True)) == manifest
    assert EvaluationSuite.from_json(suite.canonical_bytes()) == suite


def test_strict_manifest_intake(manifest_data):
    raw = json.dumps(manifest_data)
    with pytest.raises(ValueError, match="Duplicate JSON key"):
        Manifest.from_json(raw.replace('"id": "model"', '"id": "model", "id": "other"'))
    for replacement in ('true', '1.0', '"1"'):
        with pytest.raises(ValueError):
            Manifest.from_json(raw.replace('"schema_version": 1', f'"schema_version": {replacement}'))
    for model in ({"id": "model"}, {"id": "model", "revision": "tag:latest"}, pin("model") | {"extra": 5}):
        manifest_data["components"]["model"] = model
        with pytest.raises(ValidationError):
            Manifest.model_validate(manifest_data)


@pytest.mark.parametrize("revision", ["refs/heads/main", "refs/heads/topic", "git:refs/remotes/origin/topic"])
def test_manifest_rejects_mutable_branch_pins(manifest_data, revision):
    manifest_data["components"]["model"]["revision"] = revision
    with pytest.raises(ValidationError, match="mutable"):
        Manifest.from_json(json.dumps(manifest_data))


@pytest.mark.parametrize("executed_at", ["1767225600", "2026-01-01T00:00:00"])
def test_evidence_timestamp_requires_explicit_offset(suite_data, executed_at):
    data = {
        "id": "ledger-run-001",
        "candidate_fingerprint": "a" * 64,
        "suite_fingerprint": "b" * 64,
        "check_id": "regression",
        "check_revision": "r1",
        "dataset": suite_data["dataset"],
        "runner": suite_data["runner"],
        "executed_at": executed_at,
        "result": "passed",
        "artifact_digest": "c" * 64,
        "producer": "synthetic-runner",
        "source": "Synthetic fixture",
    }
    with pytest.raises(ValidationError, match="explicit UTC offset"):
        Evidence.from_json(json.dumps(data))


@pytest.mark.parametrize("field", ["model", "prompt", "harness", "business_rules", "tools"])
def test_component_change_changes_fingerprint(manifest_data, field):
    baseline = Manifest.model_validate(manifest_data)
    value = {"id": field, "revision": "r2"}
    if field == "tools":
        value = {"lookup": {"interface": pin("api"), "configuration": pin("cfg"), "executable": pin("binary")}}
    manifest_data["components"][field] = value
    candidate = Manifest.model_validate(manifest_data)
    result = compare_manifests(baseline, candidate)
    assert result.baseline_fingerprint != result.candidate_fingerprint
    assert all(change.categories == ("behavioral",) for change in result.changes)
    assert result.changes[0].field.startswith(f"components.{field}")


def test_permissions_and_metadata_change_classification(tmp_path, manifest_data):
    tool = {"interface": pin("api"), "configuration": pin("cfg"), "executable": pin("binary")}
    manifest_data["components"]["tools"]["lookup"] = tool
    baseline = Manifest.model_validate(manifest_data)
    tool["permissions"] = {"write": True}
    candidate = Manifest.model_validate(manifest_data)
    registry = Registry(tmp_path / "lab.sqlite3")
    result = registry.compare(registry.register_manifest(baseline), registry.register_manifest(candidate))
    assert [(change.field, change.categories) for change in result.changes] == [
        ("components.tools/lookup/permissions", ("permission", "security"))
    ]
    metadata_only = compare_manifests(
        baseline, baseline, baseline_metadata=ManifestMetadata(label="old"),
        candidate_metadata=ManifestMetadata(label="new"),
    )
    assert metadata_only.baseline_fingerprint == metadata_only.candidate_fingerprint
    assert metadata_only.changes[0].categories == ("administrative",)
    with pytest.raises(RecordMissing):
        registry.compare("0" * 64, candidate.fingerprint)


def test_suite_revision_is_independent_from_manifest(tmp_path, manifest_data, suite_data):
    registry = Registry(tmp_path / "lab.sqlite3")
    manifest = Manifest.model_validate(manifest_data)
    first = EvaluationSuite.model_validate(suite_data)
    suite_data["thresholds"]["minimum"] = "0.99"
    with pytest.raises(RecordConflict):
        registry.register_suite(first)
        registry.register_suite(EvaluationSuite.model_validate(suite_data))
    suite_data["revision"] = "r2"
    second = EvaluationSuite.model_validate(suite_data)
    assert registry.register_suite(second) != first.fingerprint
    assert registry.register_suite(first) == first.fingerprint
    baseline = GovernanceSnapshot(
        policy_fingerprint="3" * 64, accepted_suite_fingerprints=frozenset({first.fingerprint}),
        approval_requirements_fingerprint="4" * 64,
    )
    changes = compare_governance(
        baseline, GovernanceSnapshot(
            policy_fingerprint=baseline.policy_fingerprint,
            accepted_suite_fingerprints=frozenset({second.fingerprint}),
            approval_requirements_fingerprint=baseline.approval_requirements_fingerprint,
        ),
    )
    assert [change.field for change in changes] == ["accepted_suite_fingerprints"]
    assert changes[0].categories == ("governance",)
    assert registry.register_manifest(manifest) == registry.register_manifest(Manifest.model_validate(manifest_data))


def test_evidence_binding_and_integrity_after_reopen(tmp_path, manifest_data, suite_data):
    database = tmp_path / "lab.sqlite3"
    registry = Registry(database)
    candidate = registry.register_manifest(Manifest.model_validate(manifest_data))
    manifest_data["runtime"]["timeout"] = 30
    other_candidate = registry.register_manifest(Manifest.model_validate(manifest_data))
    suite = EvaluationSuite.model_validate(suite_data)
    suite_fingerprint = registry.register_suite(suite)
    suite_data["revision"] = "r2"
    other_suite = registry.register_suite(EvaluationSuite.model_validate(suite_data))
    artifact = b"Synthetic regression results"
    data = {
        "id": "ledger-run-001",
        "candidate_fingerprint": candidate,
        "suite_fingerprint": suite_fingerprint,
        "check_id": "regression",
        "check_revision": "r1",
        "dataset": suite_data["dataset"],
        "runner": suite_data["runner"],
        "executed_at": "2026-01-01T05:00:00-05:00",
        "result": "passed",
        "artifact_digest": sha256(artifact),
        "producer": "synthetic-runner",
        "source": "Synthetic fixture",
    }
    evidence = Evidence.from_json(json.dumps(data))
    assert evidence.executed_at.isoformat() == "2026-01-01T10:00:00+00:00"
    with pytest.raises(EvidenceMismatch, match="digest mismatch"):
        registry.register_evidence(evidence, b"tampered")
    with pytest.raises(EvidenceMismatch, match="check revision"):
        registry.register_evidence(Evidence.from_json(json.dumps(data | {"check_revision": "r2"})), artifact)
    registry.register_evidence(evidence, artifact)
    registry.register_evidence(evidence, artifact)
    with pytest.raises(RecordConflict):
        registry.register_evidence(Evidence.from_json(json.dumps(data | {"result": "failed"})), artifact)

    lookup = {"candidate_fingerprint": candidate, "suite_fingerprint": suite_fingerprint}
    registry = Registry(database)
    assert registry.get_verified_evidence(evidence.id, **lookup) == (evidence, artifact)
    with pytest.raises(EvidenceMismatch, match="another candidate"):
        registry.get_verified_evidence(evidence.id, **(lookup | {"candidate_fingerprint": other_candidate}))
    with pytest.raises(EvidenceMismatch, match="another suite"):
        registry.get_verified_evidence(evidence.id, **(lookup | {"suite_fingerprint": other_suite}))
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE evidence SET artifact = ? WHERE id = ?", (b"tampered", evidence.id))
    with pytest.raises(EvidenceMismatch, match="digest mismatch"):
        registry.get_verified_evidence(evidence.id, **lookup)
