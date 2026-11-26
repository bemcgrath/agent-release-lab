import asyncio
import base64
import json
import sqlite3

from httpx import ASGITransport, AsyncClient
import pytest

from agent_release_lab.evidence import EvaluationSuite
from agent_release_lab.identity import canonical_json, sha256
from agent_release_lab.main import create_app
from agent_release_lab.manifests import Manifest
from agent_release_lab.registry import Registry


@pytest.fixture
def api(tmp_path):
    database = tmp_path / "api.sqlite3"
    app = create_app(database)

    async def request(method, url, **kwargs):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            return await client.request(method, url, **kwargs)

    def send(method, url, **kwargs):
        return asyncio.run(request(method, url, **kwargs))

    return send, database


def pin(identifier):
    return {"id": identifier, "revision": "r1"}


@pytest.fixture
def deployment():
    return {
        "schema_version": 2,
        "agent_id": "ledger-finch",
        "components": {
            "model": pin("model"), "prompt": pin("prompt"), "harness": pin("harness"),
            "business_rules": pin("rules"), "tools": {},
        },
        "scope": {
            "purpose": "ledger-reconciliation",
            "allowed_tasks": ["summarize-ledger"],
            "boundaries": {
                "allowed_tools": [],
                "allowed_data_sources": ["synthetic-ledger"],
                "allowed_destinations": [],
                "can_write": False,
            },
        },
    }


@pytest.fixture
def suite():
    return {
        "schema_version": 1,
        "id": "ledger-suite",
        "revision": "r1",
        "checks": {"regression": "r1"},
        "dataset": {"id": "synthetic-ledger", "revision": "r1", "digest": "a" * 64},
        "runner": pin("runner"),
        "scoring": {},
        "thresholds": {},
    }


def register(send, path, payload):
    response = send("POST", path, json=payload)
    assert response.status_code == 200, response.text
    return response.json()["fingerprint"]


def registrations(send, deployment, suite):
    candidate = register(send, "/v1/manifests", deployment)
    suite_fingerprint = register(send, "/v1/suites", suite)
    artifact = b"Synthetic regression report"
    evidence = {
        "schema_version": 1,
        "id": "ledger/r1",
        "candidate_fingerprint": candidate,
        "suite_fingerprint": suite_fingerprint,
        "check_id": "regression",
        "check_revision": "r1",
        "dataset": suite["dataset"],
        "runner": suite["runner"],
        "executed_at": "2026-01-01T05:00:00-05:00",
        "result": "passed",
        "artifact_digest": sha256(artifact),
        "producer": "synthetic-runner",
        "source": "Synthetic fixture",
    }
    return {"record": evidence, "artifact_base64": base64.b64encode(artifact).decode("ascii")}


def verification(record, fingerprint):
    return {
        "evidence_id": record["id"],
        "candidate_fingerprint": record["candidate_fingerprint"],
        "suite_fingerprint": record["suite_fingerprint"],
        "expected_record_fingerprint": fingerprint,
    }


def test_http_registration_retrieval_comparison_and_verification(api, deployment, suite):
    send, _ = api
    submission = registrations(send, deployment, suite)
    record = submission["record"]
    fingerprint = register(send, "/v1/evidence", submission)
    assert fingerprint == "9a272e201b415d7bdc8cdb9a4b1a0e05bbaa099bb6bfacaf05f999ae42fcd73b"
    assert register(send, "/v1/evidence", submission) == fingerprint
    assert register(send, "/v1/suites", suite) == record["suite_fingerprint"]

    candidate = record["candidate_fingerprint"]
    manifest = send("GET", f"/v1/manifests/{candidate}").json()
    assert manifest["record"]["scope"] == deployment["scope"]
    assert manifest["fingerprint"] == candidate
    recovered_suite = send("GET", f"/v1/suites/{record['suite_fingerprint']}")
    assert recovered_suite.status_code == 200
    assert recovered_suite.json()["record"]["schema_version"] == 1

    response = send("GET", "/v1/evidence", params={"evidence_id": "ledger/r1"})
    assert response.status_code == 200
    recovered = response.json()
    assert recovered["fingerprint"] == sha256(canonical_json(recovered["record"])) == fingerprint
    assert recovered["record"]["executed_at"] == "2026-01-01T10:00:00Z"
    assert recovered["artifact_base64"] == submission["artifact_base64"]
    response = send("POST", "/v1/evidence-verifications", json=verification(record, fingerprint))
    assert response.json() == {"verified": True, "fingerprint": fingerprint}

    request = {"baseline_fingerprint": candidate, "candidate_fingerprint": candidate}
    administrative = send("POST", "/v1/comparisons", json=request | {
        "baseline_metadata": {"description": "Old display text"},
        "candidate_metadata": {"description": "Revised display text"},
    }).json()
    assert administrative["changes"] == [{
        "field": "metadata.description", "categories": ["administrative"],
        "before": "Old display text", "after": "Revised display text",
    }]
    assert administrative["baseline_fingerprint"] == administrative["candidate_fingerprint"]

    deployment["scope"]["boundaries"]["can_write"] = True
    changed = register(send, "/v1/manifests", deployment)
    assert candidate != changed
    comparison = send("POST", "/v1/comparisons", json=request | {"candidate_fingerprint": changed}).json()
    assert comparison["classification_version"] == 2
    assert comparison["changes"] == [{
        "field": "scope.boundaries.can_write", "categories": ["behavioral", "permission", "security"],
        "before": False, "after": True,
    }]

    response = send("POST", "/v1/evidence-verifications", json=verification(record, fingerprint) | {
        "candidate_fingerprint": changed,
    })
    assert response.status_code == 422


@pytest.mark.parametrize("path, body", [
    ("/v1/manifests", '{"schema_version":1,"schema_version":2}'),
    ("/v1/suites", '{"checks":{"regression":"r1","regression":"r2"}}'),
    ("/v1/evidence", '{"record":{"producer":"one","producer":"two"}}'),
    ("/v1/comparisons", '{"candidate_fingerprint":"a","candidate_fingerprint":"b"}'),
    ("/v1/evidence-verifications", '{"evidence_id":"one","evidence_id":"two"}'),
    ("/v1/manifests", '{"schema_version":'),
    ("/v1/manifests", '{"schema_version":NaN}'),
])
def test_http_rejects_invalid_raw_json(api, path, body):
    send, database = api
    response = send("POST", path, content=body, headers={"Content-Type": "application/json"})
    assert response.status_code == 422
    assert not database.exists()


def test_http_rejects_excessive_json_nesting(api):
    send, database = api
    raw = '{"runtime":{"nested":' + "[" * 1500 + "0" + "]" * 1500 + "}}"
    response = send("POST", "/v1/manifests", content=raw, headers={"Content-Type": "application/json"})
    assert response.status_code == 422
    assert not database.exists()


@pytest.mark.parametrize("timestamp", [
    "0001-01-01T00:00:00+01:00",
    "9999-12-31T23:59:59-01:00",
    "2026-01-01T00:00:00+00:60",
])
def test_http_rejects_invalid_evidence_utc_time(api, deployment, suite, timestamp):
    send, _ = api
    submission = registrations(send, deployment, suite)
    submission["record"]["executed_at"] = timestamp
    response = send("POST", "/v1/evidence", json=submission)
    assert response.status_code == 422
    assert send("GET", "/v1/evidence", params={"evidence_id": "ledger/r1"}).status_code == 404


@pytest.mark.parametrize("identifier", ["ledger/../r1", "ledger/./r1"])
def test_http_retrieves_evidence_ids_with_literal_dot_segments(api, deployment, suite, identifier):
    send, _ = api
    submission = registrations(send, deployment, suite)
    ordinary_id = "r1" if "/../" in identifier else "ledger/r1"
    register(send, "/v1/evidence", submission | {"record": submission["record"] | {"id": ordinary_id}})
    submission["record"]["id"] = identifier
    fingerprint = register(send, "/v1/evidence", submission)
    response = send("GET", "/v1/evidence", params={"evidence_id": identifier})
    assert response.status_code == 200
    assert response.json()["record"]["id"] == identifier
    assert response.json()["fingerprint"] == fingerprint


def test_http_rejects_duplicate_key_in_otherwise_valid_evidence(api, deployment, suite):
    send, _ = api
    submission = registrations(send, deployment, suite)
    raw = json.dumps(submission).replace(
        '"result": "passed"', '"result": "failed", "result": "passed"'
    )
    response = send("POST", "/v1/evidence", content=raw, headers={"Content-Type": "application/json"})
    assert response.status_code == 422
    assert send("GET", "/v1/evidence", params={"evidence_id": "ledger/r1"}).status_code == 404


def test_http_rejects_ambiguous_types_and_unversioned_submissions(api, deployment, suite):
    send, _ = api
    assert send("POST", "/v1/manifests", json=deployment | {"schema_version": True}).status_code == 422
    assert send("POST", "/v1/manifests", json=deployment | {"scope": None}).status_code == 422
    assert send("POST", "/v1/manifests", json=deployment | {"description": "Outside identity"}).status_code == 422
    assert send("POST", "/v1/manifests", content=json.dumps(deployment)).status_code == 415
    assert send("POST", "/v1/suites", json={key: val for key, val in suite.items() if key != "schema_version"}).status_code == 422
    assert send("POST", "/v1/suites", json=suite | {"schema_version": 2}).status_code == 422

    submission = registrations(send, deployment, suite)
    assert send("POST", "/v1/evidence", json=submission | {"artifact_base64": "!bad"}).status_code == 422
    record = submission["record"]
    assert send("POST", "/v1/evidence", json=submission | {
        "record": {key: val for key, val in record.items() if key != "schema_version"},
    }).status_code == 422
    assert send("POST", "/v1/evidence", json=submission | {
        "record": record | {"schema_version": 2},
    }).status_code == 422


def test_http_missing_records_and_conflicts(api, deployment, suite):
    send, _ = api
    unknown = "0" * 64
    assert send("GET", f"/v1/manifests/{unknown}").status_code == 404
    assert send("GET", f"/v1/suites/{unknown}").status_code == 404
    assert send("GET", "/v1/evidence", params={"evidence_id": "missing"}).status_code == 404
    submission = registrations(send, deployment, suite)
    record = submission["record"]
    assert send("POST", "/v1/evidence", json=submission | {
        "record": record | {"suite_fingerprint": unknown},
    }).status_code == 404
    fingerprint = register(send, "/v1/evidence", submission)
    assert send("POST", "/v1/evidence-verifications", json=verification(record, unknown)).status_code == 422
    assert send("POST", "/v1/evidence-verifications", json=verification(record, fingerprint) | {
        "evidence_id": "missing",
    }).status_code == 404
    assert send("POST", "/v1/suites", json=suite | {"thresholds": {"min": "0.9"}}).status_code == 409
    assert send("POST", "/v1/evidence", json=submission | {
        "record": record | {"result": "failed"},
    }).status_code == 409


@pytest.mark.parametrize("field, value", [
    ("source", "Changed provenance"),
    ("result", "failed"),
    ("executed_at", "2026-01-02T00:00:00Z"),
])
def test_http_detects_evidence_metadata_tampering(api, deployment, suite, field, value):
    send, database = api
    submission = registrations(send, deployment, suite)
    original = register(send, "/v1/evidence", submission)
    response = send("GET", "/v1/evidence", params={"evidence_id": "ledger/r1"})
    record = response.json()["record"] | {field: value}
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE evidence SET payload = ?", (canonical_json(record),))

    assert send("GET", "/v1/evidence", params={"evidence_id": "ledger/r1"}).status_code == 409
    assert send("POST", "/v1/evidence-verifications", json=verification(record, original)).status_code == 409

    # An externally retained fingerprint also detects changes to both database fields.
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE evidence SET record_fingerprint = ?", (sha256(canonical_json(record)),))
    assert send("POST", "/v1/evidence-verifications", json=verification(record, original)).status_code == 422


def test_legacy_registry_preserves_deployment_and_suite_but_cannot_verify_legacy_evidence(
    api, deployment, suite,
):
    send, database = api
    legacy_manifest = Manifest.model_validate({
        key: val for key, val in (deployment | {"schema_version": 1}).items() if key != "scope"
    })
    legacy_suite = EvaluationSuite.model_validate({key: val for key, val in suite.items() if key != "schema_version"})
    registry = Registry(database)
    registry.register_manifest(legacy_manifest)
    registry.register_suite(legacy_suite)
    with sqlite3.connect(database) as connection:
        connection.execute("ALTER TABLE evidence DROP COLUMN record_fingerprint")
        connection.execute(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?)",
            ("legacy", legacy_manifest.fingerprint, legacy_suite.fingerprint, b"{}", b"legacy"),
        )
    assert send("GET", f"/v1/manifests/{legacy_manifest.fingerprint}").status_code == 200
    assert send("GET", f"/v1/suites/{legacy_suite.fingerprint}").status_code == 200
    response = send("GET", "/v1/evidence", params={"evidence_id": "legacy"})
    assert response.status_code == 409
    assert "Legacy evidence" in response.json()["detail"]


def test_versioned_golden_fingerprints(deployment, suite):
    assert Manifest.model_validate(deployment).fingerprint == "877901a1dc101f09f5cf430436613a2f5c7cc41b9dbb0dc8582c341a2a3aa618"
    assert EvaluationSuite.model_validate(suite).fingerprint == "b214745f04fa001d47c5a98eb765b77c6949d9363301a9d00ea24a9ecceeb677"
