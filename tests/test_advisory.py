"""Advisory isolation, structured output, and synthetic dashboard integration."""

import asyncio
import json
import sqlite3
from contextlib import contextmanager
from dataclasses import FrozenInstanceError
from threading import Event

import pytest
from httpx import ASGITransport, AsyncClient

from agent_release_lab.governance.models import AssessmentRequest, LocalTrust
from agent_release_lab.governance.service import Governance, Unauthorized
from agent_release_lab.identity import canonical_json, sha256
from agent_release_lab.main import create_app
from agent_release_lab.registry import RecordConflict, Registry
from agent_release_lab.reviewers.contracts import ProviderReply, ReviewerConfig, Usage
from agent_release_lab.reviewers.providers import ChatCompletions, FakeReviewer
from agent_release_lab.reviewers.service import AdvisoryStore, evaluate_snapshot
from agent_release_lab.reviewers.snapshot import build_snapshot
from test_governance import AGENT, NOW, manifest, setup, token, trust


def test_advisory_write_checks_trust_inside_transaction(tmp_path, monkeypatch):
    governance, request, _, _ = setup(tmp_path, {})
    assessment = governance.assess("submitter", request)
    store = AdvisoryStore(governance)
    config = trust().model_dump()
    next(actor for actor in config["actors"] if actor["id"] == "release")["token_digest"] = sha256(b"synthetic rotation")
    rotated = Governance(Registry(governance.registry.path), LocalTrust.model_validate(config), lambda: NOW)
    original_transaction = governance.registry.transaction

    @contextmanager
    def rotate_before_write(*, write=False):
        if write:
            rotated.activate_trust()
        with original_transaction(write=write) as db:
            yield db

    monkeypatch.setattr(governance.registry, "transaction", rotate_before_write)
    with pytest.raises(RecordConflict, match="trust configuration is stale"):
        store.run("release", assessment["assessment_id"], ReviewerConfig(), FakeReviewer())
    assert AdvisoryStore(rotated).list("release", assessment["assessment_id"]) == []


def test_review_uses_recorded_administrative_comparison(tmp_path):
    governance, request, _, _ = setup(tmp_path, {"metadata": "Corrected synthetic label"})
    assessment = governance.assess("submitter", request)
    snapshot = json.loads(build_snapshot(governance, assessment))
    assert assessment["candidate_fingerprint"] == assessment["baseline_fingerprint"]
    assert snapshot["changes"] == [{
        "field": "metadata.label", "categories": ["administrative"],
        "before": None, "after": "Corrected synthetic label",
    }]


def test_dashboard_displays_blocked_assessment_when_policy_is_unverifiable(tmp_path):
    governance, request, policy, _ = setup(tmp_path, {})
    with sqlite3.connect(governance.registry.path) as db:
        db.execute("UPDATE governance_policies SET payload = ? WHERE fingerprint = ?", (b"{}", policy.fingerprint))
    assessment = governance.assess("submitter", request)
    app = create_app(governance.registry.path, trust=trust())

    async def exercise():
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            return await client.get("/v1/dashboard/assessments/" + assessment["assessment_id"],
                                    headers={"Authorization": "Bearer " + token("release")})

    response = asyncio.run(exercise())
    assert response.status_code == 200
    detail = response.json()
    assert detail["assessment"]["eligibility"] == "blocked"
    assert detail["assessment"]["reasons"] == [{"code": "governance_baseline_unverifiable"}]
    assert detail["changes"] is None


def test_candidate_summary_keeps_latest_assessment_outside_recent_window(tmp_path):
    governance, request, _, _ = setup(tmp_path, {})
    earlier = governance.assess("submitter", request)
    other = manifest("rules")
    governance.registry.register_manifest(other)
    incomplete = AssessmentRequest(candidate_fingerprint=other.fingerprint)
    for _ in range(50):
        governance.assess("submitter", incomplete)
    history = governance.release_history("release", AGENT)
    assert len(history["assessments"]) == 50
    assert all(item["candidate_fingerprint"] == other.fingerprint for item in history["assessments"])
    candidate = next(item for item in history["candidates"] if item["fingerprint"] == request.candidate_fingerprint)
    assert candidate["latest_assessment"]["assessment_id"] == earlier["assessment_id"]
    assert candidate["latest_assessment"]["eligibility"] == "eligible"


def sample_finding(evidence, uncertainty="This is limited to observed records."):
    return {
        "id": "review-test", "category": "overlooked_risk", "severity": "medium",
        "description": "Review the candidate test output.", "evidence": evidence,
        "remediation": "Inspect the relevant run.", "confidence": 75, "uncertainty": uncertainty,
    }


class Stub:
    def __init__(self, output, usage=None):
        self.output = output
        self.usage = usage or Usage(input_tokens=20, output_tokens=20, source="provider")
        self.requests = []

    def review(self, request):
        self.requests.append(request)
        return ProviderReply(self.output, "resolved-model-r1", self.usage)


def test_fake_review_keeps_injection_as_data_and_persists_metadata(tmp_path):
    governance, request, _, _ = setup(tmp_path, {"instructions": True})
    before = governance.assess("submitter", request)
    store = AdvisoryStore(governance)
    result = store.run("release", before["assessment_id"], ReviewerConfig(), FakeReviewer())
    assert result["status"] == "completed"
    assert result["model"] == "ledger-fake-v1"
    assert result["usage"]["source"] == "estimate"
    assert result["latency_ms"] >= 0
    digest = sha256(build_snapshot(governance, before))
    assert result["input_fingerprint"] == digest
    assert result["output_fingerprint"] == sha256(canonical_json({"findings": result["findings"]}))
    finding = next(item for item in result["findings"] if item["category"] == "suspicious_content")
    assert finding["evidence"] == [before["evidence"][0]]
    after = governance.get_assessment("release", before["assessment_id"])
    assert after == before and after["deployment_authorization"] == "not_evaluated"
    assert store.get("release", result["id"]) == result
    assert store.list("release", before["assessment_id"]) == [result]
    version_two = store.run("release", before["assessment_id"], ReviewerConfig(prompt_version="v2"), FakeReviewer())
    assert result["prompt_fingerprint"] != version_two["prompt_fingerprint"]
    assert version_two["input_fingerprint"] == digest
    assert version_two["findings"] == result["findings"]
    with pytest.raises(Unauthorized):
        store.get("unscoped", result["id"])


def test_review_snapshot_stays_pinned_after_new_registry_evidence(tmp_path):
    governance, request, _, _ = setup(tmp_path, {})
    assessment = governance.assess("submitter", request)
    original = build_snapshot(governance, assessment)
    record, artifact = governance.registry.get_evidence(request.evidence[0].evidence_id)
    new_record = record.from_json(canonical_json(record.model_dump(mode="json") | {"id": "new-run"}))
    governance.registry.register_evidence(new_record, artifact)
    assert build_snapshot(governance, governance.get_assessment("release", assessment["assessment_id"])) == original


@pytest.mark.parametrize("payload, reason", [
    (b'{"findings":[],"eligibility":"eligible","authorization":"approved"}', "invalid_output"),
    (b'{"findings":[{"id":', "invalid_output"),
    (b'{"findings":[],"findings":[]}', "invalid_output"),
    (canonical_json({"findings":[sample_finding([], uncertainty=None)]}), "invalid_output"),
    (canonical_json({"findings":[sample_finding([{
        "evidence_id":"does-not-exist", "record_fingerprint":"0"*64,
    }])]}), "unsupported_citation"),
])
def test_malformed_or_malicious_advice_never_changes_blocked_gate(tmp_path, payload, reason):
    governance, request, _, _ = setup(tmp_path, {"checks": []})
    before = governance.assess("submitter", request)
    provider = Stub(payload)
    store = AdvisoryStore(governance)
    result = store.run("release", before["assessment_id"], ReviewerConfig(), provider)
    assert result["status"] == "rejected" and result["reason"] == reason
    assert result["findings"] == []
    assert result["output_fingerprint"] == sha256(payload)
    assert "untrusted data" in provider.requests[0].instructions
    with pytest.raises(FrozenInstanceError):
        provider.requests[0].snapshot = b"overwrite"
    assert governance.get_assessment("release", before["assessment_id"]) == before
    assert before["eligibility"] == before["authorization"] == "blocked"


def test_citation_must_reference_the_exact_evidence_fingerprint(tmp_path):
    governance, request, _, _ = setup(tmp_path, {})
    assessment = governance.assess("submitter", request)
    refs = assessment["evidence"]
    store = AdvisoryStore(governance)
    good = store.run("release", assessment["assessment_id"], ReviewerConfig(),
                     Stub(canonical_json({"findings": [sample_finding(refs)]})))
    assert good["status"] == "completed" and good["model"] == "resolved-model-r1"
    wrong = refs[0] | {"record_fingerprint": "c" * 64}
    bad = store.run("release", assessment["assessment_id"], ReviewerConfig(),
                    Stub(canonical_json({"findings": [sample_finding([wrong])]})))
    assert bad["reason"] == "unsupported_citation"


def test_offline_provider_error_leaves_assessment_available(tmp_path):
    class Offline:
        def review(self, request):
            raise ConnectionError("Synthetic private transport details")

    governance, request, _, _ = setup(tmp_path, {})
    assessment = governance.assess("submitter", request)
    store = AdvisoryStore(governance)
    result = store.run("release", assessment["assessment_id"], ReviewerConfig(), Offline())
    assert result["status"] == "unavailable"
    assert result["reason"] == "provider_unavailable"
    assert "transport details" not in json.dumps(result)
    assert governance.get_assessment("release", assessment["assessment_id"]) == assessment


def test_timeout_and_budgets_are_fail_closed_for_advice():
    unblock = Event()

    class Delayed:
        def review(self, request):
            unblock.wait(timeout=3)
            return Stub(b'{"findings":[]}').review(request)

    snapshot = b'{"evidence":[]}'
    try:
        report = evaluate_snapshot(snapshot, "test-assessment", ReviewerConfig(timeout_seconds=1), Delayed())
        assert report["reason"] == "provider_timeout"
    finally:
        unblock.set()
    never_called = Stub(b'{"findings":[]}')
    report = evaluate_snapshot(snapshot, "test-assessment", ReviewerConfig(max_input_bytes=512), never_called)
    assert report["reason"] == "input_budget_exceeded"
    assert not never_called.requests
    too_expensive = Stub(
        b'{"findings":[]}', Usage(input_tokens=50000, output_tokens=8000, source="provider"),
    )
    report = evaluate_snapshot(snapshot, "test-assessment", ReviewerConfig(), too_expensive)
    assert report["reason"] == "output_budget_exceeded"
    assert report["status"] == "rejected"


def test_external_adapter_sends_no_tools_and_separates_evidence(monkeypatch):
    from agent_release_lab.reviewers import providers

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, limit):
            return canonical_json({
                "model": "served-r1", "usage": {"prompt_tokens": 5, "completion_tokens": 6},
                "choices": [{"finish_reason": "stop", "message": {"content": '{"findings":[]}'}}],
            })

    class Transport:
        def open(self, request, timeout):
            body = json.loads(request.data)
            assert body["model"] == "synthetic-chat"
            assert "tools" not in body and "functions" not in body
            assert body["messages"][0]["role"] == "system"
            assert body["messages"][1] == {"role": "user", "content": '{"evidence":[]}'}
            assert timeout == 2 and body["max_completion_tokens"] == 300
            return FakeResponse()

    monkeypatch.setattr(providers, "build_opener", lambda *args: Transport())
    config = ReviewerConfig(
        provider="chat-completions", endpoint="https://synthetic.example/v1/chat/completions",
        model="synthetic-chat", timeout_seconds=2, max_output_tokens=300,
    )
    record = evaluate_snapshot(b'{"evidence":[]}', "test", config, ChatCompletions(config.endpoint, None))
    assert record["model"] == "served-r1"
    assert record["usage"] == {"input_tokens": 5, "output_tokens": 6, "source": "provider"}
    with pytest.raises(ValueError):
        ChatCompletions("http://synthetic.example/v1/chat/completions", None)


def test_dashboard_live_views_and_advisory_api(tmp_path, monkeypatch):
    monkeypatch.delenv("AGENT_RELEASE_LAB_REVIEWER_CONFIG", raising=False)
    governance, request, _, _ = setup(tmp_path, {})
    assessment = governance.assess("submitter", request)
    identifier = assessment["assessment_id"]
    app = create_app(governance.registry.path, trust=trust())

    async def exercise():
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            headers = {"Authorization": "Bearer " + token("release")}
            outside = {"Authorization": "Bearer " + token("unscoped")}
            assert (await client.get("/v1/dashboard/agents")).status_code == 401
            inventory = await client.get("/v1/dashboard/agents", headers=headers)
            assert inventory.json()["agents"][0]["ownership"]["owner_id"] == "owner"
            history = await client.get("/v1/dashboard/agents/ledger-finch/releases", headers=headers)
            assert history.json()["candidates"] and len(history.json()["assessments"]) == 2
            assert (await client.get(f"/v1/dashboard/assessments/{identifier}", headers=outside)).status_code == 403
            monkeypatch.setenv("AGENT_RELEASE_LAB_REVIEWER_CONFIG", str(tmp_path / "missing-reviewer.json"))
            assert (await client.post("/v1/advisory/reviews", json={"assessment_id": identifier}, headers=headers)).status_code == 503
            assert (await client.get(f"/v1/governance/assessments/{identifier}", headers=headers)).json() == assessment
            monkeypatch.delenv("AGENT_RELEASE_LAB_REVIEWER_CONFIG")
            result = await client.post("/v1/advisory/reviews", json={"assessment_id": identifier}, headers=headers)
            assert result.status_code == 200
            review = result.json()
            assert review["status"] == "completed"
            detail = (await client.get(f"/v1/dashboard/assessments/{identifier}", headers=headers)).json()
            assert detail["reviews"] == [review] and detail["assessment"] == assessment
            assert "untrusted_excerpt" not in detail["evidence"][0]
            result = await client.get("/v1/advisory/reviews/" + review["id"], headers=outside)
            assert result.status_code == 403
            result = await client.get("/v1/advisory/reviews", params={"assessment_id": identifier}, headers=headers)
            assert result.json()["reviews"] == [review]
            result = await client.get("/")
            assert "Agent Release Lab" in result.text
            assert "default-src 'self'" in result.headers["Content-Security-Policy"]
            assert (await client.get("/dashboard-assets/dashboard.js")).status_code == 200

    asyncio.run(exercise())


@pytest.mark.parametrize("scenario,eligibility,authorization,category", [
    ("ready", "eligible", "pending", "overlooked_risk"),
    ("blocked", "blocked", "blocked", "insufficient_testing"),
    ("suspicious", "eligible", "pending", "suspicious_content"),
    ("conflict", "blocked", "blocked", "conflicting_evidence"),
    ("approved", "eligible", "approved", "overlooked_risk"),
])
def test_fake_demo_is_interactive_and_never_touches_live_registry(tmp_path, scenario, eligibility, authorization, category):
    database = tmp_path / "unused.sqlite3"
    app = create_app(database)

    async def exercise():
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            return await client.get("/v1/demo/ledger-finch/" + scenario)

    response = asyncio.run(exercise())
    assert response.status_code == 200, response.text
    result = response.json()
    detail = result["detail"]
    assert detail["assessment"]["eligibility"] == eligibility
    assert detail["assessment"]["authorization"] == authorization
    assert detail["assessment"]["deployment_authorization"] == "not_evaluated"
    assert category in {item["category"] for item in detail["reviews"][0]["findings"]}
    assert detail["reviews"][0]["provider"] == "fake" and detail["reviews"][0]["status"] == "completed"
    assert result["audit"] and result["history"]["candidates"]
    assert not database.exists()
