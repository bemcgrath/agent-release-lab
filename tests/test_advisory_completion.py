"""Completion checks for advisory authorization, accounting and smoke validation."""

import json
from io import BytesIO
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from threading import Event
from urllib.error import HTTPError, URLError

import pytest

from agent_release_lab.governance.models import LocalTrust
from agent_release_lab.governance.service import Governance
from agent_release_lab.identity import sha256
from agent_release_lab.registry import RecordConflict, Registry
from agent_release_lab.reviewers.contracts import ProviderReply, ReviewerConfig, Usage
from agent_release_lab.reviewers.service import AdvisoryStore, evaluate_snapshot
from agent_release_lab.reviewers.providers import ChatCompletions, response_format
from agent_release_lab.reviewers.smoke import run_smoke
from agent_release_lab.reviewers.snapshot import build_snapshot
from test_governance import NOW, setup, trust


class Provider:
    calls = 0

    def review(self, request):
        self.calls += 1
        return ProviderReply(b'{"findings":[]}', "synthetic-served-r1",
                             Usage(input_tokens=7, output_tokens=3, source="provider"))


def test_cumulative_budget_reserves_before_concurrent_calls(tmp_path):
    governance, request, _, _ = setup(tmp_path, {})
    assessment_id = governance.assess("submitter", request)["assessment_id"]
    store = AdvisoryStore(governance)
    peer = AdvisoryStore(Governance(Registry(governance.registry.path), trust(), lambda: NOW))
    entered, release = Event(), Event()

    class Blocking(Provider):
        def review(self, request):
            entered.set()
            assert release.wait(10)
            return super().review(request)

    provider = Blocking()
    config = ReviewerConfig(cumulative_token_budget=52000)
    with ThreadPoolExecutor() as pool:
        future = pool.submit(store.run, "release", assessment_id, config, provider)
        try:
            assert entered.wait(10)
            denied = peer.run("release", assessment_id, config, Provider())
            assert denied["reason"] == "cumulative_budget_exceeded"
            assert peer.budget_used() == 52000
        finally:
            release.set()
        assert future.result(timeout=10)["budget"]["charged_tokens"] == 10
    assert provider.calls == 1 and peer.budget_used() == 10
    assert peer.run("release", assessment_id, config, Provider())["reason"] == "cumulative_budget_exceeded"


def test_in_flight_trust_revocation_retains_usage_without_advice(tmp_path):
    governance, request, _, _ = setup(tmp_path, {})
    assessment_id = governance.assess("submitter", request)["assessment_id"]
    store = AdvisoryStore(governance)
    config = trust().model_dump()
    next(actor for actor in config["actors"] if actor["id"] == "release")["token_digest"] = sha256(b"rotated")
    replacement = Governance(Registry(governance.registry.path), LocalTrust.model_validate(config), lambda: NOW)

    class Revoking(Provider):
        def review(self, request):
            replacement.activate_trust()
            return super().review(request)

    with pytest.raises(RecordConflict, match="trust configuration is stale"):
        store.run("release", assessment_id, ReviewerConfig(retain_provider_output=True), Revoking())
    current = AdvisoryStore(replacement)
    assert current.list("release", assessment_id) == []
    assert current.budget_used() == 10
    with current.registry.transaction() as db:
        assert db.execute("SELECT COUNT(*) FROM advisory_provider_output").fetchone()[0] == 0


@pytest.mark.parametrize("source, expected", [("estimate", (4, 3)), ("unknown", (None, None))])
def test_estimated_and_unknown_usage_keep_conservative_charge(tmp_path, source, expected):
    governance, request, _, _ = setup(tmp_path, {})
    assessment_id = governance.assess("submitter", request)["assessment_id"]

    class Meter(Provider):
        def review(self, request):
            return ProviderReply(b'{"findings":[]}', "synthetic-served-r1",
                                 Usage(input_tokens=expected[0], output_tokens=expected[1], source=source))

    store = AdvisoryStore(governance)
    record = store.run("release", assessment_id, ReviewerConfig(), Meter())
    assert record["usage"] == {"source": source, "input_tokens": expected[0], "output_tokens": expected[1]}
    assert record["budget"]["charged_tokens"] == store.budget_used() == 52000


def test_review_trace_and_bounded_output(tmp_path):
    governance, request, _, _ = setup(tmp_path, {})
    assessment = governance.assess("submitter", request)
    projection = json.loads(build_snapshot(governance, assessment))
    context = projection["governance_context"]
    assert context["ownership"] == assessment["ownership"]
    assert context["baseline_authority"] == assessment["baseline_authority"]
    assert context["trust_generation"] == assessment["trust_generation"]
    assert context["runtime_attestation"] == assessment["runtime_attestation"]
    assert "token_digest" not in json.dumps(projection) and "signature" not in json.dumps(projection)
    snapshot = json.loads(build_snapshot(governance, assessment | {"reasons": [
        {"code": "evidence_superseded", "evidence_id": "old-run", "superseded_by": "fresh-run"}
    ]}))
    assert snapshot["supersession"] == [{"evidence_id": "old-run", "superseded_by": "fresh-run"}]

    class Oversized(Provider):
        def review(self, request):
            return ProviderReply(b"x" * 40000, "synthetic-served-r1",
                                 Usage(input_tokens=7, output_tokens=3, source="provider"))

    store = AdvisoryStore(governance)
    config = ReviewerConfig(retain_provider_output=True, prompt_version="v2")
    record = store.run("release", assessment["assessment_id"], config, Oversized())
    assert record["status"] == "rejected" and record["retained_output_truncated"]
    assert record["adapter_revision"] == "fake-v1"
    assert record["configuration_fingerprint"] == sha256(config.canonical_bytes())
    assert record["prompt_fingerprint"] == sha256(record["prompt_content"].encode())
    assert record["inference_parameters"]["max_output_tokens"] == config.max_output_tokens
    assert record["confidence_calibration"] == "uncalibrated"
    with governance.registry.transaction() as db:
        assert db.execute("SELECT length(output) FROM advisory_provider_output").fetchone()[0] == 16384


def test_smoke_requires_explicit_charge_approval_and_covers_all_scenarios(tmp_path):
    refused = subprocess.run([
        sys.executable, "-m", "agent_release_lab.reviewers.smoke", "--config", str(tmp_path / "unused.json"),
        "--input-usd-per-million", "1", "--output-usd-per-million", "2",
    ], capture_output=True, text=True)
    assert refused.returncode == 2 and "--allow-charges" in refused.stderr
    provider = Provider()
    reports = run_smoke(ReviewerConfig(), provider, Decimal("1"), Decimal("2"))
    assert [report["scenario"] for report in reports] == ["ready", "blocked", "suspicious", "conflict", "approved"]
    assert provider.calls == 5
    assert all(report["structured_output_valid"] and report["citations_valid"] for report in reports)
    assert all(report["estimated_cost_usd"] == "0.000013" for report in reports)


@pytest.mark.parametrize("confidence", [75, "75"])
def test_blocked_only_smoke_uses_schema_and_keeps_strict_validation(confidence):
    class BlockedProvider(Provider):
        def review(self, request):
            self.calls += 1
            assert "empty evidence array and nonempty uncertainty" in request.instructions
            assert request.response_format == "json_schema"
            schema = response_format(request.response_format)["json_schema"]["schema"]
            assert schema["$defs"]["Finding"]["properties"]["confidence"]["type"] == "integer"
            assert schema["$defs"]["Finding"]["additionalProperties"] is False
            return ProviderReply(json.dumps({"findings": [{
                "id": "missing-coverage", "category": "insufficient_testing", "severity": "medium",
                "description": "Required coverage is missing.", "evidence": [],
                "remediation": "Register a verified run.", "confidence": confidence,
                "uncertainty": "No artifact is available to confirm coverage.",
            }]}).encode(), "synthetic-served-r1", Usage(input_tokens=7, output_tokens=3, source="provider"))

    provider = BlockedProvider()
    config = ReviewerConfig(prompt_version="v3", response_format="json_schema", cumulative_token_budget=52000)
    result, = run_smoke(config, provider, Decimal("1"), Decimal("2"), scenario="blocked")
    assert provider.calls == 1 and result["scenario"] == "blocked"
    if isinstance(confidence, int):
        assert result["status"] == "completed" and result["citations_valid"]
    else:
        assert result["status"] == "rejected" and result["validation_issue_types"] == ["int_type"]


@pytest.mark.parametrize("failure, diagnostic", [
    (400, {"kind": "request_rejected", "http_status": 400}),
    (401, {"kind": "authentication_or_permission", "http_status": 401}),
    (429, {"kind": "billing_or_quota", "http_status": 429}),
    (503, {"kind": "upstream_error", "http_status": 503}),
    ("network", {"kind": "network_error"}),
    ("timeout", {"kind": "network_timeout"}),
    ("envelope", {"kind": "invalid_response_envelope"}),
])
def test_provider_diagnostics_are_sanitized(monkeypatch, failure, diagnostic):
    from agent_release_lab.reviewers import providers

    class Response(BytesIO):
        def read(self, size=-1):
            return b'{"unexpected":"synthetic-provider-body"}'

    class Transport:
        def open(self, request, timeout):
            assert request.get_header("Authorization") == "Bearer synthetic-token"
            if isinstance(failure, int):
                raise HTTPError("https://synthetic.example/private-url", failure,
                                "synthetic-message", {}, BytesIO(b"synthetic-provider-body"))
            if failure == "network":
                raise URLError("synthetic-network-detail")
            if failure == "timeout":
                raise URLError(TimeoutError("synthetic-network-detail"))
            return Response()

    monkeypatch.setattr(providers, "build_opener", lambda *args: Transport())
    config = ReviewerConfig(provider="chat-completions", model="synthetic-model",
                            endpoint="https://synthetic.example/chat/completions")
    result = evaluate_snapshot(b'{"evidence":[]}', "test", config,
                               ChatCompletions(config.endpoint, "synthetic-token"))
    assert result["reason"] == "provider_unavailable"
    assert result["provider_error"] == diagnostic
    assert result["usage"]["source"] == "unknown"
    encoded = json.dumps(result)
    for secret in ("synthetic-token", "private-url", "synthetic-message",
                   "synthetic-provider-body", "synthetic-network-detail"):
        assert secret not in encoded


@pytest.mark.parametrize("finding_id, status", [("coverage-gap", "completed"), ("invalid id", "rejected")])
def test_gemini_uses_compact_wire_schema_without_weakening_local_validation(monkeypatch, finding_id, status):
    from agent_release_lab.reviewers import providers

    class Transport:
        def open(self, request, timeout):
            payload = json.loads(request.data)
            schema = payload["response_format"]["json_schema"]["schema"]
            finding = schema["properties"]["findings"]["items"]
            assert finding["additionalProperties"] is False
            assert finding["properties"]["uncertainty"] == {"type": ["string", "null"]}
            assert finding["properties"]["confidence"] == {"type": "integer"}
            assert set(finding["required"]) == finding["properties"].keys()
            for keyword in ("$ref", "$defs", "pattern", "maxItems", "minLength"):
                assert json.dumps(keyword) not in json.dumps(schema)
            output = json.dumps({"findings": [{
                "id": finding_id, "category": "insufficient_testing", "severity": "medium",
                "description": "Coverage missing.", "remediation": "Run the required check.",
                "confidence": 75, "evidence": [], "uncertainty": "No evidence is available.",
            }]})
            return BytesIO(json.dumps({
                "model": "gemini-3.5-flash-lite", "usage": {"prompt_tokens": 7, "completion_tokens": 3},
                "choices": [{"finish_reason": "stop", "message": {"content": output}}],
            }).encode())

    monkeypatch.setattr(providers, "build_opener", lambda *args: Transport())
    config = ReviewerConfig(provider="chat-completions", model="gemini-3.5-flash-lite",
                            endpoint="https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
                            response_format="json_schema")
    result = evaluate_snapshot(b'{"evidence":[]}', "test", config, ChatCompletions(config.endpoint, None))
    assert result["status"] == status
    if status == "rejected":
        assert result["validation_issue_types"] == ["string_pattern_mismatch"]
