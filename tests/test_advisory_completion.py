"""Completion checks for advisory authorization, accounting and smoke validation."""

import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from threading import Event

import pytest

from agent_release_lab.governance.models import LocalTrust
from agent_release_lab.governance.service import Governance
from agent_release_lab.identity import sha256
from agent_release_lab.registry import RecordConflict, Registry
from agent_release_lab.reviewers.contracts import ProviderReply, ReviewerConfig, Usage
from agent_release_lab.reviewers.service import AdvisoryStore
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
