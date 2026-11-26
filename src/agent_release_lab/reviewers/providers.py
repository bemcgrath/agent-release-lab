"""Credential-free fake and an optional text-only chat-completions adapter."""

import json
import re
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from ..identity import canonical_json
from .contracts import ProviderReply, ReviewInput, Usage


class ChatCompletions:
    """Operator-configured HTTPS endpoint. HTTP is restricted to loopback."""

    def __init__(self, endpoint: str, token: str | None):
        url = urlsplit(endpoint)
        if (url.scheme != "https" and not (
            url.scheme == "http" and url.hostname in {"localhost", "127.0.0.1", "::1"}
        )) or not url.hostname or url.username or url.password or url.fragment or url.query:
            raise ValueError("Reviewer endpoint must use HTTPS or loopback HTTP without embedded credentials")
        self.endpoint = endpoint
        self._token = token

    def review(self, request: ReviewInput) -> ProviderReply:
        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                raise HTTPError(req.full_url, code, "Reviewer redirects are disabled", headers, fp)

        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = "Bearer " + self._token
        payload = {
            "model": request.model,
            "messages": [
                {"role": "system", "content": request.instructions},
                {"role": "user", "content": request.snapshot.decode("utf-8")},
            ],
            "response_format": {"type": "json_object"},
            "max_completion_tokens": request.max_output_tokens,
        }
        with build_opener(NoRedirect()).open(
            Request(self.endpoint, data=canonical_json(payload), headers=headers), timeout=request.timeout_seconds
        ) as response:
            raw = response.read(262145)
        if len(raw) > 262144:
            raise ValueError("Provider response envelope is too large")
        data = json.loads(raw)
        choice = data["choices"][0]
        message = choice["message"]
        content = message.get("content")
        complete = (
            choice.get("finish_reason") == "stop" and isinstance(content, str)
            and not message.get("tool_calls") and not message.get("refusal")
        )
        try:
            usage = Usage(input_tokens=data["usage"]["prompt_tokens"],
                          output_tokens=data["usage"]["completion_tokens"], source="provider")
        except (KeyError, TypeError, ValueError):
            usage = Usage(input_tokens=None, output_tokens=None, source="unknown")
        return ProviderReply(
            content.encode("utf-8") if isinstance(content, str) else b"", data["model"], usage, complete,
        )


class FakeReviewer:
    """Deterministic synthetic reviewer used by default and by the demo."""

    def review(self, request: ReviewInput) -> ProviderReply:
        snapshot = json.loads(request.snapshot)
        findings = []
        reports = [item for item in snapshot["evidence"] if item["available"]]
        grouped = {}
        for report in reports:
            grouped.setdefault(report["check_id"], []).append(report)

        def add(key, category, severity, description, remediation, items, uncertainty):
            findings.append({
                "id": key, "category": category, "severity": severity, "description": description,
                "remediation": remediation, "confidence": 90 if items else 65, "uncertainty": uncertainty,
                "evidence": [
                    {"evidence_id": item["evidence_id"], "record_fingerprint": item["record_fingerprint"]}
                    for item in items[:16]
                ],
            })

        for check, items in grouped.items():
            if "passed" in {item["result"] for item in items} and any(item["result"] != "passed" for item in items):
                add(f"conflict-{len(findings)}", "conflicting_evidence", "high",
                    f"Registered runs for {check} disagree.",
                    "Compare the run conditions and inspect any signed remediation link.", items,
                    "A newer remediation run may explain a historical failure.")
        suspicious = [item for item in reports if re.search(
            r"ignore\b.{0,70}\b(?:policy|instructions|controls)|\b(?:system prompt|override|approve this release)\b",
            item["untrusted_excerpt"], re.IGNORECASE | re.DOTALL,
        )]
        if suspicious:
            add("instruction-like-content", "suspicious_content", "high",
                "An artifact contains instruction-like text directed at the reviewer.",
                "Inspect how the artifact was generated and review the original run.", suspicious,
                "This heuristic cannot establish intent.")
        reasons = {reason["code"] for reason in snapshot["assessment"]["reasons"]}
        if reasons & {"evidence_missing", "evidence_stale", "evidence_not_found", "evidence_proof_missing"} or not reports:
            add("test-coverage", "insufficient_testing", "medium",
                "The assessment has a gap in current, verifiable test coverage.",
                "Register a fresh authenticated run for the missing or stale controls.", [],
                "Available records cannot establish which unsubmitted tests were run.")
        if snapshot["assessment"].get("risk_tier") in {"moderate", "high"} or snapshot["changes"]:
            add("scope-review", "overlooked_risk", "medium",
                "Changed components or elevated scope warrant a targeted human review.",
                "Inspect the scope change and exercise edge cases near the operating boundaries.", [],
                "The snapshot cannot establish coverage of every operating condition.")
        output = canonical_json({"findings": findings[:24]})
        return ProviderReply(
            output, request.model, Usage(
                input_tokens=(len(request.snapshot) + len(request.instructions.encode("utf-8")) + 3) // 4,
                output_tokens=(len(output) + 3) // 4, source="estimate",
            ),
        )
