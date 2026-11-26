"""Build canonical read-only projections of a deterministic assessment."""

from ..evidence import EvidenceMismatch
from ..governance.service import Governance
from ..identity import canonical_json
from ..registry import RecordConflict, RecordMissing


def hide_artifact(evidence: dict) -> dict:
    return {key: value for key, value in evidence.items() if key != "untrusted_excerpt"}


def build_snapshot(governance: Governance, assessment: dict) -> bytes:
    registry = governance.registry
    candidate_fingerprint = assessment["candidate_fingerprint"]
    try:
        candidate = registry.get_manifest(candidate_fingerprint).model_dump(mode="json")
        # Opaque settings may contain irrelevant free-form configuration. Only keep pins and scope.
        candidate.pop("runtime", None)
        candidate.pop("security", None)
        for tool in candidate["components"]["tools"].values():
            tool.pop("permissions", None)
            tool.pop("security", None)
    except (RecordMissing, ValueError, RecursionError):
        candidate = None
    evidence = []
    for reference in assessment["evidence"]:
        item = dict(reference, available=False)
        try:
            record, artifact = registry.get_evidence(reference["evidence_id"])
            if (record.candidate_fingerprint == candidate_fingerprint
                    and record.fingerprint == reference.get("record_fingerprint")):
                item.update(
                    available=True, check_id=record.check_id, result=record.result,
                    executed_at=record.executed_at.isoformat(), suite_fingerprint=record.suite_fingerprint,
                    producer=record.producer, untrusted_excerpt=artifact[:512].decode("utf-8", errors="replace"),
                    excerpt_truncated=len(artifact) > 512,
                )
        except (RecordMissing, RecordConflict, EvidenceMismatch, ValueError, RecursionError):
            pass
        evidence.append(item)
    changes = assessment.get("comparison")
    if changes is not None:
        changes = [
            (change | {"before": None, "after": None, "values_redacted": True})
            if change["field"] in {"runtime", "security"}
            or change["field"].endswith(("/permissions", "/security"))
            else change
            for change in changes
        ]
    return canonical_json({
        "schema_version": 1,
        "assessment": {
            key: assessment[key] for key in (
                "assessment_id", "agent_id", "candidate_fingerprint", "baseline_fingerprint",
                "assessed_at", "eligibility", "risk_tier", "risk_dimensions", "change_categories",
                "mandatory_controls", "reasons", "policy_fingerprint", "trust_fingerprint",
            )
        },
        "candidate": candidate,
        "governance_context": {key: assessment.get(key) for key in (
            "ownership", "baseline_authority", "trust_generation", "runtime_attestation",
        )},
        "supersession": [
            {"evidence_id": reason["evidence_id"], "superseded_by": reason["superseded_by"]}
            for reason in assessment["reasons"] if reason.get("superseded_by")
        ],
        "changes": changes,
        "controls": assessment.get("control_details", {}),
        "evidence": evidence,
    })
